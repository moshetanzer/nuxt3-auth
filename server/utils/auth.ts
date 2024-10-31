import crypto from 'crypto'
import argon2 from 'argon2'
import type { H3Event, EventHandler } from 'h3'
import pg from 'pg'
import { sendEmail } from './mail'

export interface User {
  id: string
  email: string
  fname: string
  lname: string
  failed_attempts: number
  email_verified: boolean
  reset_token: string
  reset_token_expires_at: Date
  email_mfa: boolean
  role: string[]
}
export interface Session {
  id: string
  user_id: string
  expires_at: Date
  two_factor_verified: boolean
}

const { Pool } = pg
const connectionString = useRuntimeConfig().authDb
const authDB = new Pool({
  connectionString
})

function generateRandomId(length = 15) {
  const bytesNeeded = Math.ceil(length * 0.5)
  const bytes = crypto.randomBytes(bytesNeeded)
  return bytes.toString('hex').slice(0, length)
}

const ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4
}

const MAX_FAILED_ATTEMPTS = useRuntimeConfig().maxFailedAttempts || 5 as number

async function hashPassword(password: string) {
  return await argon2.hash(password, ARGON2_CONFIG)
}

async function verifyPassword(email: string, password: string, hash: string) {
  try {
    return await argon2.verify(hash, password)
  } catch (error) {
    await auditLogger(email, 'verifyPassword', String((error as Error).message), 'unknown', 'unknown', 'error')
    return false
  }
}

/**
 * Checks if the user with the given email address has 5 failed login attempts,
 * in which case the account is considered locked.
 * @param {string} email The email address of the user to check.
 * @returns {Promise<boolean>} A promise that resolves to true if the account is locked, false otherwise.
 */
async function checkIfLocked(email: string): Promise<boolean> {
  const result = await authDB.query<User>(`SELECT email, failed_attempts FROM users WHERE email = $1`, [email])
  if (result.rows[0].failed_attempts >= MAX_FAILED_ATTEMPTS) {
    await auditLogger(email, 'checkIfLocked', 'Account locked', 'unknown', 'unknown', 'error')
    return true
  } else {
    return false
  }
}

/**
 * Increments the failed login attempts for a user.
 * @param {string} email The email address of the user.
 */
async function incrementFailedAttempts(email: string) {
  try {
    await authDB.query(`UPDATE users SET failed_attempts = failed_attempts + 1 WHERE email = $1`, [email])
  } catch (error) {
    await auditLogger(email, 'incrementFailedAttempts', String((error as Error).message), 'unknown', 'unknown', 'error')
  }
}

/**
 * Resets the failed login attempts for a user.
 * @param {string} email The email address of the user.
 */
async function resetFailedAttempts(email: string) {
  try {
    await authDB.query(`UPDATE users SET failed_attempts = 0 WHERE email = $1`, [email])
  } catch (error) {
    await auditLogger(email, 'resetFailedAttempts', String((error as Error).message), 'unknown', 'unknown', 'error')
  }
}

export async function createSession(event: H3Event, userId: string) {
  const sessionId = generateRandomId(30)
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours from now

  const query = `
      INSERT INTO sessions (id, user_id, expires_at)
      VALUES ($1, $2, $3)
      RETURNING id
    `
  const values = [sessionId, userId, expiresAt]
  try {
    await authDB.query(query, values)
  } catch (error) {
    const ip = getRequestIP(event) as string
    const userAgent = event.node.req.headers['user-agent'] as string
    await auditLogger(event.context.user?.email ?? userId, 'createSession', String((error as Error).message), ip, userAgent, 'error')
  }

  setCookie(event, 'sessionId', sessionId, {
    path: '/',
    maxAge: 60 * 60 * 24 * 30,
    httpOnly: true,
    sameSite: 'lax',
    secure: true
  })
}
export async function verifySession(sessionId: string) {
  try {
    const query = `
            SELECT s.*, u.role, u.fname, u.lname, u.email, u.email_verified, u.email_mfa
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.id = $1 AND s.expires_at > NOW()
          `

    const result = await authDB.query(query, [sessionId])

    if (result.rows.length === 0) {
      return null
    }

    const session = {
      id: result.rows[0].id,
      user_id: result.rows[0].user_id,
      expires_at: result.rows[0].expires_at,
      two_factor_verified: result.rows[0].two_factor_verified
    }

    const user = {
      role: result.rows[0].role,
      fname: result.rows[0].fname,
      lname: result.rows[0].lname,
      email: result.rows[0].email,
      email_verified: result.rows[0].email_verified,
      id: result.rows[0].id,
      email_mfa: result.rows[0].email_mfa
    }

    return { session, user }
  } catch (error) {
    await auditLogger('unknown', 'verifySession', String((error as Error).message), 'unknown', 'unknown', 'error')
  }
}

export async function deleteSession(event: H3Event, sessionId: string) {
  try {
    const query = 'DELETE FROM sessions WHERE id = $1'
    await authDB.query(query, [sessionId])
    deleteCookie(event, 'sessionId')
  } catch (error) {
    await auditLogger('sessionId' + sessionId, 'deleteSession', String((error as Error).message), 'unknown', 'unknown', 'error')
  }
}

export async function authenticateUser(email: string, password: string) {
  try {
    const result = await authDB.query(`SELECT * FROM users WHERE email = $1`, [email])

    if (result.rows.length === 0) {
      await verifyPassword(email, password, '$argon2id$v=19$m=16,t=2,p=1$d050OUJMT1RzckoxbGdxYQ$+CQAgx/TccW9Ul/85vo7tg')
      return null
    }

    const user = result.rows[0]

    const locked = await checkIfLocked(email)
    if (locked) {
      throw createError({
        statusCode: 401,
        statusMessage: 'Account locked'
      })
    }

    const isValid = await verifyPassword(email, password, user.password)
    if (!isValid) {
      await incrementFailedAttempts(email)
      throw createError({
        statusCode: 401,
        statusMessage: 'Invalid email or password'
      })
    }
    await resetFailedAttempts(email)
    return user
  } catch (error) {
    await auditLogger(email, 'authenticateUser', String((error as Error).message), 'unknown', 'unknown', 'error')
  }
}

export async function createUser(fname: string, lname: string, email: string, password: string, role: string) {
  try {
    const userId = generateRandomId()
    const hashedPassword = await hashPassword(password)

    const query = `
      INSERT INTO users (id, fname, lname, email, password, role, failed_attempts)
      VALUES ($1, $2, $3, $4, $5, $6, 0)
      RETURNING id
    `

    const values = [userId, fname, lname, email, hashedPassword, role]

    const result = await authDB.query(query, values)
    return result.rows[0].id
  } catch (error) {
    await auditLogger(email, 'createUser', String((error as Error).message), 'unknown', 'unknown', 'error')
  }
}

export async function auditLogger(email: string, action: string, message: string, ip: string, userAgent: string, status: string) {
  await authDB.query(`INSERT INTO audit_logs(email, action, message, ip, user_agent, status) VALUES($1, $2, $3, $4, $5, $6)`, [email, action, message, ip, userAgent, status])
}
export function verifyRequestOrigin(origin: string, allowedDomains: string[]): boolean {
  if (!origin || allowedDomains.length === 0) {
    auditLogger('origin: ' + origin, 'verifyRequestOrigin', 'Invalid origin or allowedDomains', 'unknown', 'unknown', 'error')
    return false
  }
  const originHost = safeURL(origin)?.host ?? null
  if (!originHost) {
    auditLogger('origin: ' + origin, 'verifyRequestOrigin', 'Invalid origin host', 'unknown', 'unknown', 'error')
    return false
  }
  for (const domain of allowedDomains) {
    let host: string | null
    if (domain.startsWith('http://') || domain.startsWith('https://')) {
      host = safeURL(domain)?.host ?? null
    } else {
      host = safeURL('https://' + domain)?.host ?? null
    }
    if (originHost === host) return true
  }
  auditLogger('origin: ' + origin, 'verifyRequestOrigin', 'Origin not allowed', 'unknown', 'unknown', 'error')
  return false
}

function safeURL(url: URL | string): URL | null {
  try {
    return new URL(url)
  } catch {
    auditLogger('url: ' + url, 'safeURL', 'Invalid URL', 'unknown', 'unknown', 'error')
    return null
  }
}

export async function refreshSession(sessionId: string) {
  try {
    const newExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours from now
    const query = 'UPDATE sessions SET expires_at = $1 WHERE id = $2 RETURNING *'
    const result = await authDB.query(query, [newExpiresAt, sessionId])
    return result.rows[0]
  } catch (error) {
    await auditLogger('sessionId: ' + sessionId, 'refreshSession', String((error as Error).message), 'unknown', 'unknown', 'error')
  }
}

export async function cleanupExpiredSessions() {
  try {
    const query = 'DELETE FROM sessions WHERE expires_at < NOW()'
    await authDB.query(query)
  } catch (error) {
    await auditLogger('unknown', 'cleanupExpiredSessions', String((error as Error).message), 'unknown', 'unknown', 'error')
  }
}

export async function handleRateLimit(event: H3Event): Promise<void> {
  const RATE_LIMIT = 100
  const RATE_LIMIT_WINDOW = 60

  const storage = useStorage()
  const ip = getClientIP(event)
  const userAgent = event.node.req.headers['user-agent'] as string
  const key = `rate-limit:${ip}`

  const [current, ttl] = await storage.getItem<[number, number]>(key) || [0, 0]

  if (current >= RATE_LIMIT) {
    setRateLimitHeaders(event, current, ttl)
    await auditLogger('unknown', 'handleRateLimit', 'Too many requests', ip, userAgent, 'error')
    throw createError({
      statusCode: 429,
      statusMessage: 'Too Many Requests'
    })
  }

  const newCount = current + 1
  if (newCount === 1) {
    await storage.setItem(key, [newCount, RATE_LIMIT_WINDOW], { ttl: RATE_LIMIT_WINDOW })
  } else {
    await storage.setItem(key, [newCount, ttl])
  }

  setRateLimitHeaders(event, newCount, ttl)

  function getClientIP(event: H3Event): string {
    return event.node.req.headers['x-forwarded-for'] as string
      || event.node.req.connection.remoteAddress as string
  }

  function setRateLimitHeaders(event: H3Event, current: number, ttl: number): void {
    event.node.res.setHeader('X-RateLimit-Limit', RATE_LIMIT)
    event.node.res.setHeader('X-RateLimit-Remaining', Math.max(0, RATE_LIMIT - current))
    event.node.res.setHeader('X-RateLimit-Reset', Math.ceil(Date.now() / 1000 + ttl))
  }
}

export const roleBasedAuth: EventHandler = (event: H3Event) => {
  const rules = getRouteRules(event).roles as string[]
  const to = event.node.req.url

  if (!rules || rules.length === 0) {
    return // No rules defined, allow access
  }

  const userRoles = event.context.user?.role || []

  if (!hasRequiredRole(userRoles, rules)) {
    const ip = getRequestIP(event) as string
    const userAgent = event.node.req.headers['user-agent'] as string
    auditLogger(event.context.user?.email ?? 'unknown', 'roleBasedAuth', 'Unauthorized', ip, userAgent, 'error')
    return event.node.res.writeHead(403).end('Unauthorized: Insufficient role')
  }

  if (to && !checkAccess(userRoles, to, rules)) {
    const ip = getRequestIP(event) as string
    const userAgent = event.node.req.headers['user-agent'] as string
    auditLogger(event.context.user?.email ?? 'unknown', 'roleBasedAuth', 'Unauthorized', ip, userAgent, 'error')
    return event.node.res.writeHead(403).end('Unauthorized: No access to this route')
  }
}

function hasRequiredRole(userRoles: string[], requiredRoles: string[]): boolean {
  return requiredRoles.some(role => userRoles.includes(role))
}

function checkAccess(userRoles: string[], to: string, rules: string[]): boolean {
  return rules.some((rule) => {
    const [roleName, routePattern] = rule.split(':')
    const regex = new RegExp(routePattern)
    return regex.test(to) && userRoles.includes(roleName)
  })
}
export async function emailVerification(event: H3Event) {
  const rules = getRouteRules(event).emailVerification as boolean
  const to = event.node.req.url
  if (rules && to && !event.context.user?.email_verified) {
    throw createError({
      statusCode: 401,
      statusMessage: 'Email not verified'
    })
  }
}

export async function handleSession(event: H3Event): Promise<void> {
  const sessionId = getCookie(event, 'sessionId')

  if (!sessionId) {
    event.context.session = null
    event.context.user = null
    return
  }

  const sessionData = await verifySession(sessionId)

  if (sessionData) {
    const { session, user } = sessionData
    event.context.session = session
    event.context.user = user
  } else {
    event.context.session = null
    event.context.user = null
    await deleteSession(event, sessionId)
  }
}

export async function resetPasswordRequest(event: H3Event) {
  const { email } = await readBody(event)
  const user = await authDB.query<User>(`SELECT * FROM users WHERE email = $1`, [email])
  if (user.rows.length === 0) {
    throw createError({
      statusCode: 400,
      statusMessage: 'We will send a password reset link to the email address if it exists in our system.'
    })
  }

  const existingToken = user.rows[0].reset_token
  const existingTokenExpiry = user.rows[0].reset_token_expires_at

  let resetToken: string
  let resetTokenExpiry: Date

  if (existingToken && existingTokenExpiry > new Date()) {
    // Reuse existing valid token
    resetToken = existingToken
    resetTokenExpiry = existingTokenExpiry
  } else {
    // Invalidate existing tokens and generate a new one
    resetToken = generateRandomId(30)
    resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000) // 1 hour from now
  }

  const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex')

  try {
    const query = `
      UPDATE users
      SET reset_token = $1, reset_token_expires_at = $2
      WHERE email = $3
    `
    const values = [hashedToken, resetTokenExpiry, email]
    await authDB.query(query, values)
  } catch (error) {
    await auditLogger(email, 'resetPasswordRequest', String((error as Error).message), 'unknown', 'unknown', 'error')
    throw createError({
      statusCode: 400,
      statusMessage: 'We will send a password reset link to the email address if it exists in our system.'
    })
  }

  await sendEmail(email, 'Password Reset Request', `Click <a href="${useRuntimeConfig().baseUrl}/reset-password/${resetToken}">here</a> to reset your password.`)
  return true
}

export async function verifyResetToken(event: H3Event) {
  const { resetToken: token } = getRouterParams(event)
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex')
  const result = await authDB.query<User>(`SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires_at > NOW()`, [hashedToken])
  if (result.rows.length === 0) {
    return false
  } else if (result.rows.length === 1) {
    return true
  }
}

export async function resetPassword(event: H3Event) {
  try {
    const { resetToken, password, confirmPassword } = await readBody(event)

    if (!resetToken || !password || !confirmPassword) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Missing required fields'
      })
    }

    if (password !== confirmPassword) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Passwords do not match'
      })
    }
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex')
    const result = await authDB.query<User>(`SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires_at > NOW()`, [hashedToken]).catch((error) => {
      throw createError({
        statusCode: 500,
        statusMessage: 'Database error while checking reset token'
      })
    })
    const user = result.rows[0]
    if (!user) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Invalid token'
      })
    }

    const hashedPassword = await hashPassword(password)

    await authDB.query(`UPDATE users SET password = $1, reset_token = NULL, reset_token_expires_at = NULL WHERE id = $2`, [hashedPassword, user.id]).catch(async (error) => {
      await auditLogger(
        user.email,
        'resetPassword',
        String((error as Error).message),
        'unknown',
        'unknown',
        'error'
      )
      throw createError({
        statusCode: 500,
        statusMessage: 'Failed to update password'
      })
    })

    await auditLogger(
      user.email,
      'resetPassword',
      'Password reset successful',
      'unknown',
      'unknown',
      'success'
    ).catch(() => {
      console.error('Failed to log password reset success')
    })

    return true
  } catch (error) {
    await auditLogger('unknown', 'resetPassword', String((error as Error).message), 'unknown', 'unknown', 'error')
    throw createError({
      statusCode: 500,
      statusMessage: 'An unexpected error occurred'
    })
  }
}
