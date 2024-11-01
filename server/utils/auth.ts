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
const SESSION_TOTAL_DURATION = useRuntimeConfig().sessionTotalDuration || 30 * 24 * 60 * 60 * 1000 as number// 30 days total
const SESSION_SLIDING_WINDOW = useRuntimeConfig().sessionSlidingWindow || 15 * 24 * 60 * 60 * 1000 as number // 15 days sliding window
const SESSION_REFRESH_INTERVAL = useRuntimeConfig().sessionRefreshInterval || 30 * 24 * 60 * 60 * 1000 as number// Refresh every 30 days

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

export async function verifySession(sessionId: string) {
  try {
    const query = `
      SELECT 
        s.*, 
        u.role, 
        u.fname, 
        u.lname, 
        u.email, 
        u.email_verified, 
        u.email_mfa,
        (s.created_at + INTERVAL '${Number(SESSION_TOTAL_DURATION) / 1000} seconds') AS absolute_expiration
      FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.id = $1 
        AND s.expires_at > NOW() 
        AND (s.created_at + INTERVAL '${Number(SESSION_TOTAL_DURATION) / 1000} seconds') > NOW()
    `

    const result = await authDB.query(query, [sessionId])

    if (result.rows.length === 0) {
      return null
    }

    const sessionRow = result.rows[0]
    const currentTime = new Date()
    const expiresAt = new Date(sessionRow.expires_at)
    const slidingWindowThreshold = new Date(currentTime.getTime() - Number(SESSION_SLIDING_WINDOW))

    if (expiresAt <= slidingWindowThreshold) {
      try {
        // Extend session expiration
        await refreshSession(sessionId)
      } catch (refreshError) {
        await auditLogger(
          sessionRow.email,
          'sessionRefresh',
          `Automatic session refresh failed: ${String(refreshError)}`,
          'unknown',
          'unknown',
          'warning'
        )
        // Continue with existing session even if refresh fails
      }
    }

    const session = {
      id: sessionRow.id,
      user_id: sessionRow.user_id,
      expires_at: sessionRow.expires_at,
      absolute_expiration: sessionRow.absolute_expiration,
      two_factor_verified: sessionRow.two_factor_verified
    }

    const user = {
      role: sessionRow.role,
      fname: sessionRow.fname,
      lname: sessionRow.lname,
      email: sessionRow.email,
      email_verified: sessionRow.email_verified,
      id: sessionRow.user_id,
      email_mfa: sessionRow.email_mfa
    }

    return { session, user }
  } catch (error) {
    await auditLogger(
      'unknown',
      'verifySession',
      String((error as Error).message),
      'unknown',
      'unknown',
      'error'
    )
    return null
  }
}

export async function refreshSession(sessionId: string) {
  try {
    const currentTime = new Date()
    const newExpiresAt = new Date(currentTime.getTime() + Number(SESSION_REFRESH_INTERVAL))

    const query = `
      UPDATE sessions 
      SET 
        expires_at = $1, 
        updated_at = NOW(),
        last_activity_at = NOW()
      WHERE id = $2 
        AND (created_at + INTERVAL '${Number(SESSION_TOTAL_DURATION) / 1000} seconds') > NOW()
      RETURNING *
    `
    const result = await authDB.query(query, [newExpiresAt, sessionId])

    if (result.rows.length === 0) {
      throw new Error('Session not found or expired')
    }

    await auditLogger(
      'sessionId: ' + sessionId,
      'refreshSession',
      'Session successfully refreshed',
      'unknown',
      'unknown',
      'info'
    ).catch(console.error)

    return result.rows[0]
  } catch (error) {
    await auditLogger(
      'sessionId: ' + sessionId,
      'refreshSession',
      String((error as Error).message),
      'unknown',
      'unknown',
      'error'
    )
    throw error
  }
}

export async function createSession(event: H3Event, userId: string) {
  try {
    if (!userId) {
      throw createError({
        statusCode: 401,
        statusMessage: 'User not found'
      })
    }
    const sessionId = generateRandomId(32)
    const currentTime = new Date()
    const expiresAt = new Date(currentTime.getTime() + Number(SESSION_REFRESH_INTERVAL))

    const query = `
      INSERT INTO sessions (
        id, 
        user_id, 
        expires_at, 
        created_at, 
        updated_at, 
        last_activity_at
      ) VALUES ($1, $2, $3, NOW(), NOW(), NOW())
      RETURNING *
    `

    await authDB.query(query, [sessionId, userId, expiresAt])

    await auditLogger(
      'userId: ' + userId,
      'createSession',
      'New session created',
      'unknown',
      'unknown',
      'info'
    ).catch(console.error)

    setCookie(event, 'sessionId', sessionId, {
      path: '/',
      maxAge: 60 * 60 * 24 * 30,
      httpOnly: true,
      sameSite: 'lax',
      secure: true
    })
  } catch (error) {
    await auditLogger(
      'unknown',
      'createSession',
      String((error as Error).message),
      'unknown',
      'unknown',
      'error'
    )
    throw error
  }
}

export async function handleSession(event: H3Event): Promise<void> {
  try {
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
      await deleteSession(event)
    }
  } catch (error) {
    console.error('Session handling error:', error)

    event.context.session = null
    event.context.user = null

    await auditLogger(
      'unknown',
      'handleSession',
      String((error as Error).message),
      'unknown',
      'unknown',
      'error'
    ).catch(console.error)
  }
}

export async function deleteSession(event: H3Event) {
  const sessionId = event.context.session?.id
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

export async function resetPasswordRequest(event: H3Event) {
  try {
    const { email } = await readBody(event)

    if (!email) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Email is required'
      })
    }
    const user = await authDB.query<User>(`SELECT id, email, reset_token, reset_token_expires_at FROM users WHERE email = $1`, [email]).catch(async (error) => {
      await auditLogger(
        email,
        'resetPasswordRequest',
        `Database error: ${String((error as Error).message)}`,
        'unknown',
        'unknown',
        'error'
      )
      throw createError({
        statusCode: 500,
        statusMessage: 'An error occurred processing your request'
      })
    })
    let resetToken: string
    let resetTokenExpiry: Date
    let hashedToken: string

    if (user.rows.length === 0) {
      // Still generate a token to prevent timing attacks, but don't save it
      resetToken = generateRandomId(30)
      resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000)
      hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex')
      const errorEmailAddress = useRuntimeConfig().emailUser
      await auditLogger(email, 'resetPasswordRequest', 'Email not found', 'unknown', 'unknown', 'error')
      await sendEmail(errorEmailAddress, 'Password reset failed - ensure no timing attack', `Click <a href="${useRuntimeConfig().baseUrl}/reset-password/${resetToken}">here</a> to reset your password.`)

      return true
    }

    const existingToken = user.rows[0].reset_token
    const existingTokenExpiry = user.rows[0].reset_token_expires_at

    if (existingToken && existingTokenExpiry && new Date(existingTokenExpiry) > new Date()) {
      resetToken = existingToken
      resetTokenExpiry = new Date(existingTokenExpiry)
      hashedToken = existingToken
    } else {
    // Invalidate existing tokens and generate a new one
      resetToken = generateRandomId(30)
      resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000) // 1 hour from now
      hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex')
    }

    await authDB.query(`
      UPDATE users
      SET reset_token = $1, reset_token_expires_at = $2
      WHERE email = $3
    `, [hashedToken, resetTokenExpiry, email]).catch(async (error) => {
      await auditLogger(
        email,
        'resetPasswordRequest',
        `Token update failed: ${String((error as Error).message)}`,
        'unknown',
        'unknown',
        'error'
      )
      throw createError({
        statusCode: 500,
        statusMessage: 'An error occurred processing your request'
      })
    })

    await sendEmail(email, 'Password Reset Request', `Click <a href="${useRuntimeConfig().baseUrl}/reset-password/${resetToken}">here</a> to reset your password.`).catch(async (error) => {
      await auditLogger(
        email,
        'resetPasswordRequest',
        `Email sending failed: ${String((error as Error).message)}`,
        'unknown',
        'unknown',
        'error'
      )
      throw createError({
        statusCode: 500,
        statusMessage: 'An error occurred processing your request'
      })
    })
    return true
  } catch (error) {
    await auditLogger('unknown', 'resetPasswordRequest', String((error as Error).message), 'unknown', 'unknown', 'error')
    throw createError({
      statusCode: 500,
      statusMessage: 'An unexpected error occurred'
    })
  }
}

export async function verifyResetToken(event: H3Event) {
  try {
    const { resetToken: token } = getRouterParams(event)

    if (!token) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Reset token is required'
      })
    }
    let hashedToken: string
    try {
      hashedToken = crypto.createHash('sha256').update(token).digest('hex')
    } catch (error) {
      await auditLogger('unknown', 'verifyResetToken', String((error as Error).message), 'unknown', 'unknown', 'error')
      throw createError({
        statusCode: 500,
        statusMessage: 'Failed to process reset token'
      })
    }
    const result = await authDB.query<User>(`SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires_at > NOW()`, [hashedToken]).catch(async (error) => {
      await auditLogger('unknown', 'verifyResetToken', String((error as Error).message), 'unknown', 'unknown', 'error')
      throw createError({
        statusCode: 500,
        statusMessage: 'Error verifying reset token'
      })
    })
    if (result.rows.length === 0) {
      await auditLogger('unknown', 'verifyResetToken', 'Invalid token', 'unknown', 'unknown', 'error')
      return false
    } else if (result.rows.length === 1) {
      await auditLogger(result.rows[0].email, 'verifyResetToken', 'Token verified', 'unknown', 'unknown', 'success')
      return true
    }
  } catch (error) {
    await auditLogger('unknown', 'verifyResetToken', String((error as Error).message), 'unknown', 'unknown', 'error')
    throw createError({
      statusCode: 500,
      statusMessage: 'An unexpected error occurred'
    })
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
    let hashedToken: string
    try {
      hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex')
    } catch (error) {
      await auditLogger('unknown', 'resetPassword', String((error as Error).message), 'unknown', 'unknown', 'error')
      throw createError({
        statusCode: 500,
        statusMessage: 'Failed to process reset token'
      })
    }
    const result = await authDB.query<User>(`SELECT * FROM users WHERE reset_token = $1 AND reset_token_expires_at > NOW()`, [hashedToken]).catch(async (error) => {
      await auditLogger('unknown', 'resetPassword', String((error as Error).message), 'unknown', 'unknown', 'error')
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
