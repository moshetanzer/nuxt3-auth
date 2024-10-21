import crypto from 'crypto'
import argon2 from 'argon2'
import type { H3Event } from 'h3'
import pg from 'pg'

export interface User {
  id: string
  email: string
  fname: string
  lname: string
  failed_attempts: number
  email_verified: boolean
  role: string[]
}
export interface Session {
  id: string
  user_id: string
  expires_at: Date
}

const { Pool } = pg
const connectionString = useRuntimeConfig().authDb
const authDB = new Pool({
  connectionString
})

export function generateRandomId(length = 15) {
  return crypto.randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length)
}

const ARGON2_CONFIG = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4
}

async function hashPassword(password: string) {
  return await argon2.hash(password, ARGON2_CONFIG)
}

async function verifyPassword(password: string, hash: string) {
  try {
    return await argon2.verify(hash, password)
  } catch (error) {
    console.log(error)
    return false
  }
}

/**
 * Checks if the user with the given email address has 5 failed login attempts,
 * in which case the account is considered locked.
 * @param {string} email The email address of the user to check.
 * @returns {Promise<boolean>} A promise that resolves to true if the account is locked, false otherwise.
 */
async function checkIfLocked(email: string) {
  const result = await authDB.query<User>(`SELECT email, failed_attempts FROM users WHERE email = $1`, [email])
  if (result.rows[0].failed_attempts >= 5) {
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
  await authDB.query(`UPDATE users SET failed_attempts = failed_attempts + 1 WHERE email = $1`, [email])
}

/**
 * Resets the failed login attempts for a user.
 * @param {string} email The email address of the user.
 */
async function resetFailedAttempts(email: string) {
  await authDB.query(`UPDATE users SET failed_attempts = 0 WHERE email = $1`, [email])
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
  await authDB.query(query, values)

  setCookie(event, 'sessionId', sessionId, {
    path: '/',
    maxAge: 60 * 60 * 24 * 30,
    httpOnly: true,
    sameSite: 'lax',
    secure: true
  })
}
export async function verifySession(sessionId: string) {
  const query = `
            SELECT s.*, u.role, u.fname, u.lname, u.email
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
    expires_at: result.rows[0].expires_at
  }

  const user = {
    role: result.rows[0].role,
    fname: result.rows[0].fname,
    lname: result.rows[0].lname,
    email: result.rows[0].email,
    email_verified: result.rows[0].email_verified,
    id: result.rows[0].id
  }

  return { session, user }
}

export async function deleteSession(sessionId: string) {
  const query = 'DELETE FROM sessions WHERE id = $1'
  await authDB.query(query, [sessionId])
}

export async function authenticateUser(email: string, password: string) {
  const result = await authDB.query(`SELECT * FROM users WHERE email = $1`, [email])

  if (result.rows.length === 0) {
    await verifyPassword(password, '$argon2id$v=19$m=16,t=2,p=1$d050OUJMT1RzckoxbGdxYQ$+CQAgx/TccW9Ul/85vo7tg')
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

  const isValid = await verifyPassword(password, user.password)
  if (!isValid) {
    await incrementFailedAttempts(email)
    throw createError({
      statusCode: 401,
      statusMessage: 'Invalid email or password'
    })
  }
  await resetFailedAttempts(email)
  return user
}

export async function createUser(fname: string, lname: string, email: string, password: string, role: string) {
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
}

// export async function auditLogger(email: string, action: string, message: string, ip: string, userAgent: string, status: string) {
//   await authDB.query(`INSERT INTO audit_logs(email, action, message, ip) VALUES($1, $2, $3, $4)`, [email, action, message, ip])
// }
export function verifyRequestOrigin(origin: string, allowedDomains: string[]): boolean {
  if (!origin || allowedDomains.length === 0) return false
  const originHost = safeURL(origin)?.host ?? null
  if (!originHost) return false
  for (const domain of allowedDomains) {
    let host: string | null
    if (domain.startsWith('http://') || domain.startsWith('https://')) {
      host = safeURL(domain)?.host ?? null
    } else {
      host = safeURL('https://' + domain)?.host ?? null
    }
    if (originHost === host) return true
  }
  return false
}

function safeURL(url: URL | string): URL | null {
  try {
    return new URL(url)
  } catch {
    return null
  }
}

export async function refreshSession(sessionId: string) {
  const newExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours from now
  const query = 'UPDATE sessions SET expires_at = $1 WHERE id = $2 RETURNING *'
  const result = await authDB.query(query, [newExpiresAt, sessionId])
  return result.rows[0]
}

export async function cleanupExpiredSessions() {
  const query = 'DELETE FROM sessions WHERE expires_at < NOW()'
  await authDB.query(query)
}
