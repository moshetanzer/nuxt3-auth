import crypto from 'crypto'
import argon2 from 'argon2'

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
    return false
  }
}

async function checkIfLocked(email: string) {
  const result = await authDB.query(`SELECT email, failed_attempts FROM users WHERE email = $1`, [email])
  if (result.rows.failed_attempts >= 5) {
    return true
  } else {
    return false
  }
}

async function incrementFailedAttempts(email: string) {
  await authDB.query(`UPDATE users SET failed_attempts = failed_attempts + 1 WHERE email = $1`, [email])
}

async function resetFailedAttempts(email: string) {
  await authDB.query(`UPDATE users SET failed_attempts = 0 WHERE email = $1`, [email])
}
export async function createSession(userId: string) {
  const sessionId = generateRandomId(30)
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours from now

  const query = `
      INSERT INTO sessions (id, user_id, expires_at)
      VALUES ($1, $2, $3)
      RETURNING id
    `

  const values = [sessionId, userId, expiresAt]

  const result = await authDB.query(query, values)
  return result.rows[0].id
}

export async function verifySession(sessionId: string) {
  const query = `
      SELECT s.*, u.role
      FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.id = $1 AND s.expires_at > NOW()
    `

  const result = await authDB.query(query, [sessionId])

  if (result.rows.length === 0) {
    return null
  }

  return result.rows[0]
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

export async function auditLogger(email: string, action: string, message: string, ip: string, userAgent: string, status: string) {
  await authDB.query(`INSERT INTO audit_logs(email, action, message, ip) VALUES($1, $2, $3, $4)`, [email, action, message, ip])
}
