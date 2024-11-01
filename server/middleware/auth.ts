import type { User, Session } from '~~/server/utils/auth'
import { handleRateLimit, roleBasedAuth, emailVerification, handleSession } from '~~/server/utils/auth'

export default defineEventHandler(async (event) => {
  // CSRF Protection
  // only in production since for some reason on ssr fetch origin is null and host is localhost
  if (process.env.NODE_ENV === 'production') {
    if (event.node.req.method !== 'GET') {
      const originHeader = getHeader(event, 'Origin') ?? null
      // console.log('originHeader', originHeader)
      const hostHeader = getHeader(event, 'Host') ?? null
      // console.log('hostHeader', hostHeader)

      if (!originHeader || !hostHeader || !verifyRequestOrigin(originHeader, [hostHeader])) {
        return event.node.res.writeHead(403).end('Invalid origin')
      }
    }
  }
  // Rate Limit
  await handleRateLimit(event)

  // Session Management
  await handleSession(event)

  // Role-Based Authorization
  await roleBasedAuth(event)

  // Email Verification
  await emailVerification(event)
})

declare module 'h3' {
  interface H3EventContext {
    user: Partial<User> | null
    session: Session | null
  }
}
