import type { User, Session } from '~~/server/utils/auth'
import { handleRateLimit, roleBasedAuth, emailVerification, handleSession } from '~~/server/utils/auth'

export default defineEventHandler(async (event) => {
  // CSRF Protection
  // only in production since for some reason on ssr fetch origin is null and host is localhost
  if (process.env.NODE_ENV === 'production') {
    if (event.node.req.method !== 'GET') {
      const originHeader = getHeader(event, 'Origin') ?? null
      const hostHeader = getHeader(event, 'Host') ?? null
      if (!originHeader || !hostHeader || !verifyRequestOrigin(originHeader, [hostHeader])) {
        console.log('Invalid origin')
        return event.node.res.writeHead(403).end('Invalid origin')
      }
    }
  }
  // Rate Limit
  await handleRateLimit(event)

  // Session Management
  await handleSession(event)
  console.log('this is berfore role based ' + event.context.user?.role)

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
