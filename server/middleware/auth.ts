import type { H3Event, EventHandler } from 'h3'
import type { User, Session } from '~~/server/utils/auth'

export default defineEventHandler(async (event) => {
  // CSRF Protection
  if (event.node.req.method !== 'GET') {
    const originHeader = getHeader(event, 'Origin') ?? null
    const hostHeader = getHeader(event, 'Host') ?? null
    if (!originHeader || !hostHeader || !verifyRequestOrigin(originHeader, [hostHeader])) {
      return event.node.res.writeHead(403).end('Invalid origin')
    }
  }

  // Rate Limiting
  const RATE_LIMIT = 100
  const RATE_LIMIT_WINDOW = 60

  const storage = useStorage()
  const ip = getClientIP(event)
  const key = `rate-limit:${ip}`

  const [current, ttl] = await storage.getItem<[number, number]>(key) || [0, 0]

  if (current >= RATE_LIMIT) {
    setRateLimitHeaders(event, current, ttl)
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

  function getClientIP(event: H3Event) {
    return event.node.req.headers['x-forwarded-for']
      || event.node.req.connection.remoteAddress
  }

  function setRateLimitHeaders(event: H3Event, current: number, ttl: number) {
    event.node.res.setHeader('X-RateLimit-Limit', RATE_LIMIT)
    event.node.res.setHeader('X-RateLimit-Remaining', Math.max(0, RATE_LIMIT - current))
    event.node.res.setHeader('X-RateLimit-Reset', Math.ceil(Date.now() / 1000 + ttl))
  }

  // Session Management
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
    // Clear the invalid session
    await deleteSession(sessionId)
    deleteCookie(event, 'sessionId')
  }

  const roleBasedAuth: EventHandler = (event: H3Event) => {
    const rules = getRouteRules(event).roles as string[]
    const to = event.node.req.url

    if (!rules || rules.length === 0) {
      return // No rules defined, allow access
    }

    const userRoles = event.context.user?.role || []

    if (!hasRequiredRole(userRoles, rules)) {
      return event.node.res.writeHead(403).end('Unauthorized: Insufficient role')
    }

    if (to && !checkAccess(userRoles, to, rules)) {
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

  roleBasedAuth(event)
})
declare module 'h3' {
  interface H3EventContext {
    user: Partial<User> | null
    session: Session | null
  }
}
