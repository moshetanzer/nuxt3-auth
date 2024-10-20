export default defineEventHandler(async (event) => {
  // CSRF Protection
  if (event.node.req.method !== 'GET') {
    const originHeader = getHeader(event, 'Origin') ?? null
    const hostHeader = getHeader(event, 'Host') ?? null
    if (!originHeader || !hostHeader || !verifyRequestOrigin(originHeader, [hostHeader])) {
      return event.node.res.writeHead(403).end('Invalid origin')
    }
  }

  // Session
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
})

interface User {
  role: string
  fname: string
  lname: string
  email: string
}

interface Session {
  id: string
  user_id: string
  expires_at: Date
}

declare module 'h3' {
  interface H3EventContext {
    user: User | null
    session: Session | null
  }
}
