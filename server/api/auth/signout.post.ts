export default defineEventHandler(async (event) => {
  if (!event.context.session) {
    throw createError({
      statusCode: 401
    })
  }

  await deleteSession(event.context.session.id)
  setCookie(event, 'sessionId', '', {
    path: '/',
    maxAge: 0,
    httpOnly: true,
    sameSite: 'lax',
    secure: true
  })
  return {
    message: 'Logged out'
  }
})
