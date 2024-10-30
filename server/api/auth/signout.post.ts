export default defineEventHandler(async (event) => {
  if (!event.context.session) {
    throw createError({
      statusCode: 401
    })
  }

  await deleteSession(event, event.context.session.id)

  return {
    message: 'Logged out'
  }
})
