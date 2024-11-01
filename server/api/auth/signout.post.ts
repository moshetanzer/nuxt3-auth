export default defineEventHandler(async (event) => {
  if (!event.context.session) {
    return {
      message: 'Logged out'
    }
    // throw createError({
    //   statusCode: 401
    // })
  }

  await deleteSession(event)

  return {
    message: 'Logged out'
  }
})
