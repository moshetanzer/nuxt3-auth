export default defineEventHandler(async (event) => {
  if (!event.context.session) {
    throw createError({
      statusCode: 401
    })
  }
  return event.context.user
})
