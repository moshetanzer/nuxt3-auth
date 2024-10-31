export default defineEventHandler(async (event) => {
  try {
    const reset = await resetPassword(event)
    if (reset) {
      return { success: true, message: 'Password reset' }
    } else {
      return { success: false, message: 'Password reset failed' }
    }
  } catch (error) {
    throw createError({
      message: (error as Error).message || 'An error occurred',
      data: { error },
      status: 400
    })
  }
})
