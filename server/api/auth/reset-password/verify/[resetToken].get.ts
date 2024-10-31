export default defineEventHandler(async (event) => {
  try {
    const verified = await verifyResetToken(event)
    if (verified) {
      return { success: true, message: 'Reset token verified' }
    } else {
      return { success: false, message: 'Reset token verification failed' }
    }
  } catch (error) {
    throw createError({
      message: (error as Error).message || 'An error occurred',
      data: { error },
      status: 400
    })
  }
})
