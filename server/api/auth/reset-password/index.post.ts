import { resetPasswordRequest } from '~~/server/utils/auth'

export default defineEventHandler(async (event) => {
  try {
    await resetPasswordRequest(event)
    return { success: true, message: 'If the email exists in our system, we will send a password reset link to the email address' }
  } catch (error) {
    throw createError({
      message: (error as Error).message || 'An error occurred',
      data: { error },
      status: 400
    })
  }
})
