export default defineNuxtRouteMiddleware(async (to) => {
  const verify = await verifyToken(to.params.resetToken as string)
  console.log('Reset token verified - cleint middleware')
  if (!verify) {
    console.log('Reset token verification failed - client middleware')
    return abortNavigation()
  }
})
