export default defineNuxtRouteMiddleware(async (to) => {
  const verify = await verifyToken(to.params.resetToken as string)
  if (!verify) {
    return abortNavigation()
  }
})
