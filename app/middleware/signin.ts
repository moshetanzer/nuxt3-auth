export default defineNuxtRouteMiddleware((to, from) => {
  if (useUser().value) {
    return navigateTo('/')
  }
})
