export default defineNuxtRouteMiddleware(async (to, from) => {
  const user = useUser()
  const data = user.value ||= await useRequestFetch()('/api/auth/user')
  if (data) {
    user.value = data
  }
})
