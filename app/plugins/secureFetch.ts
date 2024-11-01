export default defineNuxtPlugin((nuxtApp) => {
  const $secureFetch = $fetch.create({
    async onResponseError({ response }) {
      if (response.status === 401) {
        await nuxtApp.runWithContext(() => navigateTo('/signin'))
      }
    }
  })
  return {
    provide: {
      secureFetch: $secureFetch
    }
  }
})
