export default defineNuxtPlugin((nuxtApp) => {
  const api = $fetch.create({

    async onResponseError({ response }) {
      if (response.status === 401) {
        await nuxtApp.runWithContext(() => navigateTo('/login'))
      }
    }
  })

  return {
    provide: {
      secureFetch: api
    }
  }
})
