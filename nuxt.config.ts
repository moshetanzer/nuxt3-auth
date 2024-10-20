export default defineNuxtConfig({
  runtimeConfig: {
    authDb: ''
  },
  compatibilityDate: '2024-04-03',
  future :{
    compatibilityVersion: 4
  },
  devtools: { enabled: true },
  modules: ['@nuxt/eslint'],
  eslint: {
    config: {
      stylistic: {
        commaDangle: 'never',
        braceStyle: '1tbs'
      }
    } }
})