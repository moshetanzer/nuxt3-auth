export default defineNuxtConfig({
  modules: ['@nuxt/eslint'],
  ssr: true,
  devtools: { enabled: false },
  runtimeConfig: {
    authDb: '',
    emailHost: '',
    emailPort: '',
    emailUser: '',
    emailPassword: '',
    sessionTotalDuration: '',
    sessionSlidingWindow: '',
    sessionRefreshInterval: '',
    baseUrl: 'http://localhost:3002'
  },
  routeRules: {
    '/api/admin/**': {
      roles: ['admin'],
      emailVerification: true
    },
    '/api/user/**': {
      roles: ['user', 'admin']
    }
  },
  future: {
    compatibilityVersion: 4
  },
  compatibilityDate: '2024-04-03',
  eslint: {
    config: {
      stylistic: {
        commaDangle: 'never',
        braceStyle: '1tbs'
      }
    } }
})
