import type { UseFetchOptions } from 'nuxt/app'

interface User {
  id: string
  email: string
  fname: string
  lname: string
  failed_attempts: number
  role: string
  email_verified: boolean
  email_mfa: boolean
}

export const useUser = () => {
  const user = useState<User | null>('user', () => null)
  return user
}
export const useLogOut = async () => {
  try {
    await $fetch('/api/auth/signout', { method: 'POST' })
    const user = useUser()
    user.value = null
    navigateTo('/signin')
  } catch (err) {
    console.error(err)
  }
}

export async function verifyToken(resetToken: string) {
  try {
    const response = await $fetch(`/api/auth/reset-password/verify/${resetToken}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      } })
    if (response.success) {
      return true
    } else {
      return false
    }
  } catch (err) {
    console.error(err)
    return false
  }
}

export function useSecureFetchOld<T>(
  url: string | (() => string),
  options?: UseFetchOptions<T>
) {
  return useFetch(url, {
    ...options,
    $fetch: useNuxtApp().$secureFetch
  })
}

export function useSecureFetch<T>(
  url: string | (() => string),
  options?: UseFetchOptions<T>
) {
  const nuxtApp = useNuxtApp()
  const request = useRequestFetch()

  return useAsyncData(async () => {
    const resolvedUrl = typeof url === 'function' ? url() : url
    return await request(resolvedUrl, {
      ...options,
      $fetch: nuxtApp.$secureFetch
    })
  }, options)
}
