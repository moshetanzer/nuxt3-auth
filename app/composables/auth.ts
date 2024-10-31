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
