interface User {
  id: string
  email: string
  fname: string
  lname: string
  failed_attempts: number
  role: string
}
export const useUser = () => {
  const user = useState<User | null>('user', () => null)
  return user
}
