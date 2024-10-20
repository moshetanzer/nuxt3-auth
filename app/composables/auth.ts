export const useUser = () => {
  const user = useState<User | null>('user', () => null)
  return user
}
export const updateUser = async () => {
  const updatedData = await useRequestFetch()('/api/auth/user')
  if (updatedData) {
    useUser().value = updatedData
  }
}
