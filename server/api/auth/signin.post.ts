export default defineEventHandler(async (event) => {
  const body = await readBody(event)

  if (!body.email || !body.password) {
    return createError({
      statusCode: 400,
      statusMessage: 'Missing email or password'
    })
  }

  const user = await authenticateUser(body.email, body.password)
  if (!user) {
    return createError({
      statusCode: 401,
      statusMessage: 'Invalid email or password'
    })
  }

  await createSession(event, user.id)
})
