export default defineEventHandler(async (event) => {
  const body = await readBody(event)

  if (!body.fname || !body.lname || !body.email || !body.password) {
    return createError({
      statusCode: 400,
      statusMessage: 'Missing fname, lname, email or password'
    })
  }

  const user = await createUser(body.fname, body.lname, body.email, body.password, 'user')
  if (!user) {
    return createError({
      statusCode: 400,
      statusMessage: 'Failed to create user'
    })
  }

  return {
    message: 'Account created. Please login.'
  }
})
