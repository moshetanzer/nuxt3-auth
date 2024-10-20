export defineEventHandler(async (event) => {
    const body = await readBody(event);
    const { email, password } = body;

    const user = await authenticateUser(email, password);

    if (!user) {
        createError({
            statusCode: 401,
            statusMessage: 'Invalid email or password'
        })
    }

    return user
})