<script setup lang="ts">
definePageMeta({
  middleware: ['protected-from-logged-in']
})
const email = ref('')
const password = ref('')
const status = ref('')
const route = useRoute()
async function signIn() {
  try {
    await $fetch('/api/auth/signin', {
      method: 'POST',
      body: {
        email: email.value,
        password: password.value
      }
    })
    if (route.query.redirect) {
      // this is safe since nuxt will throw error if redirect is out of app
      navigateTo(route.query.redirect as string)
    } else {
      navigateTo('/')
    }
  } catch (error: unknown) {
    if (error instanceof Error) {
      status.value = error.message
    } else {
      status.value = 'Unknown error'
    }
  }
}
</script>

<template>
  <div>
    <h1>Sign In</h1>
    <form
      method="post"
      @submit.prevent="signIn"
    >
      <label for="email">Email</label>
      <input
        id="email"
        v-model="email"
        type="email"
        autocomplete="username"
        name="email"
      >
      <label for="password">Password</label>
      <input
        id="password"
        v-model="password"
        type="password"
        autocomplete="current-password"
        name="password"
      >
      <div>{{ status }}</div>

      <button type="submit">
        Sign In
      </button>
    </form>
    <NuxtLink
      to="/reset-password"
      role="button"
    >
      forgot password
    </NuxtLink>

    <NuxtLink
      to="/signup"
      role="button"
    >
      signup
    </NuxtLink>
  </div>
</template>
