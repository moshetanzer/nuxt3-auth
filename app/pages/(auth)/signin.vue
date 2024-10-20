<script setup lang="ts">
definePageMeta({
  middleware: ['signin']
})
const email = ref('')
const password = ref('')
const status = ref('')

async function signIn() {
  try {
    await $fetch('/api/auth/signin', {
      method: 'POST',
      body: {
        email: email.value,
        password: password.value
      }
    })
    navigateTo('/')
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
    <form @submit.prevent="signIn">
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
  </div>
</template>
