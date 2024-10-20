<script setup lang="ts">
definePageMeta({
  middleware: ['signin']
})
const email = ref('')
const password = ref('')
const error = ref('')
async function signIn() {
  const response = await $fetch('/api/auth/signin', {
    method: 'POST',
    body: {
      email: email.value,
      password: password.value
    }
  })
  if (response && response.statusCode !== 200) {
    error.value = response.message || 'An error occurred'
  } else {
    navigateTo('/')
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
        name="email"
      >
      <label for="password">Password</label>
      <input
        id="password"
        v-model="password"
        type="password"
        name="password"
      >

      <button type="submit">
        Sign In
      </button>
    </form>
    <div>
      {{ error }}
    </div>
  </div>
</template>
