<script setup lang="ts">
const email = ref('')
const status = ref('')
async function forgotPassword() {
  try {
    const response = await $fetch('/api/auth/reset-password', {
      method: 'POST',
      body: {
        email: email.value
      }
    })
    status.value = response.message
  } catch (error) {
    status.value = (error as Error).message
  }
}
</script>

<template>
  <div>
    <h1>Forgot Password</h1>
    <form
      method="post"
      @submit.prevent="forgotPassword"
    >
      <label for="email">Email</label>
      <input
        id="email"
        v-model="email"
        type="email"
        name="email"
      >
      <button type="submit">
        Submit
      </button>
    </form>
    {{ status }}
  </div>
</template>
