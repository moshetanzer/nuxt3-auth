<script setup lang="ts">
const email = ref('')

async function forgotPassword() {
  const response = await $fetch('/api/auth/reset-password', {
    method: 'POST',
    body: {
      email: email.value
    }
  })
  console.log(response)
}
</script>

<template>
  <div>
    <h1>Forgot Password</h1>
    <form @submit.prevent="forgotPassword">
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
  </div>
</template>
