<script setup lang="ts">
const password = ref('')
const confirmPassword = ref('')

async function resetPassword() {
  const response = await $fetch('/api/auth/forgot-password', {
    method: 'POST',
    body: {
      password: password.value,
      confirmPassword: confirmPassword.value,
      token: useRoute().query.resetToken
    }
  })
  console.log(response)
}
</script>

<template>
  <div>
    <h1>Forgot Password</h1>
    <form @submit.prevent="resetPassword()">
      <label for="new-password">New Password</label>
      <input
        id="new-password"
        v-model="password"
        type="password"
        name="password"
        autocomplete="new-password"
      >
      <label for="confirm-password">Confirm Password</label>
      <input
        id="confirm-password"
        v-model="confirmPassword"
        type="password"
        name="confirmPassword"
        autocomplete="new-password"
      >

      <button type="submit">
        reset password
      </button>
    </form>
  </div>
</template>
