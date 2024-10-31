<script setup lang="ts">
definePageMeta({
  middleware: ['reset-password-verification']
})
const password = ref('')
const confirmPassword = ref('')
const status = ref('')
async function resetPassword() {
  try {
    const response = await $fetch('/api/auth/reset-password/reset', {
      method: 'POST',
      body: {
        password: password.value,
        confirmPassword: confirmPassword.value,
        resetToken: useRoute().params.resetToken
      }
    })
    if (response.success === true) {
      status.value = response.message
    } else {
      status.value = response.message
    }
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
      @submit.prevent="resetPassword()"
    >
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
    {{ status }}
  </div>
</template>
