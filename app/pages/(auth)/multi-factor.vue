<script setup lang="ts">
const code = ref('')
const status = ref('')
async function verify() {
  try {
    const response = await $fetch('/api/auth/verify', {
      method: 'POST',
      body: {
        code: code.value
      }
    })
    if (!response.success) {
      status.value = response.message
    } else {
      navigateTo('/')
    }
  } catch (error) {
    status.value = (error as Error).message
  }
}
</script>

<template>
  <div>
    <h1>Multi Factor Auth</h1>
    <form @submit.prevent="verify">
      <label for="code">Code</label>
      <input
        id="code"
        v-model="code"
        type="text"
        name="code"
      >
      <button type="submit">
        Verify
      </button>
    </form>
    {{ status }}
  </div>
</template>
