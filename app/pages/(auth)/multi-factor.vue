<script setup lang="ts">
const code = ref('')

async function verify() {
  const response = await $fetch('/api/auth/verify', {
    method: 'POST',
    body: {
      code: code.value
    }
  })
  if (response.error) {
    error.value = response.error
  } else {
    navigateTo('/')
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
  </div>
</template>
