<template>
  <div>
    Verify your email
    <div>
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
      <div>{{ status }}</div>
    </div>
  </div>
</template>

<script lang="ts" setup>
async function sendVerificationEmail() {
  try {
    await $fetch('/api/auth/send-verification-email')
  } catch (error: unknown) {
    if (error instanceof Error) {
      status.value = error.message
    } else {
      status.value = 'Unknown error'
    }
  }
}
onMounted(() => {
  sendVerificationEmail()
})
const code = ref('')
const status = ref('')

async function verify() {
  try {
    await $fetch('/api/auth/signin', {
      method: 'POST',
      body: {
        code: code.value
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

<style>

</style>
