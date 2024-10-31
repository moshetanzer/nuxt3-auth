<script lang="ts" setup>
const fname = ref('')
const lname = ref('')
const email = ref('')
const password = ref('')
const confirmPassword = ref('')
const status = ref('')

async function signUp() {
  try {
    await $fetch('/api/auth/signup', {
      method: 'POST',
      body: {
        fname: fname.value,
        lname: lname.value,
        email: email.value,
        password: password.value,
        confirmPassword: confirmPassword.value
      }
    })
    status.value = 'Account created. Please sign in.'
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
    <h1>Sign Up</h1>
    <form
      method="post"
      @submit.prevent="signUp"
    >
      <label for="fname">First Name</label>
      <input
        id="fname"
        v-model="fname"
        type="text"
        name="fname"
      >
      <label for="lname">Last Name</label>
      <input
        id="lname"
        v-model="lname"
        type="text"
        name="lname"
      >
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
      <label for="confirmPassword">Confirm Password</label>
      <input
        id="confirmPassword"
        v-model="confirmPassword"
        type="password"
        name="confirmPassword"
      >
      <button type="submit">
        Sign Up
      </button>
      <p v-if="status">
        {{ status }}
      </p>
    </form>
  </div>
</template>
