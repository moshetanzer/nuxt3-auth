<script setup lang="ts">
definePageMeta({
  middleware: ['protected']
})

const logOut = () => {
  navigateTo('/signout')
}
const user = useUser()
</script>

<template>
  <div>
    <h1>Welcome to NuxtAuth</h1>
    <span>{{ user?.fname }}</span>
    <NuxtLink to="/users">
      users
    </NuxtLink>
    <button @click="logOut">
      Sign Out
    </button>
  </div>
</template>
