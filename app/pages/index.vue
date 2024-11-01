<script setup lang="ts">
definePageMeta({
  middleware: ['protected']
})

const user = useUser()
</script>

<template>
  <div>
    <h1>Welcome to NuxtAuth</h1>
    <div>{{ user?.fname }}</div>
    <div>
      <NuxtLink to="/users">
        users
      </NuxtLink>
    </div>
    <button @click="useLogOut()">
      Sign Out
    </button>
  </div>
</template>
