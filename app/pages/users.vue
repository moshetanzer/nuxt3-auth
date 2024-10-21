<script setup lang="ts">
definePageMeta({
  middleware: ['protected'],
  auth: {
    roles: ['user']
  }
})
</script>

<template>
  <div>
    <h1>Users</h1>
    <NuxtLink to="/">
      Home
    </NuxtLink>
  </div>
</template>
