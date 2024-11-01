<script setup lang="ts">
definePageMeta({
  middleware: ['protected'],
  auth: {
    roles: ['user']
  }
})

const { data } = await useSecureFetch('/api/user/test', {
  method: 'POST'
})
</script>

<template>
  <div>
    <h1>Users</h1>
    {{ data }}
    <NuxtLink to="/">
      Home
    </NuxtLink>
  </div>
</template>
