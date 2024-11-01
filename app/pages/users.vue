<script setup lang="ts">
definePageMeta({
  middleware: ['protected'],
  auth: {
    roles: ['user']
  }
})

const { data, error } = await useFetch('/api/user/test', {
  method: 'post'
})
</script>

<template>
  <div>
    <h1>Users</h1>

    {{ data }}
    {{ error }}
    <NuxtLink to="/">
      Home
    </NuxtLink>
  </div>
</template>
