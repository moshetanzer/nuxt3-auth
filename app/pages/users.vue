<script setup lang="ts">
definePageMeta({
  middleware: ['protected'],
  auth: {
    roles: ['user']
  }
})

const { data: response } = await useSecureFetch('/api/user/test')
// const { data: response } = await useAsyncData('response', () => useRequestFetch()('/api/user/test'))
</script>

<template>
  <div>
    <h1>Users</h1>

    {{ response }}
    <NuxtLink to="/">
      Home
    </NuxtLink>
  </div>
</template>
