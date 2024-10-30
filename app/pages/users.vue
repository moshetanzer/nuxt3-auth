<script setup lang="ts">
definePageMeta({
  middleware: ['protected'],
  auth: {
    roles: ['user']
  }
})

const { data: test } = await useFetch('/api/user/test', {
  method: 'POST'
})
</script>

<template>
  <div>
    <h1>Users</h1>

    {{ test }}
    <NuxtLink to="/">
      Home
    </NuxtLink>
  </div>
</template>
