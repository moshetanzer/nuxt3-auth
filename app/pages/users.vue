<script setup lang="ts">
definePageMeta({
  middleware: ['protected'],
  auth: {
    roles: ['user']
  }
})
const { data: users, status, error } = await useFetch('/api/admin/users',
  { method: 'POST' }
)
const { data: user } = await useFetch('/api/user/test', {
  method: 'POST'

})
</script>

<template>
  <div>
    <h1>Users</h1>

    {{ users }}
    {{ status }}
    {{ error }}

    {{ user }}
    <NuxtLink to="/">
      Home
    </NuxtLink>
  </div>
</template>
