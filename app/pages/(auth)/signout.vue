<script setup lang="ts">
async function logOut() {
  await $fetch('/api/auth/signout', {
    method: 'POST'
  })
  navigateTo('/')
}
onMounted(() => {
  logOut()
})
</script>

<template>
  <div>Signing out...</div>
</template>
