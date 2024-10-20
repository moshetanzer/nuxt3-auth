<script setup lang="ts">
async function logOut() {
  console.log('log out')
}
onMounted(() => {
  logOut()
})
</script>

<template>
  <div>Signing out...</div>
</template>
