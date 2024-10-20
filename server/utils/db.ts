import pg from 'pg'

const { Pool } = pg

export const connectionString = useRuntimeConfig().authDB
export const authDB = new Pool({
  connectionString
})
