import type { Pool } from 'mysql2/promise'
import mysql from 'mysql2/promise'

declare global {
  // eslint-disable-next-line no-var
  var __zts_mysqlPool: Pool | undefined
}

function requireEnv(name: string): string {
  const v = process.env[name]
  if (!v) throw new Error(`Missing required env var: ${name}`)
  return v
}

export function isGatekeeperConfigured(): boolean {
  return Boolean(
    process.env.MYSQL_HOST &&
    process.env.MYSQL_USER &&
    process.env.MYSQL_PASSWORD &&
    process.env.MYSQL_DATABASE,
  )
}

export function getMysqlPool(): Pool {
  if (global.__zts_mysqlPool) return global.__zts_mysqlPool

  const host = requireEnv('MYSQL_HOST')
  const user = requireEnv('MYSQL_USER')
  const password = requireEnv('MYSQL_PASSWORD')
  const database = requireEnv('MYSQL_DATABASE')
  const port = process.env.MYSQL_PORT ? Number(process.env.MYSQL_PORT) : 3306

  global.__zts_mysqlPool = mysql.createPool({
    host,
    user,
    password,
    database,
    port,
    waitForConnections: true,
    connectionLimit: 10,
    enableKeepAlive: true,
  })

  return global.__zts_mysqlPool
}

export type GatekeeperRow = {
  scan_count: number
}

export async function getUserScanCount(userId: string): Promise<number> {
  const pool = getMysqlPool()
  const table = process.env.MYSQL_GATEKEEPER_TABLE ?? 'user_gatekeeper'
  const userIdCol = process.env.MYSQL_GATEKEEPER_USER_ID_COL ?? 'user_id'
  const scanCountCol = process.env.MYSQL_GATEKEEPER_SCAN_COUNT_COL ?? 'scan_count'

  // Ensure a row exists (requires a UNIQUE index on user_id)
  await pool.query(
    `INSERT INTO \`${table}\` (\`${userIdCol}\`, \`${scanCountCol}\`) VALUES (?, 0)
     ON DUPLICATE KEY UPDATE \`${scanCountCol}\` = \`${scanCountCol}\``,
    [userId],
  )

  const [rows] = await pool.query<any[]>(
    `SELECT \`${scanCountCol}\` AS scan_count FROM \`${table}\` WHERE \`${userIdCol}\` = ? LIMIT 1`,
    [userId],
  )

  const row = rows?.[0] as GatekeeperRow | undefined
  return typeof row?.scan_count === 'number' ? row.scan_count : 0
}

export async function incrementUserScanCount(userId: string): Promise<void> {
  const pool = getMysqlPool()
  const table = process.env.MYSQL_GATEKEEPER_TABLE ?? 'user_gatekeeper'
  const userIdCol = process.env.MYSQL_GATEKEEPER_USER_ID_COL ?? 'user_id'
  const scanCountCol = process.env.MYSQL_GATEKEEPER_SCAN_COUNT_COL ?? 'scan_count'

  await pool.query(
    `UPDATE \`${table}\` SET \`${scanCountCol}\` = \`${scanCountCol}\` + 1 WHERE \`${userIdCol}\` = ?`,
    [userId],
  )
}

