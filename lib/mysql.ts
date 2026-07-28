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

function parseConnectionUrl(url: string): {
  host: string
  user: string
  password: string
  database: string
  port: number
} {
  const parsed = new URL(url)
  const host = parsed.hostname
  const user = decodeURIComponent(parsed.username)
  const password = decodeURIComponent(parsed.password)
  const database = parsed.pathname.replace(/^\//, '')
  const port = parsed.port ? Number(parsed.port) : 3306

  if (!host || !user || !database) {
    throw new Error('Invalid MySQL URL. Expected mysql://user:pass@host:3306/database')
  }

  return { host, user, password, database, port }
}

export function isGatekeeperConfigured(): boolean {
  if (process.env.MYSQL_URL || process.env.DATABASE_URL) return true

  return Boolean(
    process.env.MYSQL_HOST &&
    process.env.MYSQL_USER &&
    process.env.MYSQL_PASSWORD &&
    process.env.MYSQL_DATABASE,
  )
}

export function getMysqlPool(): Pool {
  if (global.__zts_mysqlPool) return global.__zts_mysqlPool

  const connectionUrl = process.env.MYSQL_URL || process.env.DATABASE_URL
  const config = connectionUrl
    ? parseConnectionUrl(connectionUrl)
    : {
        host: requireEnv('MYSQL_HOST'),
        user: requireEnv('MYSQL_USER'),
        password: requireEnv('MYSQL_PASSWORD'),
        database: requireEnv('MYSQL_DATABASE'),
        port: process.env.MYSQL_PORT ? Number(process.env.MYSQL_PORT) : 3306,
      }

  global.__zts_mysqlPool = mysql.createPool({
    host: config.host,
    user: config.user,
    password: config.password,
    database: config.database,
    port: config.port,
    waitForConnections: true,
    connectionLimit: 10,
    enableKeepAlive: true,
  })

  return global.__zts_mysqlPool
}

// ── AUDIT LOGGING FUNCTION ──────────────────────────────────────────────────
export async function logAuditTrail(filename: string, fileType: string, riskLevel: string, actionTaken: string) {
  const pool = getMysqlPool()
  await pool.execute(
    'INSERT INTO scan_logs (filename, file_type, risk_level, action_taken) VALUES (?, ?, ?, ?)',
    [filename, fileType, riskLevel, actionTaken],
  )
}

export type GatekeeperRow = {
  scan_count: number
}

export async function getUserScanCount(userId: string): Promise<number> {
  const pool = getMysqlPool()
  const table = process.env.MYSQL_GATEKEEPER_TABLE ?? 'user_gatekeeper'
  const userIdCol = process.env.MYSQL_GATEKEEPER_USER_ID_COL ?? 'user_id'
  const scanCountCol = process.env.MYSQL_GATEKEEPER_SCAN_COUNT_COL ?? 'scan_count'

  await pool.query(
    `INSERT INTO \`${table}\` (\`${userIdCol}\`, \`${scanCountCol}\`) VALUES (?, 0) ON DUPLICATE KEY UPDATE \`${scanCountCol}\` = \`${scanCountCol}\``,
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

// ── DEFAULT EXPORT (Fixes the Build Error) ──────────────────────────────────
const pool = getMysqlPool()
export default pool