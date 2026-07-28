const mysql = require('mysql2/promise')
const fs = require('node:fs')
const path = require('node:path')

function loadDotenvLocal() {
  const envPath = path.join(process.cwd(), '.env.local')
  if (!fs.existsSync(envPath)) return
  const raw = fs.readFileSync(envPath, 'utf8')
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const eq = trimmed.indexOf('=')
    if (eq <= 0) continue
    const k = trimmed.slice(0, eq).trim()
    const v = trimmed.slice(eq + 1).trim()
    if (!process.env[k]) process.env[k] = v
  }
}

function parseUrl(url) {
  const parsed = new URL(url)
  return {
    host: parsed.hostname,
    port: parsed.port ? Number(parsed.port) : 3306,
    user: decodeURIComponent(parsed.username),
    password: decodeURIComponent(parsed.password),
    database: parsed.pathname.replace(/^\//, ''),
  }
}

async function main() {
  loadDotenvLocal()
  const url = process.env.MYSQL_URL || process.env.DATABASE_URL
  const cfg = url
    ? parseUrl(url)
    : {
      host: process.env.MYSQL_HOST,
      port: process.env.MYSQL_PORT ? Number(process.env.MYSQL_PORT) : 3306,
      user: process.env.MYSQL_USER,
      password: process.env.MYSQL_PASSWORD,
      database: process.env.MYSQL_DATABASE,
    }

  if (!cfg.host || !cfg.user || !cfg.database) {
    throw new Error('Missing MySQL config. Add .env.local from .env.example')
  }

  const conn = await mysql.createConnection(cfg)
  const [rows] = await conn.query('SELECT NOW() AS now_time, DATABASE() AS db_name')
  console.log('MySQL connection OK:', rows[0])
  await conn.end()
}

main().catch((err) => {
  console.error('MySQL connection FAILED:', err.message)
  process.exit(1)
})
