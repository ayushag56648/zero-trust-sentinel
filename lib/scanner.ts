// lib/scanner.ts
// Requires: npm install pdf-parse@1.1.1
//
// WHY require('pdf-parse/lib/pdf-parse.js') instead of require('pdf-parse'):
//   pdf-parse's index.js self-test always fires in Next.js Turbopack because
//   module.parent is null, causing ENOENT on a missing test fixture.
//   Importing the inner file bypasses this wrapper entirely.

if (typeof global.DOMMatrix === 'undefined') {
  // @ts-ignore
  global.DOMMatrix = class DOMMatrix {}
}

export interface ThreatSignal {
  type:     'keyword' | 'url' | 'entropy' | 'pattern' | 'structural'
  severity: 'low' | 'medium' | 'high' | 'critical'
  detail:   string
  weight:   number
}

export interface ScanResult {
  score:         number
  riskLevel:     'clean' | 'low' | 'medium' | 'high' | 'critical'
  signals:       ThreatSignal[]
  extractedText: string
  elementCount:  number
}

function escapeRegex(str: string): RegExp {
  return new RegExp(str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi')
}

// ─────────────────────────────────────────────────────────────────────────────
// FIX 1 — Hex-obfuscation normaliser
//
// Attackers write /J#61vaScript — hex-encoded 'a' — which PDF readers parse
// as /JavaScript but defeats plain string-match scanners.
// We decode all #XX sequences BEFORE scanning so obfuscated tags are caught.
// ─────────────────────────────────────────────────────────────────────────────
function normalisePdfBinary(raw: string): string {
  return raw.replace(/#([0-9A-Fa-f]{2})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// FIX 2 — Magic byte / file header validation
//
// Checks the actual binary signature, not just the file extension.
// Catches: EXEs disguised as PDFs, polyglot PDF+ZIP bombs, OLE2 macro docs,
// Linux/macOS executables, and RAR archives smuggled as documents.
// ─────────────────────────────────────────────────────────────────────────────
function validateFileHeader(buffer: Buffer, filename: string): ThreatSignal[] {
  const signals: ThreatSignal[] = []
  const headerHex   = buffer.slice(0, 8).toString('hex').toLowerCase()
  const headerAscii = buffer.slice(0, 8).toString('ascii')

  // PDF must start with %PDF
  if (filename.toLowerCase().endsWith('.pdf') && !headerAscii.startsWith('%PDF')) {
    signals.push({
      type: 'structural', severity: 'critical',
      detail: 'File claims to be PDF but is missing the %PDF header — likely a disguised executable or corrupt file',
      weight: 70,
    })
  }

  // Windows executable — MZ magic bytes (4d5a)
  if (headerHex.startsWith('4d5a')) {
    signals.push({
      type: 'structural', severity: 'critical',
      detail: 'Windows executable (MZ) magic bytes detected — file is an EXE, DLL, or PE binary disguised as a document',
      weight: 90,
    })
  }

  // ZIP / polyglot — PK magic (504b0304)
  // A PDF+ZIP polyglot is simultaneously a valid PDF and a valid ZIP.
  // Opening in a PDF reader looks clean; renaming to .zip reveals the payload.
  if (headerHex.startsWith('504b0304')) {
    signals.push({
      type: 'structural', severity: 'high',
      detail: 'ZIP magic bytes (PK) found — possible polyglot PDF+ZIP file or OOXML Office macro document',
      weight: 55,
    })
  }

  // ELF binary — Linux/Unix executable (7f454c46)
  if (headerHex.startsWith('7f454c46')) {
    signals.push({
      type: 'structural', severity: 'critical',
      detail: 'ELF binary magic bytes detected — file is a Linux/Unix executable disguised as a document',
      weight: 90,
    })
  }

  // Mach-O binary — macOS executable (feedface / feedfacf / cefaedfe / cffaedfe)
  if (['feedface', 'feedfacf', 'cefaedfe', 'cffaedfe'].some(m => headerHex.startsWith(m))) {
    signals.push({
      type: 'structural', severity: 'critical',
      detail: 'Mach-O binary magic bytes detected — file is a macOS executable disguised as a document',
      weight: 90,
    })
  }

  // OLE2 compound document — d0cf11e0 (legacy .doc/.xls/.ppt with VBA macros)
  if (headerHex.startsWith('d0cf11e0')) {
    signals.push({
      type: 'structural', severity: 'high',
      detail: 'OLE2 compound document magic bytes — legacy Office format that supports VBA macros',
      weight: 40,
    })
  }

  // RAR archive — 526172211a07
  if (headerHex.startsWith('526172211a07')) {
    signals.push({
      type: 'structural', severity: 'medium',
      detail: 'RAR archive magic bytes found — archive file disguised as a document',
      weight: 30,
    })
  }

  return signals
}

// ─────────────────────────────────────────────────────────────────────────────
// Structural binary scan — PDF dangerous object tags
// Operates on the hex-normalised binary so obfuscated tags are found (Fix 1)
// ─────────────────────────────────────────────────────────────────────────────
function scanPdfStructure(normalisedBinary: string): ThreatSignal[] {
  const tags: Array<{
    tag: string; label: string; weight: number; severity: ThreatSignal['severity']
  }> = [
    { tag: '/JS',            label: 'Embedded JavaScript (/JS)',           weight: 40, severity: 'high'     },
    { tag: '/JavaScript',    label: 'Embedded JavaScript (/JavaScript)',   weight: 40, severity: 'high'     },
    { tag: '/OpenAction',    label: 'Auto-execute on open (/OpenAction)',  weight: 50, severity: 'critical' },
    { tag: '/AA',            label: 'Additional action trigger (/AA)',     weight: 30, severity: 'high'     },
    { tag: '/Launch',        label: 'External program launch (/Launch)',   weight: 60, severity: 'critical' },
    { tag: '/EmbeddedFiles', label: 'Hidden embedded files',               weight: 40, severity: 'high'     },
    { tag: '/AcroForm',      label: 'Interactive form (/AcroForm)',        weight: 15, severity: 'medium'   },
    { tag: '/GoToR',         label: 'Remote go-to action (/GoToR)',        weight: 25, severity: 'high'     },
    { tag: '/RichMedia',     label: 'Rich media embed (/RichMedia)',       weight: 20, severity: 'medium'   },
    { tag: '/ObjStm',        label: 'Object stream — obfuscation risk',    weight: 10, severity: 'low'      },
    { tag: '/XFA',           label: 'XFA active XML form content',         weight: 25, severity: 'high'     },
    { tag: '/SubmitForm',    label: 'Form data submission (/SubmitForm)',   weight: 30, severity: 'high'     },
    { tag: '/ImportData',    label: 'External data import (/ImportData)',  weight: 30, severity: 'high'     },
    { tag: '/Sound',         label: 'Embedded sound object',               weight: 15, severity: 'medium'   },
    { tag: '/Movie',         label: 'Embedded movie object',               weight: 20, severity: 'medium'   },
    { tag: '/URI',           label: 'URI action object',                   weight: 10, severity: 'low'      },
  ]

  return tags
    .filter(({ tag }) => normalisedBinary.includes(tag))
    .map(({ label, weight, severity }) => ({
      type:     'structural' as const,
      severity,
      detail:   `Dangerous PDF structure detected: ${label}`,
      weight,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// FIX 3 — Encryption + empty content detection
//
// An encrypted PDF returns empty text from pdf-parse. Without this check the
// scanner scores it 0 (clean) — a dangerous false negative. Encrypted PDFs
// are a common malware delivery method specifically because they blind scanners.
// ─────────────────────────────────────────────────────────────────────────────
function scanEncryptionAndEmptiness(
  rawBinary:     string,
  extractedText: string,
): ThreatSignal[] {
  const signals: ThreatSignal[] = []
  const isEncrypted = rawBinary.includes('/Encrypt')
  const isEmpty     = extractedText.trim().length < 20

  if (isEncrypted) {
    signals.push({
      type:     'structural',
      severity: 'high',
      detail:   'PDF is encrypted — full content analysis is blocked. Treat as untrusted.',
      weight:   35,
    })
  }

  // Empty + non-encrypted = image-only PDF (common phishing tactic)
  if (isEmpty && !isEncrypted) {
    signals.push({
      type:     'structural',
      severity: 'medium',
      detail:   'PDF contains no extractable text — may be image-only (common in phishing docs) or heavily obfuscated.',
      weight:   20,
    })
  }

  return signals
}

// ─────────────────────────────────────────────────────────────────────────────
// Keyword scan — malicious commands and script patterns
// ─────────────────────────────────────────────────────────────────────────────
function scanKeywords(text: string): ThreatSignal[] {
  const rules: Array<{ pattern: string; severity: ThreatSignal['severity']; weight: number }> = [
    { pattern: 'javascript:',       severity: 'high',     weight: 30 },
    { pattern: 'vbscript:',         severity: 'high',     weight: 30 },
    { pattern: 'cmd.exe',           severity: 'critical', weight: 40 },
    { pattern: 'powershell',        severity: 'critical', weight: 35 },
    { pattern: 'eval(',             severity: 'high',     weight: 25 },
    { pattern: 'base64_decode',     severity: 'high',     weight: 25 },
    { pattern: 'document.cookie',   severity: 'medium',   weight: 20 },
    { pattern: 'window.location',   severity: 'medium',   weight: 15 },
    { pattern: '<script',           severity: 'high',     weight: 30 },
    { pattern: 'onerror=',          severity: 'high',     weight: 30 },
    { pattern: 'shell_exec',        severity: 'critical', weight: 40 },
    { pattern: 'exec(',             severity: 'high',     weight: 25 },
    { pattern: '/etc/passwd',       severity: 'critical', weight: 40 },
    { pattern: 'net user',          severity: 'critical', weight: 35 },
    { pattern: '-ExecutionPolicy',  severity: 'critical', weight: 40 },
    { pattern: 'certutil',          severity: 'high',     weight: 30 },
    { pattern: 'mshta',             severity: 'high',     weight: 30 },
    { pattern: 'wscript',           severity: 'high',     weight: 30 },
    { pattern: 'regsvr32',          severity: 'high',     weight: 30 },
    { pattern: 'rundll32',          severity: 'high',     weight: 30 },
    { pattern: 'bitsadmin',         severity: 'high',     weight: 30 },
    { pattern: 'msiexec',           severity: 'high',     weight: 25 },
    { pattern: 'reg add',           severity: 'critical', weight: 35 },
    { pattern: 'reg delete',        severity: 'critical', weight: 35 },
    { pattern: 'schtasks',          severity: 'high',     weight: 30 },
    { pattern: 'invoke-expression', severity: 'critical', weight: 40 },
    { pattern: 'iex(',              severity: 'critical', weight: 40 },
    { pattern: 'frombase64string',  severity: 'high',     weight: 30 },
  ]
  return rules
    .filter(({ pattern }) => escapeRegex(pattern).test(text))
    .map(({ pattern, severity, weight }) => ({
      type:     'keyword' as const,
      severity,
      detail:   `Malicious keyword detected: "${pattern}"`,
      weight,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// URL scan — phishing domains, IP URLs, shorteners, bad TLDs
// ─────────────────────────────────────────────────────────────────────────────
function scanUrls(text: string): ThreatSignal[] {
  const signals: ThreatSignal[] = []
  const urls      = text.match(/https?:\/\/[^\s"'<>\r\n]+/gi) ?? []
  const ipUrl     = /https?:\/\/\d{1,3}(\.\d{1,3}){3}/i
  const typosquat = /(paypa1|arnazon|g00gle|micros0ft|app1e|faceb00k|netfl1x|linkedln)/i
  const shortener = /(bit\.ly|t\.co|tinyurl|ow\.ly|is\.gd|rebrand\.ly|short\.io|tiny\.cc)/i
  const badTld    = /\.(xyz|tk|ml|ga|cf|gq|pw|top|click|link|work|racing|stream|download|party)(\b|\/)/i

  for (const url of urls) {
    if (typosquat.test(url))
      signals.push({ type: 'url', severity: 'critical', detail: `Typosquat domain: ${url}`,             weight: 40 })
    else if (ipUrl.test(url))
      signals.push({ type: 'url', severity: 'high',     detail: `IP-based URL (no domain): ${url}`,     weight: 28 })
    else if (shortener.test(url))
      signals.push({ type: 'url', severity: 'medium',   detail: `URL shortener hides destination: ${url}`, weight: 18 })
    else if (badTld.test(url))
      signals.push({ type: 'url', severity: 'medium',   detail: `Suspicious TLD: ${url}`,               weight: 15 })
    else
      signals.push({ type: 'url', severity: 'low',      detail: `External URL: ${url}`,                 weight: 5  })
  }
  return signals
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern scan — social engineering + credential leaks
// ─────────────────────────────────────────────────────────────────────────────
function scanPatterns(text: string): ThreatSignal[] {
  const signals: ThreatSignal[] = []

  if (/update.{0,30}password|verify.{0,30}account|confirm.{0,30}identity/i.test(text))
    signals.push({ type: 'pattern', severity: 'high',   detail: 'Phishing language: credential harvesting phrase', weight: 30 })

  if (/urgent|immediate.{0,20}action|account.{0,20}suspend/i.test(text))
    signals.push({ type: 'pattern', severity: 'medium', detail: 'Social engineering: urgency language',            weight: 15 })

  if (/\b(password|passwd|secret|api.?key|token|access.?key)\s*[:=]\s*\S+/i.test(text))
    signals.push({ type: 'pattern', severity: 'high',   detail: 'Credential leak: key=value pattern',             weight: 30 })

  if (/your.{0,20}(account|card|bank).{0,20}(has been|will be).{0,20}(suspended|blocked|closed)/i.test(text))
    signals.push({ type: 'pattern', severity: 'high',   detail: 'Phishing language: account suspension threat',   weight: 28 })

  if (/click.{0,20}(here|below|link).{0,30}(verify|confirm|validate|unlock)/i.test(text))
    signals.push({ type: 'pattern', severity: 'medium', detail: 'Phishing language: click-to-verify instruction', weight: 20 })

  return signals
}

// ─────────────────────────────────────────────────────────────────────────────
// Entropy scan — detects base64-encoded or encrypted payloads
// Shannon entropy > 5.2 on a long string = likely obfuscated/encoded content
// ─────────────────────────────────────────────────────────────────────────────
function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {}
  for (const ch of str) freq[ch] = (freq[ch] ?? 0) + 1
  const len = str.length
  return -Object.values(freq).reduce((s, f) => {
    const p = f / len
    return s + p * Math.log2(p)
  }, 0)
}

function scanEntropy(text: string): ThreatSignal[] {
  return (text.match(/[A-Za-z0-9+/=]{40,}/g) ?? [])
    .map(blob => ({ blob, e: shannonEntropy(blob) }))
    .filter(({ e }) => e > 5.2)
    .map(({ blob, e }) => ({
      type:     'entropy' as const,
      severity: (e > 5.8 ? 'high' : 'medium') as ThreatSignal['severity'],
      detail:   `High-entropy string (Shannon=${e.toFixed(2)}) — likely encoded payload: ${blob.slice(0, 30)}…`,
      weight:   e > 5.8 ? 25 : 12,
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Score → risk level
// ─────────────────────────────────────────────────────────────────────────────
function toRiskLevel(score: number): ScanResult['riskLevel'] {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 35) return 'medium'
  if (score >= 10) return 'low'
  return 'clean'
}

// ─────────────────────────────────────────────────────────────────────────────
// Main export
// ─────────────────────────────────────────────────────────────────────────────
export async function analyzeFile(buffer: Buffer, filename: string): Promise<ScanResult> {
  let text         = ''
  let elementCount = 0

  // FIX 2 — magic-byte check runs first, before any format-specific parsing
  const headerSignals = validateFileHeader(buffer, filename)

  if (filename.toLowerCase().endsWith('.pdf')) {
    const rawBinary = buffer.toString('binary')

    // FIX 1 — normalise hex-obfuscated tags before structural scan
    const normalisedBinary = normalisePdfBinary(rawBinary)

    try {
      const pdfParse = require('pdf-parse/lib/pdf-parse.js')
      const data     = await pdfParse(buffer)
      text         = data.text ?? ''
      elementCount = (data.numpages ?? 1) * 10
      console.log(`[scanner] extracted ${text.length} chars from ${data.numpages} page(s)`)
    } catch (err: any) {
      console.error('[scanner] pdf-parse failed:', err?.message ?? err)
    }

    // FIX 3 — encryption / empty-content check after extraction attempt
    const encryptionSignals = scanEncryptionAndEmptiness(rawBinary, text)

    const signals = [
      ...headerSignals,
      ...encryptionSignals,
      ...scanPdfStructure(normalisedBinary),
      ...scanKeywords(text),
      ...scanUrls(text),
      ...scanPatterns(text),
      ...scanEntropy(text),
    ]

    const score = Math.min(
      Math.round(signals.reduce((s, sig) => s + sig.weight, 0)),
      100,
    )

    return { score, riskLevel: toRiskLevel(score), signals, extractedText: text, elementCount }
  }

  // ── Plain text / TXT ──────────────────────────────────────────────────────
  text         = buffer.toString('utf-8')
  elementCount = text.split(/\s+/).filter(Boolean).length

  const signals = [
    ...headerSignals,
    ...scanKeywords(text),
    ...scanUrls(text),
    ...scanPatterns(text),
    ...scanEntropy(text),
  ]

  const score = Math.min(
    Math.round(signals.reduce((s, sig) => s + sig.weight, 0)),
    100,
  )

  return { score, riskLevel: toRiskLevel(score), signals, extractedText: text, elementCount }
}