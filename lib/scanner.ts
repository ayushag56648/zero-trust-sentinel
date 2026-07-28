// lib/scanner.ts
// Requires: npm install pdf-parse@1.1.1
//
// WHY require('pdf-parse/lib/pdf-parse.js') instead of require('pdf-parse'):
//
//   pdf-parse's index.js contains a self-test block that runs when
//   module.parent is null/undefined:
//
//     let isDebugMode = !module.parent;
//     if (isDebugMode) {
//       let dataBuffer = Fs.readFileSync('./test/data/05-versions-space.pdf');
//       ...
//     }
//
//   Next.js Turbopack loads every module as a top-level module
//   (module.parent === null), so the self-test ALWAYS triggers,
//   tries to read a test fixture that doesn't exist in the deployment,
//   and throws ENOENT.
//
//   The fix: import lib/pdf-parse.js directly — it's the same function
//   but with no self-test wrapper. v1.1.1 has no "exports" field in
//   package.json so this subpath is always accessible.

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

// ── Structural binary scan (PDF object tags) ─────────────────────────────────
function scanPdfStructure(rawBinary: string): ThreatSignal[] {
  const tags: Array<{ tag: string; label: string; weight: number; severity: ThreatSignal['severity'] }> = [
    { tag: '/JS',            label: 'Embedded JavaScript (/JS)',          weight: 40, severity: 'high'     },
    { tag: '/JavaScript',    label: 'Embedded JavaScript (/JavaScript)',  weight: 40, severity: 'high'     },
    { tag: '/OpenAction',    label: 'Auto-Execute on Open (/OpenAction)', weight: 50, severity: 'critical' },
    { tag: '/AA',            label: 'Additional Action Trigger (/AA)',    weight: 30, severity: 'high'     },
    { tag: '/Launch',        label: 'External Program Launch (/Launch)',  weight: 60, severity: 'critical' },
    { tag: '/EmbeddedFiles', label: 'Hidden Embedded Files',              weight: 40, severity: 'high'     },
    { tag: '/AcroForm',      label: 'Interactive Form (/AcroForm)',       weight: 15, severity: 'medium'   },
    { tag: '/GoToR',         label: 'Remote Go-To Action (/GoToR)',       weight: 25, severity: 'high'     },
    { tag: '/RichMedia',     label: 'Rich Media Embed (/RichMedia)',      weight: 20, severity: 'medium'   },
    { tag: '/ObjStm',        label: 'Object Stream (obfuscation risk)',   weight: 10, severity: 'low'      },
  ]
  return tags
    .filter(({ tag }) => rawBinary.includes(tag))
    .map(({ tag, label, weight, severity }) => ({
      type: 'structural' as const,
      severity,
      detail: `Malicious PDF structure: ${label}`,
      weight,
    }))
}

// ── Keyword scan ─────────────────────────────────────────────────────────────
function scanKeywords(text: string): ThreatSignal[] {
  const rules: Array<{ pattern: string; severity: ThreatSignal['severity']; weight: number }> = [
    { pattern: 'javascript:',      severity: 'high',     weight: 30 },
    { pattern: 'vbscript:',        severity: 'high',     weight: 30 },
    { pattern: 'cmd.exe',          severity: 'critical', weight: 40 },
    { pattern: 'powershell',       severity: 'critical', weight: 35 },
    { pattern: 'eval(',            severity: 'high',     weight: 25 },
    { pattern: 'base64_decode',    severity: 'high',     weight: 25 },
    { pattern: 'document.cookie',  severity: 'medium',   weight: 20 },
    { pattern: 'window.location',  severity: 'medium',   weight: 15 },
    { pattern: '<script',          severity: 'high',     weight: 30 },
    { pattern: 'onerror=',         severity: 'high',     weight: 30 },
    { pattern: 'shell_exec',       severity: 'critical', weight: 40 },
    { pattern: 'exec(',            severity: 'high',     weight: 25 },
    { pattern: '/etc/passwd',      severity: 'critical', weight: 40 },
    { pattern: 'net user',         severity: 'critical', weight: 35 },
    { pattern: '-ExecutionPolicy', severity: 'critical', weight: 40 },
    { pattern: 'certutil',         severity: 'high',     weight: 30 },
    { pattern: 'mshta',            severity: 'high',     weight: 30 },
    { pattern: 'wscript',          severity: 'high',     weight: 30 },
  ]
  return rules
    .filter(({ pattern }) => escapeRegex(pattern).test(text))
    .map(({ pattern, severity, weight }) => ({
      type: 'keyword' as const,
      severity,
      detail: `Malicious keyword in text: "${pattern}"`,
      weight,
    }))
}

// ── URL scan ─────────────────────────────────────────────────────────────────
function scanUrls(text: string): ThreatSignal[] {
  const signals: ThreatSignal[] = []
  const urls      = text.match(/https?:\/\/[^\s"'<>\r\n]+/gi) ?? []
  const ipUrl     = /https?:\/\/\d{1,3}(\.\d{1,3}){3}/i
  const typosquat = /(paypa1|arnazon|g00gle|micros0ft|app1e|faceb00k)/i
  const shortener = /(bit\.ly|t\.co|tinyurl|ow\.ly|is\.gd|rebrand\.ly)/i
  const badTld    = /\.(xyz|tk|ml|ga|cf|gq|pw|top|click|link|work|racing|stream)(\b|\/)/i

  for (const url of urls) {
    if (typosquat.test(url))
      signals.push({ type: 'url', severity: 'critical', detail: `Typosquat domain: ${url}`, weight: 40 })
    else if (ipUrl.test(url))
      signals.push({ type: 'url', severity: 'high',     detail: `IP-based URL: ${url}`,     weight: 28 })
    else if (shortener.test(url))
      signals.push({ type: 'url', severity: 'medium',   detail: `URL shortener: ${url}`,    weight: 18 })
    else if (badTld.test(url))
      signals.push({ type: 'url', severity: 'medium',   detail: `Suspicious TLD: ${url}`,   weight: 15 })
    else
      signals.push({ type: 'url', severity: 'low',      detail: `External URL: ${url}`,     weight: 5  })
  }
  return signals
}

// ── Pattern scan ─────────────────────────────────────────────────────────────
function scanPatterns(text: string): ThreatSignal[] {
  const signals: ThreatSignal[] = []
  if (/update.{0,30}password|verify.{0,30}account|confirm.{0,30}identity/i.test(text))
    signals.push({ type: 'pattern', severity: 'high',   detail: 'Phishing language: credential harvesting phrase', weight: 30 })
  if (/urgent|immediate.{0,20}action|account.{0,20}suspend/i.test(text))
    signals.push({ type: 'pattern', severity: 'medium', detail: 'Social engineering: urgency language',            weight: 15 })
  if (/\b(password|passwd|secret|api.?key|token)\s*[:=]\s*\S+/i.test(text))
    signals.push({ type: 'pattern', severity: 'high',   detail: 'Credential leak: key=value pattern',             weight: 30 })
  return signals
}

// ── Entropy scan ─────────────────────────────────────────────────────────────
function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {}
  for (const ch of str) freq[ch] = (freq[ch] ?? 0) + 1
  const len = str.length
  return -Object.values(freq).reduce((s, f) => { const p = f / len; return s + p * Math.log2(p) }, 0)
}

function scanEntropy(text: string): ThreatSignal[] {
  return (text.match(/[A-Za-z0-9+/=]{40,}/g) ?? [])
    .map(blob => ({ blob, e: shannonEntropy(blob) }))
    .filter(({ e }) => e > 5.2)
    .map(({ blob, e }) => ({
      type:     'entropy' as const,
      severity: (e > 5.8 ? 'high' : 'medium') as ThreatSignal['severity'],
      detail:   `High-entropy blob (Shannon=${e.toFixed(2)}): ${blob.slice(0, 30)}…`,
      weight:   e > 5.8 ? 25 : 12,
    }))
}

// ── Main export ───────────────────────────────────────────────────────────────
export async function analyzeFile(buffer: Buffer, filename: string): Promise<ScanResult> {
  let text         = ''
  let elementCount = 0

  if (filename.toLowerCase().endsWith('.pdf')) {
    const rawBinary = buffer.toString('binary')

    try {
      // ✅ Use lib/pdf-parse.js to bypass the self-test in index.js
      // index.js runs `Fs.readFileSync('./test/data/05-versions-space.pdf')` when
      // module.parent is null — which always happens in Next.js Turbopack.
      // lib/pdf-parse.js is the same function without that wrapper.
      const pdfParse = require('pdf-parse/lib/pdf-parse.js')
      const data     = await pdfParse(buffer)
      text         = data.text ?? ''
      elementCount = (data.numpages ?? 1) * 10
      console.log(`[scanner] extracted ${text.length} chars from ${data.numpages} page(s)`)
    } catch (err: any) {
      console.error('[scanner] pdf-parse failed:', err?.message ?? err)
    }

    const signals  = [
      ...scanPdfStructure(rawBinary),
      ...scanKeywords(text),
      ...scanUrls(text),
      ...scanPatterns(text),
      ...scanEntropy(text),
    ]
    const score = Math.min(Math.round(signals.reduce((s, sig) => s + sig.weight, 0)), 100)

    return {
      score,
      riskLevel: score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 35 ? 'medium' : score >= 10 ? 'low' : 'clean',
      signals,
      extractedText: text,
      elementCount,
    }
  }

  // Plain text / TXT
  text         = buffer.toString('utf-8')
  elementCount = text.split(/\s+/).filter(Boolean).length
  const signals  = [...scanKeywords(text), ...scanUrls(text), ...scanPatterns(text), ...scanEntropy(text)]
  const score    = Math.min(Math.round(signals.reduce((s, sig) => s + sig.weight, 0)), 100)

  return {
    score,
    riskLevel: score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 35 ? 'medium' : score >= 10 ? 'low' : 'clean',
    signals,
    extractedText: text,
    elementCount,
  }
}