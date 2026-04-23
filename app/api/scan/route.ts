// app/api/scan/route.ts

import { NextRequest } from 'next/server'
import { analyzeFile } from '@/lib/scanner'
import { createSafePdf } from '@/lib/reconstructor'
import Groq from 'groq-sdk'
import { getUserScanCount, incrementUserScanCount, isGatekeeperConfigured } from '@/lib/mysql'

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY ?? '' })

// ─────────────────────────────────────────────────────────────────────────────
// FIX 4 — File size limit
// Prevents memory exhaustion from huge uploads going through the full pipeline
// ─────────────────────────────────────────────────────────────────────────────
const MAX_FILE_BYTES = 20 * 1024 * 1024  // 20 MB

// ─────────────────────────────────────────────────────────────────────────────
// FIX 5 — Allowed MIME types
// The browser accept attribute is trivially bypassed by renaming a file.
// We check the actual MIME type reported by the multipart form data.
// ─────────────────────────────────────────────────────────────────────────────
const ALLOWED_MIME_TYPES = new Set([
  'application/pdf',
  'text/plain',
])

function escapeRegex(str: string): RegExp {
  return new RegExp(str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi')
}

function sse(data: object): string {
  return `data: ${JSON.stringify(data)}\n\n`
}

const DISARM_KEYWORDS = [
  'javascript:', 'vbscript:', 'cmd.exe', 'powershell', 'eval(',
  'base64_decode', 'document.cookie', 'window.location', '<script',
  'onerror=', 'onload=', 'shell_exec', 'exec(', 'system(',
  '/etc/passwd', 'net user', 'reg add', 'certutil', 'mshta',
  'wscript', '-ExecutionPolicy', 'regsvr32', 'rundll32',
  'invoke-expression', 'iex(', 'frombase64string', 'bitsadmin',
]

export async function POST(req: NextRequest) {
  console.log(process.env.GROQ_API_KEY ? 'Groq API Key Found' : 'Groq API Key Missing')

  // ── Gatekeeper (DB quota check) ──────────────────────────────────────────
  const userId = req.headers.get('x-user-id')?.trim()
  if (!userId) {
    return new Response(
      JSON.stringify({ error: 'Missing user identity (x-user-id header)' }),
      { status: 401, headers: { 'Content-Type': 'application/json' } },
    )
  }

  const gatekeeperEnabled = isGatekeeperConfigured()
  if (gatekeeperEnabled) {
    try {
      const scanCount = await getUserScanCount(userId)
      if (scanCount >= 3) {
        return new Response(
          JSON.stringify({ error: 'Scan limit reached (3). Access denied.' }),
          { status: 403, headers: { 'Content-Type': 'application/json' } },
        )
      }
    } catch (dbErr: any) {
      console.error('[gatekeeper] db error:', dbErr?.message ?? dbErr)
      return new Response(
        JSON.stringify({ error: 'Gatekeeper database unavailable' }),
        { status: 503, headers: { 'Content-Type': 'application/json' } },
      )
    }
  } else {
    console.warn('[gatekeeper] disabled: missing MySQL env vars')
  }

  const encoder = new TextEncoder()

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (data: object) =>
        controller.enqueue(encoder.encode(sse(data)))

      try {
        // ── Stage 1: extract ───────────────────────────────────────────────
        send({ stage: 'extract', status: 'running', message: 'Receiving file...' })

        const formData = await req.formData()
        const file = formData.get('file') as File | null

        if (!file) {
          send({ stage: 'error', status: 'error', message: 'No file uploaded' })
          controller.close()
          return
        }

        // FIX 5 — MIME type check (extension can be spoofed, MIME is harder)
        if (!ALLOWED_MIME_TYPES.has(file.type)) {
          send({
            stage: 'error', status: 'error',
            message: `File type "${file.type || 'unknown'}" is not allowed. Only PDF and plain text files are accepted.`,
          })
          controller.close()
          return
        }

        const buffer = Buffer.from(await file.arrayBuffer())

        // FIX 4 — File size check (must happen before any processing)
        if (buffer.length > MAX_FILE_BYTES) {
          send({
            stage: 'error', status: 'error',
            message: `File is too large (${(buffer.length / 1024 / 1024).toFixed(1)} MB). Maximum allowed size is 20 MB.`,
          })
          controller.close()
          return
        }

        send({
          stage:  'extract',
          status: 'done',
          message: `Extracted ${buffer.length.toLocaleString()} bytes`,
        })

        // ── Stage 2: threat scan ───────────────────────────────────────────
        send({ stage: 'scan', status: 'running', message: 'Analysing content...' })

        const scanResult = await analyzeFile(buffer, file.name)

        // AI PDF verification with Groq + Llama 3
        let aiAnalysis = ''
        const isPdf = file.name.toLowerCase().endsWith('.pdf')
        if (isPdf && process.env.GROQ_API_KEY) {
          try {
            const structuralSignals = scanResult.signals.filter((s: any) => s.type === 'structural')
            const extractedSnippet  = scanResult.extractedText.substring(0, 400)
            const hasJavaScriptTag  = structuralSignals.some(
              (s: any) => String(s?.detail ?? '').includes('/JavaScript') || String(s?.detail ?? '').includes('/JS'),
            )
            const hasOpenActionTag = structuralSignals.some((s: any) =>
              String(s?.detail ?? '').includes('/OpenAction'),
            )

            const completion = await groq.chat.completions.create({
              model:       'llama3-70b-8192',
              temperature: 0.2,
              messages: [
                {
                  role:    'system',
                  content: 'You are a PDF malware analyst. Reply in exactly two lines: line 1 is SAFE or MALICIOUS, line 2 is one short plain-English reason.',
                },
                {
                  role:    'user',
                  content: `Assess this uploaded PDF.

File: ${file.name}
Detected /JavaScript or /JS tag: ${hasJavaScriptTag ? 'yes' : 'no'}
Detected /OpenAction tag: ${hasOpenActionTag ? 'yes' : 'no'}
All structural indicators:
${JSON.stringify(structuralSignals, null, 2)}

Extracted text snippet:
${JSON.stringify(extractedSnippet)}`,
                },
              ],
            })

            aiAnalysis = completion.choices[0]?.message?.content?.trim() ?? ''

            console.log('\n==========================================')
            console.log('🤖 AI DETECTIVE REPORT:')
            console.log(aiAnalysis)
            console.log('==========================================\n')

          } catch (aiErr: any) {
            console.warn('[route] Groq call failed (non-fatal):', aiErr?.message ?? aiErr)
          }
        }

        send({
          stage:        'scan',
          status:       'done',
          message:      `${scanResult.signals.length} signal(s) detected`,
          score:        scanResult.score,
          riskLevel:    scanResult.riskLevel,
          signals:      scanResult.signals,
          elementCount: scanResult.elementCount,
          aiAnalysis,
        })

        // ── Stage 3: disarm ────────────────────────────────────────────────
        send({ stage: 'disarm', status: 'running', message: 'Neutralising threats...' })

        let safeText      = scanResult.extractedText
        let disarmedCount = 0

        for (const word of DISARM_KEYWORDS) {
          const before = safeText
          safeText = safeText.replace(escapeRegex(word), '[DISARMED]')
          if (safeText !== before) disarmedCount++
        }

        send({
          stage:   'disarm',
          status:  'done',
          message: `${disarmedCount} threat(s) neutralised`,
        })

        // ── Stage 4: reconstruct ───────────────────────────────────────────
        send({
          stage:   'reconstruct',
          status:  'running',
          message: 'Rebuilding clean document (text + images)...',
        })

        // Pass original buffer so reconstructor can extract, sanitise (EXIF
        // strip via sharp), and re-embed every image found in the source PDF.
        const cleanPdf  = await createSafePdf(safeText, file.name, buffer)
        const base64Pdf = cleanPdf.toString('base64')
        const safeName  = file.name.replace(/\.[^.]+$/, '')

        send({
          stage:   'reconstruct',
          status:  'done',
          message: `Reconstruction complete — ${(cleanPdf.length / 1024).toFixed(1)} KB`,
        })

        // ── Complete ───────────────────────────────────────────────────────
        send({
          stage:             'complete',
          status:            'done',
          filename:          `Safe_${safeName}.pdf`,
          score:             scanResult.score,
          riskLevel:         scanResult.riskLevel,
          signals:           scanResult.signals,
          aiAnalysis,
          reconstructedFile: `data:application/pdf;base64,${base64Pdf}`,
        })

        // Gatekeeper increment (only after successful full pipeline)
        if (gatekeeperEnabled) {
          try {
            await incrementUserScanCount(userId)
          } catch (dbErr: any) {
            // Non-fatal — scan succeeded, usage tracking failed
            console.warn('[gatekeeper] increment failed (non-fatal):', dbErr?.message ?? dbErr)
          }
        }

      } catch (err: any) {
        console.error('[route] pipeline crash:', err?.message, err?.stack)
        send({ stage: 'error', status: 'error', message: err?.message ?? 'Internal error' })
      } finally {
        controller.close()
      }
    },
  })

  return new Response(stream, {
    headers: {
      'Content-Type':     'text/event-stream',
      'Cache-Control':    'no-cache, no-transform',
      'Connection':       'keep-alive',
      'X-Accel-Buffering': 'no',
    },
  })
}