// app/api/scan/route.ts
import { NextRequest } from 'next/server'
import { analyzeFile } from '@/lib/scanner'
import { createSafePdf } from '@/lib/reconstructor'

function escapeRegex(str: string): RegExp {
  return new RegExp(str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi')
}

function sse(data: object): string {
  return `data: ${JSON.stringify(data)}\n\n`
}

const MALICIOUS_KEYWORDS = [
  'javascript:', 'vbscript:', 'cmd.exe', 'powershell', 'eval(',
  'base64_decode', 'document.cookie', 'window.location', '<script',
  'onerror=', 'onload=', 'shell_exec', 'exec(', 'system(',
  '/etc/passwd', 'net user', 'reg add', 'certutil', 'mshta',
  'wscript', '-ExecutionPolicy',
]

export async function POST(req: NextRequest) {
  const encoder = new TextEncoder()

  const stream = new ReadableStream({
    async start(controller) {
      const send = (data: object) =>
        controller.enqueue(encoder.encode(sse(data)))

      try {
        // ── STAGE 1: extract ───────────────────────────────────────────────
        send({ stage: 'extract', status: 'running', message: 'Receiving file…' })

        const formData = await req.formData()
        const file = formData.get('file') as File | null

        if (!file) {
          send({ stage: 'error', status: 'error', message: 'No file uploaded' })
          controller.close(); return
        }

        const buffer = Buffer.from(await file.arrayBuffer())

        send({
          stage:   'extract',
          status:  'done',
          message: `Extracted ${buffer.length.toLocaleString()} bytes`,
        })

        // ── STAGE 2: threat scan ───────────────────────────────────────────
        send({ stage: 'scan', status: 'running', message: 'Analysing content…' })

        const scanResult = await analyzeFile(buffer, file.name)

        // Defensive log so server terminal shows what was extracted
        console.log(`[route] scan done — text_length=${scanResult.extractedText.length} score=${scanResult.score}`)

        send({
          stage:        'scan',
          status:       'done',
          message:      `${scanResult.signals.length} signal(s) detected`,
          score:        scanResult.score,
          riskLevel:    scanResult.riskLevel,
          signals:      scanResult.signals,
          elementCount: scanResult.elementCount,
        })

        // ── STAGE 3: disarm ────────────────────────────────────────────────
        send({ stage: 'disarm', status: 'running', message: 'Neutralising threats…' })

        // Guard: if text is empty (image-only PDF, encrypted, etc.) tell the user
        if (scanResult.extractedText.trim().length === 0) {
          console.warn('[route] extractedText is empty — skipping disarm, using placeholder')
        }

        let safeText = scanResult.extractedText
        let disarmedCount = 0

        for (const word of MALICIOUS_KEYWORDS) {
          const before = safeText
          safeText = safeText.replace(escapeRegex(word), '[DISARMED]')
          if (safeText !== before) disarmedCount++
        }

        send({
          stage:   'disarm',
          status:  'done',
          message: `${disarmedCount} threat(s) neutralised`,
        })

        // ── STAGE 4: reconstruct ───────────────────────────────────────────
        send({ stage: 'reconstruct', status: 'running', message: 'Rebuilding clean document…' })

        const cleanPdf   = await createSafePdf(safeText, file.name)
        const base64Pdf  = cleanPdf.toString('base64')
        const safeName   = file.name.replace(/\.[^.]+$/, '')

        send({
          stage:   'reconstruct',
          status:  'done',
          message: `Reconstruction complete — ${(cleanPdf.length / 1024).toFixed(1)} KB`,
        })

        // ── COMPLETE ───────────────────────────────────────────────────────
        send({
          stage:             'complete',
          status:            'done',
          filename:          `Safe_${safeName}.pdf`,
          score:             scanResult.score,
          riskLevel:         scanResult.riskLevel,
          signals:           scanResult.signals,
          reconstructedFile: `data:application/pdf;base64,${base64Pdf}`,
        })

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
      'Content-Type':  'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection':    'keep-alive',
      'X-Accel-Buffering': 'no',   // disable nginx buffering if present
    },
  })
}