import { NextRequest } from 'next/server';
import { analyzeFile } from '@/lib/scanner';
import { createSafePdf } from '@/lib/reconstructor';
import { GoogleGenerativeAI } from '@google/generative-ai';

// ── Gemini setup ─────────────────────────────────────────────────────────────
// Using gemini-1.5-flash for the fastest real-time performance.
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY ?? '');
const gemini = genAI.getGenerativeModel({ model: 'gemini-2.5-flash' })
function escapeRegex(str: string): RegExp {
  return new RegExp(str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
}

function sse(data: object): string {
  return `data: ${JSON.stringify(data)}\n\n`;
}

const DISARM_KEYWORDS = [
  'javascript:', 'vbscript:', 'cmd.exe', 'powershell', 'eval(',
  'base64_decode', 'document.cookie', 'window.location', '<script',
  'onerror=', 'onload=', 'shell_exec', 'exec(', 'system(',
  '/etc/passwd', 'net user', 'reg add', 'certutil', 'mshta',
  'wscript', '-ExecutionPolicy',
];

export async function POST(req: NextRequest) {
  const encoder = new TextEncoder();

const stream = new ReadableStream<Uint8Array>({
      async start(controller) {
      const send = (data: object) =>
        controller.enqueue(encoder.encode(sse(data)));

      try {
        // ── Stage 1: extract ─────────────────────────────────────────────
        send({ stage: 'extract', status: 'running', message: 'Receiving file...' });

        const formData = await req.formData();
        const file = formData.get('file') as File | null;

        if (!file) {
          send({ stage: 'error', status: 'error', message: 'No file uploaded' });
          controller.close();
          return;
        }

        const buffer = Buffer.from(await file.arrayBuffer());

        send({
          stage: 'extract',
          status: 'done',
          message: `Extracted ${buffer.length.toLocaleString()} bytes`,
        });

        // ── Stage 2: threat scan ─────────────────────────────────────────
        send({ stage: 'scan', status: 'running', message: 'Analysing content...' });

        const scanResult = await analyzeFile(buffer, file.name);

        // AI intent analysis (only when signals exist and key is configured)
        let aiAnalysis = '';
        if (scanResult.signals.length > 0 && process.env.GEMINI_API_KEY) {
          try {
            const prompt = `
              You are an elite SOC analyst in a Zero-Trust CDR pipeline.
              File: "${file.name}"
              Threat signals detected:
              ${JSON.stringify(scanResult.signals, null, 2)}
              Extracted text snippet: "${scanResult.extractedText.substring(0, 300)}"

              In exactly ONE short sentence, explain what the attacker is trying to do with this file and why it is dangerous. Use plain language — no technical jargon like "entropy" or "/Launch".`;

            const result = await gemini.generateContent(prompt);
            aiAnalysis = result.response.text().trim();

            // LOG TO TERMINAL FOR BACKEND VERIFICATION
            console.log("\n==========================================");
            console.log("🤖 AI DETECTIVE REPORT:");
            console.log(aiAnalysis);
            console.log("==========================================\n");

          } catch (aiErr: any) {
            console.warn('[route] Gemini call failed (non-fatal):', aiErr?.message ?? aiErr);
          }
        }

        send({
          stage: 'scan',
          status: 'done',
          message: `${scanResult.signals.length} signal(s) detected`,
          score: scanResult.score,
          riskLevel: scanResult.riskLevel,
          signals: scanResult.signals,
          elementCount: scanResult.elementCount,
          aiAnalysis,
        });

        // ── Stage 3: disarm ──────────────────────────────────────────────
        send({ stage: 'disarm', status: 'running', message: 'Neutralising threats...' });

        let safeText = scanResult.extractedText;
        let disarmedCount = 0;

        for (const word of DISARM_KEYWORDS) {
          const before = safeText;
          safeText = safeText.replace(escapeRegex(word), '[DISARMED]');
          if (safeText !== before) disarmedCount++;
        }

        send({
          stage: 'disarm',
          status: 'done',
          message: `${disarmedCount} threat(s) neutralised`,
        });

        // ── Stage 4: reconstruct ─────────────────────────────────────────
        send({ stage: 'reconstruct', status: 'running', message: 'Rebuilding clean document...' });

        const cleanPdf = await createSafePdf(safeText, file.name);
        const base64Pdf = cleanPdf.toString('base64');
        const safeName = file.name.replace(/\.[^.]+$/, '');

        send({
          stage: 'reconstruct',
          status: 'done',
          message: `Reconstruction complete — ${(cleanPdf.length / 1024).toFixed(1)} KB`,
        });

        // ── Complete ─────────────────────────────────────────────────────
        send({
          stage: 'complete',
          status: 'done',
          filename: `Safe_${safeName}.pdf`,
          score: scanResult.score,
          riskLevel: scanResult.riskLevel,
          signals: scanResult.signals,
          aiAnalysis,
          reconstructedFile: `data:application/pdf;base64,${base64Pdf}`,
        });

      } catch (err: any) {
        console.error('[route] pipeline crash:', err?.message, err?.stack);
        send({ stage: 'error', status: 'error', message: err?.message ?? 'Internal error' });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    },
  });
}