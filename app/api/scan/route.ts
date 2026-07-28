import { NextRequest } from 'next/server';
import { analyzeFile } from '@/lib/scanner';
import { createSafePdf } from '@/lib/reconstructor';
import Groq from 'groq-sdk';

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY ?? '' });

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

// ── Helper Function: Check URLs against Google Safe Browsing API ──
async function checkUrlsWithGoogle(urls: string[]): Promise<{ url: string; isMalicious: boolean }[]> {
  if (urls.length === 0) return [];

  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  // If no Google API key is provided, return links as clean by default
  if (!apiKey) {
    return urls.map(url => ({ url, isMalicious: false }));
  }

  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

  const body = {
    client: { clientId: 'zero-trust-sentinel', clientVersion: '1.0.0' },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: urls.map(url => ({ url })),
    },
  };

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    const data = await res.json();
    const matches = data.matches || [];

    return urls.map(url => ({
      url,
      isMalicious: matches.some((m: any) => m.threat.url === url),
    }));
  } catch (err) {
    console.warn('[google-safe-browsing] API check failed:', err);
    return urls.map(url => ({ url, isMalicious: false }));
  }
}

export async function POST(req: NextRequest) {
  console.log(process.env.GROQ_API_KEY ? 'Groq API Key Found' : 'Groq API Key Missing');


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

        let aiAnalysis = '';
        const isPdf = file.name.toLowerCase().endsWith('.pdf');

        if (isPdf && process.env.GROQ_API_KEY) {
          try {
            const structuralSignals = scanResult.signals.filter((s: any) => s.type === 'structural');

            // 1. Extract raw URLs found by the scanner
            const extractedUrls: string[] = scanResult.signals
              .filter((s: any) => s.type === 'url' || String(s?.detail ?? '').startsWith('http'))
              .map((s: any) => s.detail || s.value);

            // 2. Perform live check against threat database
            const verifiedLinks = await checkUrlsWithGoogle(extractedUrls);
            const maliciousLinks = verifiedLinks.filter(l => l.isMalicious).map(l => l.url);
            const safeLinks = verifiedLinks.filter(l => !l.isMalicious).map(l => l.url);

            // 3. Structural Threat Flags
            const hasJavaScriptTag = structuralSignals.some(
              (s: any) => String(s?.detail ?? '').includes('/JavaScript') || String(s?.detail ?? '').includes('/JS'),
            );
            const hasOpenActionTag = structuralSignals.some((s: any) =>
              String(s?.detail ?? '').includes('/OpenAction'),
            );

            // 4. Generate Pinpointed AI Summary with Llama 3
            const completion = await groq.chat.completions.create({
              model: 'llama-3.1-8b-instant',
              temperature: 0.1,
              messages: [
                {
                  role: 'system',
                  content: `You are a helpful document security assistant. Explain document findings in simple, everyday English to non-technical users.

STRICT RULES:
1. Never use technical jargon like "Object Stream", "heuristics", "entropy", or "obfuscation".
2. Line 1: Must strictly be either "SAFE" or "WARNING".
3. Line 2: Pinpoint EXACTLY what was found in 1-2 plain English sentences.
   - If links are present, explicitly state whether they were verified as safe professional links (like LinkedIn/GitHub) or flagged as malicious.
   - If auto-run scripts exist, state that a hidden script was removed.`,
                },
                {
                  role: 'user',
                  content: `Analyze these exact scan results for "${file.name}":

- Verified Dangerous Links: ${JSON.stringify(maliciousLinks)}
- Verified Safe Links: ${JSON.stringify(safeLinks)}
- Contains Auto-Run Scripts (/JavaScript or /JS): ${hasJavaScriptTag ? 'YES' : 'NO'}
- Contains Auto-Open Triggers (/OpenAction): ${hasOpenActionTag ? 'YES' : 'NO'}

Write a pinpointed 2-line summary:`,
                },
              ],
            });

            aiAnalysis = completion.choices[0]?.message?.content?.trim() ?? '';

            console.log("\n==========================================");
            console.log("🤖 AI DETECTIVE REPORT:");
            console.log(aiAnalysis);
            console.log("==========================================\n");

          } catch (aiErr: any) {
            console.warn('[route] Groq call failed (non-fatal):', aiErr?.message ?? aiErr);
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
        send({
          stage: 'reconstruct',
          status: 'running',
          message: 'Rebuilding clean document (text + images)...',
        });

        const cleanPdf = await createSafePdf(safeText, file.name, buffer);
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