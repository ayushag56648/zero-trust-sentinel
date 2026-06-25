# Zero-Trust Sentinel

> A web-based Content Disarm & Reconstruction (CDR) pipeline for PDF and text files — built with Next.js 15, TypeScript, and Groq/Llama3 AI.

![TypeScript](https://img.shields.io/badge/TypeScript-96%25-3178C6?style=flat-square&logo=typescript&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-16.2-black?style=flat-square&logo=next.js)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)

---

## What is this?

Zero-Trust Sentinel is a file security tool that treats **every uploaded document as untrusted by default** and runs it through a four-stage CDR pipeline before returning a clean, reconstructed version.

Enterprise CDR tools (Glasswall, Votiro, OPSWAT MetaDefender) do the same thing — but they cost thousands of dollars per year and require IT teams to deploy. This project implements the same core principles as an open-source web application anyone can run.

The key design decision: instead of trying to find and delete malicious content (sanitisation), the pipeline **never copies active content at all**. It extracts only what is known-safe — text characters and pixel values — and builds a brand new document from scratch. An attacker cannot hide in a pixel value.

---

## Live Pipeline Demo

```
Upload PDF
    │
    ▼
Stage 1 — Extract      Read raw bytes into buffer (23,496 bytes)
    │
    ▼
Stage 2 — AI Scan      5-layer threat analysis → Threat score: 100/100 Critical
    │                  • Structural binary scan  (/JavaScript, /OpenAction, /Launch)
    │                  • Keyword detection       (cmd.exe, powershell, eval()
    │                  • Entropy analysis        (base64-encoded payloads)
    │                  • URL analysis            (typosquats, IP URLs, bad TLDs)
    │                  • Pattern detection       (phishing language, credential leaks)
    │                  • AI verdict              (Groq Llama3-70B)
    │
    ▼
Stage 3 — Disarm       Neutralise threat keywords in text layer
    │
    ▼
Stage 4 — Reconstruct  Poppler renders every page to PNG at 150 DPI
                       sharp strips EXIF / XMP / metadata from each image
                       pdf-lib wraps clean images into a new PDF
                       → Download Safe_document.pdf (236.9 KB)
```

---

## Features

**Five-layer threat scanner**

- Structural binary scan — detects `/JavaScript`, `/OpenAction`, `/Launch`, `/AA`, `/EmbeddedFiles`, `/XFA`, `/SubmitForm` and 10 more dangerous PDF object tags directly in the raw binary
- Hex-obfuscation normaliser — decodes `#XX` sequences before scanning so `/J#61vaScript` is not missed
- Magic byte validation — checks actual file header bytes (MZ, ELF, PK, OLE2) not just extension
- Encrypted PDF detection — flags encrypted files that would otherwise score as clean
- Shannon entropy analysis — detects base64-encoded or encrypted payloads (entropy > 5.2)

**AI-augmented verdict**

- Sends structural signals and extracted text to Groq Llama3-70B
- Returns a plain-English SAFE / MALICIOUS verdict with reason
- Non-fatal — pipeline continues even if the Groq API is unavailable

**Method A CDR Reconstruction (Poppler rasterisation)**

- Poppler renders each page as a high-resolution PNG — pixel-perfect output preserving tables, fonts, Unicode, dark-themed code blocks, mathematical notation
- sharp re-encodes every rendered image from pixel data only — EXIF, XMP, ICC profiles, and steganographic comment blocks are never written to output
- pdf-lib wraps clean images into a new PDF with sanitised metadata
- The output PDF is structurally known — it contains only image XObjects, zero active content objects
- Text remains visually accurate but is not selectable by design (this is the security guarantee)

**Gatekeeper (scan quota)**

- MySQL-backed per-user scan limiting (3 scans per user ID)
- UUID assigned per browser session via localStorage
- Gracefully disabled when MySQL env vars are not configured

**Real-time streaming UI**

- Server-Sent Events (SSE) stream each pipeline stage as it completes
- Progress bar advances only on real backend confirmations, not timers
- Per-stage status indicators (waiting / running / done / error)
- Threat signal list with severity colour coding
- One-click download of reconstructed file

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | Next.js 15 (App Router, Turbopack) |
| Language | TypeScript |
| Styling | Tailwind CSS v4, shadcn/ui, Radix UI |
| PDF scanning | pdf-parse (text extraction) |
| PDF reconstruction | pdf-lib, Poppler (pdftoppm) |
| Image sanitisation | sharp |
| AI analysis | Groq SDK — Llama3-70B-8192 |
| Streaming | Server-Sent Events (ReadableStream) |
| Database | MySQL (via mysql2) — optional |
| State management | React Context |

---

## Project Structure

```
zero-trust-sentinel/
├── app/
│   ├── api/
│   │   └── scan/
│   │       └── route.ts        ← SSE streaming pipeline endpoint
│   ├── layout.tsx
│   └── page.tsx
├── components/
│   └── dashboard/
│       ├── file-upload-zone.tsx   ← Upload UI + SSE consumer
│       ├── live-pipeline-panel.tsx
│       ├── audit-logs-table.tsx
│       └── stats-header.tsx
├── lib/
│   ├── scanner.ts              ← 5-layer threat scanner
│   ├── reconstructor.ts        ← CDR pipeline (Poppler + sharp + pdf-lib)
│   └── mysql.ts                ← Gatekeeper quota system
├── context/
│   └── scan-context.tsx        ← Global pipeline state
└── hooks/
```

---

## Getting Started

### Prerequisites

- Node.js 18+
- Poppler (for PDF rasterisation)

```bash
# Windows (run PowerShell as Admin)
choco install poppler

# Linux
sudo apt install poppler-utils

# macOS
brew install poppler
```

### Installation

```bash
git clone https://github.com/ayushag56648/zero-trust-sentinel
cd zero-trust-sentinel
npm install
```

### Environment Variables

Create a `.env.local` file:

```env
# Required for AI analysis
GROQ_API_KEY=your_groq_api_key_here

# Optional — enables per-user scan quota
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your_password
MYSQL_DATABASE=zts_db
```

Get a free Groq API key at [console.groq.com](https://console.groq.com).

If MySQL env vars are not set, the gatekeeper is automatically disabled and all scans are allowed.

### Run

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

---

## How the CDR Works

**Why reconstruction instead of sanitisation?**

Sanitisation searches for known threats and deletes them. The problem: an attacker who knows your scanner's rules can evade them — `/OpenAction` becomes `/Op#65nAction`, or JavaScript is buried inside a compressed `/ObjStm` object your string-match never sees.

Reconstruction inverts the problem. Instead of finding everything bad, you extract only what is provably safe — visible text and rendered pixel values — and build a new document containing only those. You cannot miss a threat you never copied.

**The rasterisation approach (Method A)**

Poppler is the same rendering engine used inside Firefox and Chrome. It renders each page exactly as a PDF viewer would, producing a high-resolution PNG. That PNG goes through sharp for metadata stripping, then pdf-lib embeds it in a new document. The new PDF structurally cannot contain `/JavaScript` or any other active object because pdf-lib never wrote one.

**What this removes unconditionally**

Every threat that lives in the PDF object tree is gone — `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFiles`, `/AcroForm`, `/XFA`, `/RichMedia`, obfuscated variants, embedded executables, form submission actions. None of these survive because the output PDF was built from scratch and none were written into it.

---

## Security Gaps (Known Limitations)

This is an academic/portfolio project. Known limitations compared to enterprise CDR:

- **Steganography in pixel data** — data hidden inside pixel colour values survives rasterisation (requires statistical pixel analysis to detect)
- **Encrypted PDFs** — scanner flags them but Poppler may refuse to render; output falls back to text-only
- **Zero-day Poppler exploits** — a PDF crafted to exploit the renderer itself (extremely rare, but theoretically possible)
- **Image-only phishing PDFs** — no text layer means keyword scanner finds nothing; only structural signals apply

---

## Roadmap

- [ ] Deploy live demo (Vercel + PlanetScale)
- [ ] Add OCR on reconstructed pages (Tesseract) to restore text selectability
- [ ] Steganography detection via pixel entropy analysis
- [ ] DOCX and XLSX CDR support
- [ ] Scan history dashboard with audit log export

---

## Author

**Ayush Anand George**
2nd Year B.Tech Computer Science (Cybersecurity) — SRM Institute of Science and Technology

[GitHub](https://github.com/ayushag56648) · [LinkedIn](https://linkedin.com/in/ayushanandgeorge)

---

## License

MIT
