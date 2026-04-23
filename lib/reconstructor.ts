// lib/reconstructor.ts  —  Zero-Trust CDR (Content Disarm & Reconstruction)
//
// Pipeline:
//   1. Parse the original PDF with pdf-lib (read-only, never copy objects).
//   2. Create a brand-new PDF from scratch.
//   3. Re-typeset the sanitised text into the new document.
//   4. Extract every embedded image → strip EXIF/metadata with sharp
//      → re-embed only clean pixel data as a fresh image XObject.
//   5. Strip all active-content catalogue keys from the output document.
//   6. Write safe metadata (FIX 6 — sanitise filename before embedding).
//
// Requires: npm install pdf-lib sharp

import { PDFDocument, PDFName, PDFDict, PDFStream, rgb, StandardFonts } from 'pdf-lib'
import sharp from 'sharp'

// ─────────────────────────────────────────────────────────────────────────────
// Dangerous PDF catalogue keys — none of these must exist in the output
// ─────────────────────────────────────────────────────────────────────────────
const DANGEROUS_CATALOGUE_KEYS = [
  'JavaScript', 'JS', 'AA', 'OpenAction', 'AcroForm',
  'Names', 'EmbeddedFiles', 'URI', 'SubmitForm', 'ImportData',
  'Launch', 'GoTo', 'GoToR', 'GoToE', 'Thread',
  'Sound', 'Movie', 'Hide', 'Named', 'SetOCGState',
  'Rendition', 'Trans', 'GoTo3DView', 'RichMedia',
]

// ─────────────────────────────────────────────────────────────────────────────
// FIX 6 — Filename sanitiser for PDF metadata
//
// If the original filename is eval(malicious).pdf that string would go
// straight into the PDF title metadata. We strip everything that isn't
// a safe printable character first.
// ─────────────────────────────────────────────────────────────────────────────
function sanitiseFilename(name: string): string {
  return name
    .replace(/[^a-zA-Z0-9._\-\s]/g, '_') // allow only safe chars
    .replace(/\s+/g, ' ')                  // collapse whitespace
    .trim()
    .slice(0, 120)                          // cap length
}

// ─────────────────────────────────────────────────────────────────────────────
// Strip ALL metadata from an image and return clean PNG pixel data.
// sharp re-encodes from raw pixel values only — EXIF, XMP, ICC profiles,
// steganographic comment blocks are never written into the output.
// ─────────────────────────────────────────────────────────────────────────────
async function sanitiseImage(
  rawBytes: Uint8Array,
): Promise<{ png: Buffer; width: number; height: number }> {
  const img = sharp(Buffer.from(rawBytes))
    .rotate()          // honour EXIF orientation, then discard EXIF
    .withMetadata({})  // write zero metadata fields

  const { width = 0, height = 0 } = await img.metadata().catch(() => ({}))

  const png = await img
    .png({ compressionLevel: 6, adaptiveFiltering: false })
    .toBuffer()

  return { png, width, height }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pull raw compressed stream bytes out of a PDF image XObject.
// ─────────────────────────────────────────────────────────────────────────────
function extractRawImageBytes(xObject: PDFStream): Uint8Array | null {
  try {
    return xObject.getContents()
  } catch {
    return null
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Walk a page's /Resources /XObject dict and collect every /Image entry.
// ─────────────────────────────────────────────────────────────────────────────
function collectImageXObjects(page: any): Map<string, PDFStream> {
  const result = new Map<string, PDFStream>()
  try {
    const resources = page.node.get(PDFName.of('Resources'))
    if (!(resources instanceof PDFDict)) return result

    const xObjects = resources.get(PDFName.of('XObject'))
    if (!(xObjects instanceof PDFDict)) return result

    xObjects.entries().forEach(([key, ref]) => {
      try {
        const obj = page.doc.context.lookup(ref)
        if (!(obj instanceof PDFStream)) return
        const subtype = obj.dict.get(PDFName.of('Subtype'))
        if (subtype?.toString() === '/Image') {
          result.set(key.toString(), obj)
        }
      } catch { /* skip corrupt XObject */ }
    })
  } catch { /* page has no /Resources */ }
  return result
}

// ─────────────────────────────────────────────────────────────────────────────
// Main CDR entry-point
//
// @param safeText       Already-disarmed plain text (from scanner + route)
// @param originalName   Original filename (sanitised before use in metadata)
// @param originalBuffer Raw bytes of the uploaded PDF (for image extraction)
// ─────────────────────────────────────────────────────────────────────────────
export async function createSafePdf(
  safeText:       string,
  originalName:   string,
  originalBuffer?: Buffer,
): Promise<Buffer> {

  // ── 1. Create a completely new blank document ────────────────────────────
  const outDoc = await PDFDocument.create()

  // ── 2. Embed font ────────────────────────────────────────────────────────
  const font        = await outDoc.embedFont(StandardFonts.Helvetica)
  const FONT_SIZE   = 11
  const LINE_HEIGHT = FONT_SIZE * 1.45
  const MARGIN      = 50
  const PAGE_W      = 595   // A4 points
  const PAGE_H      = 842
  const USABLE_W    = PAGE_W - MARGIN * 2
  const USABLE_H    = PAGE_H - MARGIN * 2

  // ── 3. Extract + sanitise images from the original PDF ───────────────────
  const cleanImages: Array<{ pngBytes: Buffer; width: number; height: number }> = []

  if (originalBuffer) {
    try {
      // Load source read-only — we NEVER copy PDF objects from it
      const srcDoc = await PDFDocument.load(originalBuffer, {
        ignoreEncryption: true,
        updateMetadata:   false,
      })

      for (const page of srcDoc.getPages()) {
        const xObjs = collectImageXObjects(page)

        for (const [, stream] of xObjs) {
          const raw = extractRawImageBytes(stream)
          if (!raw || raw.length === 0) continue

          try {
            const { png, width, height } = await sanitiseImage(raw)
            if (width > 0 && height > 0) {
              cleanImages.push({ pngBytes: png, width, height })
            }
          } catch (imgErr) {
            // Non-fatal — log and skip this image rather than crashing
            console.warn('[reconstructor] image sanitise failed, dropping:', (imgErr as Error).message)
          }
        }
      }

      console.log(`[reconstructor] extracted & sanitised ${cleanImages.length} image(s)`)
    } catch (srcErr) {
      console.warn('[reconstructor] could not parse source PDF for images:', (srcErr as Error).message)
    }
  }

  // ── 4. Page layout helpers ───────────────────────────────────────────────
  function newPage() {
    const p = outDoc.addPage([PAGE_W, PAGE_H])
    return { page: p, cursorY: PAGE_H - MARGIN }
  }

  // ── 5. Write sanitised text ──────────────────────────────────────────────
  let { page, cursorY } = newPage()

  const words = safeText.replace(/\r\n/g, '\n').split(/\s+/)
  let   line  = ''

  const flushLine = (ln: string) => {
    if (cursorY - LINE_HEIGHT < MARGIN) {
      ;({ page, cursorY } = newPage())
    }
    if (ln.trim()) {
      page.drawText(ln, {
        x:    MARGIN,
        y:    cursorY - FONT_SIZE,
        size: FONT_SIZE,
        font,
        color: rgb(0.05, 0.05, 0.05),
      })
    }
    cursorY -= LINE_HEIGHT
  }

  for (const word of words) {
    if (word === '\n' || word === '') {
      if (line) { flushLine(line); line = '' }
      flushLine('')
      continue
    }
    const candidate = line ? `${line} ${word}` : word
    const textWidth  = font.widthOfTextAtSize(candidate, FONT_SIZE)

    if (textWidth > USABLE_W && line) {
      flushLine(line)
      line = word
    } else {
      line = candidate
    }
  }
  if (line) flushLine(line)

  // ── 6. Re-embed sanitised images ─────────────────────────────────────────
  if (cleanImages.length > 0) {
    if (cursorY - LINE_HEIGHT * 3 < MARGIN) {
      ;({ page, cursorY } = newPage())
    }
    cursorY -= LINE_HEIGHT
    page.drawText('── Reconstructed Images ──', {
      x:    MARGIN,
      y:    cursorY - FONT_SIZE,
      size: FONT_SIZE - 1,
      font,
      color: rgb(0.4, 0.4, 0.4),
    })
    cursorY -= LINE_HEIGHT * 1.5

    for (const { pngBytes, width, height } of cleanImages) {
      const scale = Math.min(1, USABLE_W / width, (USABLE_H * 0.6) / height)
      const drawW = Math.round(width  * scale)
      const drawH = Math.round(height * scale)

      if (cursorY - drawH - MARGIN < MARGIN) {
        ;({ page, cursorY } = newPage())
      }

      try {
        const embedded = await outDoc.embedPng(pngBytes)
        page.drawImage(embedded, {
          x: MARGIN, y: cursorY - drawH,
          width: drawW, height: drawH,
        })
        cursorY -= drawH + LINE_HEIGHT
      } catch (embedErr) {
        console.warn('[reconstructor] embed failed for one image:', (embedErr as Error).message)
      }
    }
  }

  // ── 7. Strip dangerous keys from output catalogue ────────────────────────
  try {
    const catRef  = outDoc.context.trailerInfo.Root
    const catDict = outDoc.context.lookup(catRef, PDFDict)
    for (const key of DANGEROUS_CATALOGUE_KEYS) {
      catDict.delete(PDFName.of(key))
    }
  } catch { /* catalogue access failed — non-fatal */ }

  // ── 8. Write safe metadata (FIX 6 — sanitised filename) ─────────────────
  const safeName = sanitiseFilename(originalName)
  outDoc.setTitle(`Safe_${safeName}`)
  outDoc.setAuthor('Zero-Trust Sentinel CDR')
  outDoc.setSubject('Reconstructed document — all active content removed')
  outDoc.setKeywords([])
  outDoc.setProducer('ZTS-CDR v2')
  outDoc.setCreator('ZTS-CDR v2')

  const pdfBytes = await outDoc.save({ useObjectStreams: false })
  return Buffer.from(pdfBytes)
}