// lib/reconstructor.ts
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib'

const PAGE_W    = 595   // A4 points
const PAGE_H    = 842
const MARGIN    = 50
const MAX_W     = PAGE_W - MARGIN * 2
const LINE_H    = 16
const BODY_SIZE = 11
const HEAD_SIZE = 13
const SUB_SIZE  = 9

export async function createSafePdf(safeText: string, originalName: string): Promise<Buffer> {
  const pdfDoc  = await PDFDocument.create()
  const bold    = await pdfDoc.embedFont(StandardFonts.HelveticaBold)
  const regular = await pdfDoc.embedFont(StandardFonts.Helvetica)

  // ── page / cursor management ─────────────────────────────────────────────
  let page   = pdfDoc.addPage([PAGE_W, PAGE_H])
  let cursor = PAGE_H - MARGIN

  function newPage() {
    page   = pdfDoc.addPage([PAGE_W, PAGE_H])
    cursor = PAGE_H - MARGIN
  }

  // Sanitise a line: strip non-printable / non-ASCII that Helvetica can't encode
  function sanitise(s: string): string {
    return s.replace(/[^\x20-\x7E]/g, ' ').replace(/\s+/g, ' ').trim()
  }

  // Draw one line, starting a new page if needed
  function drawLine(
    raw:   string,
    font:  typeof bold,
    size:  number,
    color = rgb(0, 0, 0),
  ): void {
    const text = sanitise(raw)
    if (!text) return

    if (cursor - (size + 4) < MARGIN) newPage()

    cursor -= size + 4
    try {
      page.drawText(text, {
        x:        MARGIN,
        y:        cursor,
        size,
        font,
        color,
        maxWidth: MAX_W,
      })
    } catch {
      // skip unencodable line rather than crashing
    }
  }

  // Word-wrap a paragraph into lines that fit MAX_W
  function wrapParagraph(para: string, font: typeof bold, size: number): string[] {
    const words = sanitise(para).split(' ').filter(Boolean)
    if (words.length === 0) return []

    const lines: string[] = []
    let current = ''

    for (const word of words) {
      const candidate = current ? `${current} ${word}` : word
      let width = MAX_W + 1
      try { width = font.widthOfTextAtSize(candidate, size) } catch { /* ignore */ }

      if (width > MAX_W) {
        if (current) lines.push(current)
        current = word
      } else {
        current = candidate
      }
    }
    if (current) lines.push(current)
    return lines
  }

  // ── Header ───────────────────────────────────────────────────────────────
  drawLine('VERIFIED SAFE — ZERO-TRUST SENTINEL', bold, HEAD_SIZE, rgb(0.08, 0.72, 0.38))
  cursor -= 4

  drawLine(
    `Original file: ${originalName}  |  Active content disarmed`,
    regular, SUB_SIZE, rgb(0.39, 0.45, 0.55),
  )
  cursor -= LINE_H   // spacer before body

  // ── Guard: nothing to write ──────────────────────────────────────────────
  if (!safeText || safeText.trim().length === 0) {
    drawLine(
      '[No text content could be extracted from this file]',
      regular, BODY_SIZE, rgb(0.6, 0.6, 0.6),
    )
    const bytes = await pdfDoc.save()
    return Buffer.from(bytes)
  }

  // ── Body ─────────────────────────────────────────────────────────────────
  const paragraphs = safeText.split(/\r?\n/)

  for (const para of paragraphs) {
    if (!para.trim()) {
      cursor -= LINE_H * 0.6   // blank-line gap
      continue
    }

    for (const line of wrapParagraph(para, regular, BODY_SIZE)) {
      drawLine(line, regular, BODY_SIZE)
    }
  }

  const pdfBytes = await pdfDoc.save()
  console.log(`[reconstructor] produced ${pdfBytes.length} bytes for "${originalName}"`)
  return Buffer.from(pdfBytes)
}