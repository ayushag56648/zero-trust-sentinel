import { PDFDocument } from 'pdf-lib';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFile, readFile, unlink, readdir } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

const execAsync = promisify(exec);

/**
 * Main CDR entry-point called by the route.
 * Flattens the original PDF into HIGH-QUALITY safe images using Poppler (pdftocairo),
 * eliminating active threats while keeping text and layout razor-sharp.
 */
export async function createSafePdf(
  safeText: string,
  originalName: string,
  originalBuffer?: Buffer,
): Promise<Buffer> {
  if (!originalBuffer) {
    throw new Error("Original buffer is required for rasterization.");
  }

  const tmpDir = os.tmpdir();
  const uniqueId = `zts_cdr_${Date.now()}_${Math.random().toString(36).substring(7)}`;
  const inputPdfPath = path.join(tmpDir, `${uniqueId}.pdf`);
  const outputPrefix = path.join(tmpDir, uniqueId);

  // Write the untrusted buffer to a temp file for Poppler processing
  await writeFile(inputPdfPath, originalBuffer);

  try {
    // ── High-Quality Poppler Rasterization Settings ───────────────────────
    // -jpeg: Outputs JPEG format
    // -r 300: High Resolution (300 DPI) for crystal-clear text rendering
    // -jpegopt quality=95: Minimal compression artifacts
    await execAsync(`pdftocairo -jpeg -jpegopt quality=95 -r 300 "${inputPdfPath}" "${outputPrefix}"`);

    // Retrieve and sort generated page images
    const files = await readdir(tmpDir);
    const imageFiles = files
      .filter(f => f.startsWith(uniqueId) && f.endsWith('.jpg'))
      .sort((a, b) => {
        const numA = parseInt(a.match(/-(\d+)\.jpg$/)?.[1] || '0', 10);
        const numB = parseInt(b.match(/-(\d+)\.jpg$/)?.[1] || '0', 10);
        return numA - numB;
      });

    if (imageFiles.length === 0) {
      throw new Error("Poppler failed to render images. Ensure poppler_utils is installed in dev.nix.");
    }

    // Initialize fresh, safe output PDF
    const outDoc = await PDFDocument.create();

    // Reconstruct the PDF page-by-page while scaling dimensions back to standard 72 DPI PDF points
    for (const imgFile of imageFiles) {
      const imgPath = path.join(tmpDir, imgFile);
      const imgBytes = await readFile(imgPath);

      const image = await outDoc.embedJpg(imgBytes);

      // Convert 300 DPI image pixels back to standard PDF points (1 pt = 1/72 inch)
      // This prevents the PDF page size from becoming physically massive
      const pdfWidth = (image.width / 300) * 72;
      const pdfHeight = (image.height / 300) * 72;

      const page = outDoc.addPage([pdfWidth, pdfHeight]);

      page.drawImage(image, {
        x: 0,
        y: 0,
        width: pdfWidth,
        height: pdfHeight,
      });

      // Clean up individual temp images
      await unlink(imgPath).catch(() => { });
    }

    // Set clean metadata
    outDoc.setTitle(`Safe_${originalName}`);
    outDoc.setAuthor('Zero-Trust Sentinel CDR');
    outDoc.setSubject('Reconstructed document — all active content removed');
    outDoc.setProducer('ZTS-CDR v2');
    outDoc.setCreator('ZTS-CDR v2');

    const pdfBytes = await outDoc.save();
    return Buffer.from(pdfBytes);

  } finally {
    // Clean up temporary original PDF file
    await unlink(inputPdfPath).catch(() => { });
  }
}