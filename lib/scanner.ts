if (typeof global.DOMMatrix === 'undefined') {
  // @ts-ignore
  global.DOMMatrix = class DOMMatrix {};
}

// Import directly to bypass the Next.js self-test crash
const pdf = require('pdf-parse/lib/pdf-parse.js');

export interface ScanResult {
  score: number;
  threats: string[];
  extractedText: string;
  signals: Array<{ severity: string; detail: string }>;
}

export async function analyzeFile(buffer: Buffer, filename: string): Promise<ScanResult> {
  let text = "";
  
  if (filename.endsWith('.pdf')) {
    try {
      // 1. We removed the "options" override so the default text extractor runs normally!
      const data = await pdf(buffer);
      text = data.text;
      
      // Fallback check: If the PDF is strictly image-based with no text
      if (!text || text.trim() === "") {
        text = "[ZERO-TRUST SYSTEM NOTICE: No readable text could be extracted. This file may be an image-based PDF or corrupted.]\n\n";
      }
    } catch (err) {
      console.error("PDF extraction failed:", err);
      text = "Error: Text extraction failed.";
    }
  } else {
    // Handles .txt and other plain text formats
    text = buffer.toString('utf-8');
  }

  // --- AI Threat Analysis ---
  const threats: string[] = [];
  const signals: Array<{ severity: string; detail: string }> = [];
  let score = 0;
  
  const maliciousKeywords = ['javascript:', 'cmd.exe', 'powershell', 'eval(', 'base64_decode'];
  
  maliciousKeywords.forEach(word => {
    if (text.toLowerCase().includes(word)) {
      threats.push(`Found: ${word}`);
      // Add the signal so your new LivePipelinePanel lights up with the exact threat
      signals.push({ 
        severity: 'high', 
        detail: `Suspicious active content detected: ${word}` 
      });
      score += 20;
    }
  });

  return { 
    score: Math.min(score, 100), 
    threats, 
    extractedText: text,
    signals
  };
}