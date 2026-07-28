"use client"
import Link from "next/link"
import { ShieldCheck, FileSearch, Brain, ShieldOff, RefreshCw, Github, Linkedin } from "lucide-react"
import { InteractivePdfDisarm } from "@/components/interactive-pdf-disarm"

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-[#080809] text-[#f4f4f5] selection:bg-[#5b5fcf]/30">
      
      {/* NAVBAR */}
      <nav className="fixed top-0 left-0 right-0 z-50 h-[56px] bg-[rgba(8,8,9,0.8)] backdrop-blur-md border-b border-[#1f1f23]">
        <div className="container mx-auto h-full px-6 flex items-center justify-between max-w-7xl">
          
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-[#5b5fcf]" />
            <span className="text-[14px] font-[500] tracking-[-0.01em] text-[#f4f4f5]">Zero Trust Sentinel</span>
          </div>

          <div className="hidden md:flex items-center gap-8 text-[13px] text-[#71717a]">
            <Link href="#how-it-works" className="hover:text-[#f4f4f5] transition-colors duration-150">How it works</Link>
            <Link href="#features" className="hover:text-[#f4f4f5] transition-colors duration-150">Features</Link>
            <Link href="/dashboard" className="hover:text-[#f4f4f5] transition-colors duration-150">Dashboard</Link>
          </div>

          <div>
            <Link href="/dashboard" className="bg-[#5b5fcf] text-white text-[13px] px-[14px] py-[6px] rounded-[6px] hover:bg-[#6366f1] transition-colors duration-150">
              Start scanning
            </Link>
          </div>
          
        </div>
      </nav>

      {/* HERO SECTION */}
      <section 
        className="relative pt-32 pb-20 md:pt-40 md:pb-32 overflow-hidden flex items-center min-h-screen"
        style={{
          background: 'radial-gradient(ellipse 80% 50% at 70% 50%, rgba(91,95,207,0.07) 0%, transparent 60%), #080809'
        }}
      >
        <div className="container mx-auto px-6 max-w-7xl">
          <div className="flex flex-col lg:flex-row items-center gap-16 lg:gap-8">
            
            {/* Left Column */}
            <div className="w-full lg:w-1/2 flex flex-col items-start text-left">
              
              <div className="text-[11px] uppercase tracking-[0.08em] text-[#5b5fcf] font-[500] border-l-2 border-[#5b5fcf] pl-[10px]">
                Document Security
              </div>

              <h1 className="mt-[20px] font-[600] tracking-[-0.03em] leading-[1.1] text-[#f4f4f5] text-[clamp(2.5rem,5vw,3.75rem)]">
                Scan.<br />
                Disarm.<br />
                Reconstruct.
              </h1>

              <p className="mt-[16px] text-[15px] text-[#71717a] leading-[1.65] max-w-[380px]">
                Every uploaded document runs through a 5-layer AI threat detection pipeline. The output is rebuilt from scratch — zero active content, pixel-perfect fidelity.
              </p>

              <div className="mt-[28px] flex items-center">
                <div className="flex flex-col">
                  <span className="text-[22px] font-[600] text-[#f4f4f5]">5 layers</span>
                  <span className="text-[12px] text-[#71717a]">of analysis</span>
                </div>
                
                <div className="h-[32px] w-[1px] bg-[#1f1f23] mx-[20px]"></div>
                
                <div className="flex flex-col">
                  <span className="text-[22px] font-[600] text-[#f4f4f5]">&lt; 10 sec</span>
                  <span className="text-[12px] text-[#71717a]">full pipeline</span>
                </div>
              </div>

              <div className="mt-[32px]">
                <Link 
                  href="/dashboard" 
                  className="inline-block bg-[#5b5fcf] hover:bg-[#6366f1] text-white px-[20px] py-[10px] rounded-[6px] text-[14px] font-[500] transition-all duration-150 hover:-translate-y-[1px]"
                >
                  Upload a PDF &rarr;
                </Link>
                <div className="mt-[12px] text-[12px] text-[#3f3f46]">
                  No account needed &nbsp;&middot;&nbsp; Max 20MB &nbsp;&middot;&nbsp; PDF and TXT
                </div>
              </div>

            </div>

            {/* Right Column (3D PDF Scene) */}
            <InteractivePdfDisarm />

          </div>
        </div>
      </section>

      {/* THIN DIVIDER SECTION */}
      <div className="w-full border-t border-b border-[#1f1f23] bg-[#0c0c0f] py-[20px]">
        <div className="container mx-auto px-6 max-w-7xl">
          <div className="flex flex-wrap items-center justify-center gap-[20px] md:gap-[40px] text-[12px] text-[#3f3f46] font-[500] tracking-[0.03em]">
            <span>Groq / Llama3-70B</span>
            <div className="h-[12px] w-[1px] bg-[#1f1f23]" />
            <span>Poppler CDR</span>
            <div className="h-[12px] w-[1px] bg-[#1f1f23]" />
            <span>Shannon Entropy</span>
            <div className="h-[12px] w-[1px] bg-[#1f1f23]" />
            <span>Zero Active Content</span>
          </div>
        </div>
      </div>

      {/* HOW IT WORKS SECTION */}
      <section id="how-it-works" className="py-32">
        <div className="container mx-auto px-6 max-w-7xl">
          
          <div className="mb-20">
            <div className="text-[11px] uppercase tracking-[0.08em] text-[#5b5fcf] font-[500] border-l-2 border-[#5b5fcf] pl-[10px]">
              The pipeline
            </div>
            <h2 className="mt-[12px] font-[600] tracking-[-0.02em] text-[#f4f4f5] text-[clamp(1.5rem,3vw,2rem)]">
              Four stages. Every upload. No exceptions.
            </h2>
          </div>

          <div className="relative">
            {/* Connecting horizontal line */}
            <div className="absolute top-[32px] left-0 right-0 h-[1px] bg-[#1f1f23] hidden md:block" />

            <div className="grid grid-cols-1 md:grid-cols-4 gap-12 md:gap-6 relative z-10">
              
              {/* Stage 01 */}
              <div className="flex flex-col group border-l-[0px] border-[#5b5fcf] hover:border-l-[2px] pl-0 hover:pl-[12px] transition-all duration-200 ease-out max-w-[220px]">
                <div className="font-mono text-[12px] text-[#3f3f46] bg-[#080809] w-max pr-4">01</div>
                <FileSearch className="w-4 h-4 text-[#5b5fcf] my-[12px] bg-[#080809]" />
                <h3 className="text-[16px] font-[500] text-[#f4f4f5] mb-[4px]">Extract</h3>
                <p className="text-[14px] text-[#71717a] leading-[1.5]">
                  Raw bytes into buffer. Magic byte validation against actual file header.
                </p>
              </div>

              {/* Stage 02 */}
              <div className="flex flex-col group border-l-[0px] border-[#5b5fcf] hover:border-l-[2px] pl-0 hover:pl-[12px] transition-all duration-200 ease-out max-w-[220px]">
                <div className="font-mono text-[12px] text-[#3f3f46] bg-[#080809] w-max pr-4">02</div>
                <Brain className="w-4 h-4 text-[#5b5fcf] my-[12px] bg-[#080809]" />
                <h3 className="text-[16px] font-[500] text-[#f4f4f5] mb-[4px]">Scan</h3>
                <p className="text-[14px] text-[#71717a] leading-[1.5]">
                  5-layer analysis: structure, keywords, entropy, URLs, patterns + AI verdict.
                </p>
              </div>

              {/* Stage 03 */}
              <div className="flex flex-col group border-l-[0px] border-[#5b5fcf] hover:border-l-[2px] pl-0 hover:pl-[12px] transition-all duration-200 ease-out max-w-[220px]">
                <div className="font-mono text-[12px] text-[#3f3f46] bg-[#080809] w-max pr-4">03</div>
                <ShieldOff className="w-4 h-4 text-[#5b5fcf] my-[12px] bg-[#080809]" />
                <h3 className="text-[16px] font-[500] text-[#f4f4f5] mb-[4px]">Catalogue</h3>
                <p className="text-[14px] text-[#71717a] leading-[1.5]">
                  Every signal documented with severity weight and confidence score.
                </p>
              </div>

              {/* Stage 04 */}
              <div className="flex flex-col group border-l-[0px] border-[#5b5fcf] hover:border-l-[2px] pl-0 hover:pl-[12px] transition-all duration-200 ease-out max-w-[220px]">
                <div className="font-mono text-[12px] text-[#3f3f46] bg-[#080809] w-max pr-4">04</div>
                <RefreshCw className="w-4 h-4 text-[#5b5fcf] my-[12px] bg-[#080809]" />
                <h3 className="text-[16px] font-[500] text-[#f4f4f5] mb-[4px]">Reconstruct</h3>
                <p className="text-[14px] text-[#71717a] leading-[1.5]">
                  Poppler renders every page. sharp strips metadata. pdf-lib builds a new document.
                </p>
              </div>

            </div>
          </div>

        </div>
      </section>

      {/* FEATURES SECTION */}
      <section id="features" className="py-32 border-t border-[#1f1f23]">
        <div className="container mx-auto px-6 max-w-7xl">
          <div className="flex flex-col lg:flex-row gap-16 lg:gap-8">
            
            {/* Left Column (Sticky) */}
            <div className="w-full lg:w-[40%]">
              <div className="sticky top-[120px]">
                <div className="text-[11px] uppercase tracking-[0.08em] text-[#5b5fcf] font-[500] border-l-2 border-[#5b5fcf] pl-[10px]">
                  What the scanner catches
                </div>
                <h2 className="mt-[12px] font-[600] tracking-[-0.02em] text-[#f4f4f5] text-[clamp(1.4rem,2.5vw,1.85rem)]">
                  Six layers of defense.<br />One clean output.
                </h2>
                <p className="mt-[16px] text-[14px] text-[#71717a] leading-[1.6] max-w-[280px]">
                  Most scanners look for known threats. Zero Trust Sentinel assumes every file is hostile until reconstruction proves otherwise.
                </p>
              </div>
            </div>

            {/* Right Column (Scrolling List) */}
            <div className="w-full lg:w-[60%] flex flex-col border-t border-[#1f1f23]">
              
              {/* Feature 01 */}
              <div className="group flex items-center justify-between py-[24px] border-b border-[#1f1f23] hover:bg-[#111114] transition-colors duration-150 px-4 -mx-4 rounded-[8px]">
                <div className="flex items-start md:items-center flex-col md:flex-row gap-[12px] md:gap-[32px]">
                  <span className="font-mono text-[12px] text-[#3f3f46]">01</span>
                  <div>
                    <h4 className="text-[15px] font-[500] text-[#f4f4f5]">Hex-obfuscation bypass</h4>
                    <p className="text-[14px] text-[#71717a] mt-1 md:mt-0">/J#61vaScript decoded before scan</p>
                  </div>
                </div>
                <div className="hidden sm:block font-mono text-[11px] text-[#3f3f46] border border-[#1f1f23] rounded-full px-[10px] py-[4px] group-hover:text-[#71717a] group-hover:border-[#3f3f46] transition-colors duration-150">
                  scanner.ts:L47
                </div>
              </div>

              {/* Feature 02 */}
              <div className="group flex items-center justify-between py-[24px] border-b border-[#1f1f23] hover:bg-[#111114] transition-colors duration-150 px-4 -mx-4 rounded-[8px]">
                <div className="flex items-start md:items-center flex-col md:flex-row gap-[12px] md:gap-[32px]">
                  <span className="font-mono text-[12px] text-[#3f3f46]">02</span>
                  <div>
                    <h4 className="text-[15px] font-[500] text-[#f4f4f5]">Magic byte validation</h4>
                    <p className="text-[14px] text-[#71717a] mt-1 md:mt-0">EXE, ELF, ZIP, OLE2 header detection</p>
                  </div>
                </div>
                <div className="hidden sm:block font-mono text-[11px] text-[#3f3f46] border border-[#1f1f23] rounded-full px-[10px] py-[4px] group-hover:text-[#71717a] group-hover:border-[#3f3f46] transition-colors duration-150">
                  scanner.ts:L82
                </div>
              </div>

              {/* Feature 03 */}
              <div className="group flex items-center justify-between py-[24px] border-b border-[#1f1f23] hover:bg-[#111114] transition-colors duration-150 px-4 -mx-4 rounded-[8px]">
                <div className="flex items-start md:items-center flex-col md:flex-row gap-[12px] md:gap-[32px]">
                  <span className="font-mono text-[12px] text-[#3f3f46]">03</span>
                  <div>
                    <h4 className="text-[15px] font-[500] text-[#f4f4f5]">Shannon entropy analysis</h4>
                    <p className="text-[14px] text-[#71717a] mt-1 md:mt-0">Detects base64 payloads statistically</p>
                  </div>
                </div>
                <div className="hidden sm:block font-mono text-[11px] text-[#3f3f46] border border-[#1f1f23] rounded-full px-[10px] py-[4px] group-hover:text-[#71717a] group-hover:border-[#3f3f46] transition-colors duration-150">
                  scanner.ts:L114
                </div>
              </div>

              {/* Feature 04 */}
              <div className="group flex items-center justify-between py-[24px] border-b border-[#1f1f23] hover:bg-[#111114] transition-colors duration-150 px-4 -mx-4 rounded-[8px]">
                <div className="flex items-start md:items-center flex-col md:flex-row gap-[12px] md:gap-[32px]">
                  <span className="font-mono text-[12px] text-[#3f3f46]">04</span>
                  <div>
                    <h4 className="text-[15px] font-[500] text-[#f4f4f5]">Structural binary scan</h4>
                    <p className="text-[14px] text-[#71717a] mt-1 md:mt-0">PDF object tree read in raw binary</p>
                  </div>
                </div>
                <div className="hidden sm:block font-mono text-[11px] text-[#3f3f46] border border-[#1f1f23] rounded-full px-[10px] py-[4px] group-hover:text-[#71717a] group-hover:border-[#3f3f46] transition-colors duration-150">
                  scanner.ts:L156
                </div>
              </div>

              {/* Feature 05 */}
              <div className="group flex items-center justify-between py-[24px] border-b border-[#1f1f23] hover:bg-[#111114] transition-colors duration-150 px-4 -mx-4 rounded-[8px]">
                <div className="flex items-start md:items-center flex-col md:flex-row gap-[12px] md:gap-[32px]">
                  <span className="font-mono text-[12px] text-[#3f3f46]">05</span>
                  <div>
                    <h4 className="text-[15px] font-[500] text-[#f4f4f5]">Encrypted PDF detection</h4>
                    <p className="text-[14px] text-[#71717a] mt-1 md:mt-0">Flags files that would score as clean</p>
                  </div>
                </div>
                <div className="hidden sm:block font-mono text-[11px] text-[#3f3f46] border border-[#1f1f23] rounded-full px-[10px] py-[4px] group-hover:text-[#71717a] group-hover:border-[#3f3f46] transition-colors duration-150">
                  scanner.ts:L190
                </div>
              </div>

              {/* Feature 06 */}
              <div className="group flex items-center justify-between py-[24px] border-b border-[#1f1f23] hover:bg-[#111114] transition-colors duration-150 px-4 -mx-4 rounded-[8px]">
                <div className="flex items-start md:items-center flex-col md:flex-row gap-[12px] md:gap-[32px]">
                  <span className="font-mono text-[12px] text-[#3f3f46]">06</span>
                  <div>
                    <h4 className="text-[15px] font-[500] text-[#f4f4f5]">Poppler rasterisation</h4>
                    <p className="text-[14px] text-[#71717a] mt-1 md:mt-0">Same renderer as Firefox and Chrome</p>
                  </div>
                </div>
                <div className="hidden sm:block font-mono text-[11px] text-[#3f3f46] border border-[#1f1f23] rounded-full px-[10px] py-[4px] group-hover:text-[#71717a] group-hover:border-[#3f3f46] transition-colors duration-150">
                  reconstructor.ts:L22
                </div>
              </div>

            </div>

          </div>
        </div>
      </section>

      {/* BOTTOM CTA */}
      <section className="bg-[#0c0c0f] border-t border-[#1f1f23] py-[80px]">
        <div className="container mx-auto px-6 max-w-7xl flex flex-col items-start">
          <h2 className="text-[clamp(1.5rem,3vw,2.25rem)] font-[600] tracking-[-0.02em] text-[#f4f4f5]">
            Ready to scan your first file?
          </h2>
          <p className="mt-[8px] text-[15px] text-[#71717a]">
            No account needed. No data stored. Upload and scan.
          </p>
          <div className="mt-[24px]">
            <Link 
              href="/dashboard" 
              className="inline-block bg-[#5b5fcf] hover:bg-[#6366f1] text-white px-[20px] py-[10px] rounded-[6px] text-[14px] font-[500] transition-all duration-150 hover:-translate-y-[1px]"
            >
              Upload a PDF &rarr;
            </Link>
          </div>
        </div>
      </section>

      {/* FOOTER */}
      <footer className="bg-[#080809] border-t border-[#1f1f23] py-[28px]">
        <div className="container mx-auto px-6 max-w-7xl flex flex-col md:flex-row items-center justify-between gap-4">
          
          <div className="flex items-center text-[14px]">
            <span className="font-[500] text-[#f4f4f5]">Zero Trust Sentinel</span>
            <span className="text-[#3f3f46] ml-2">&middot; Built by Ayush Anand George</span>
          </div>

          <div className="flex items-center gap-6 text-[#3f3f46]">
            <a href="#" className="hover:text-[#71717a] transition-colors duration-150">
              <Github className="w-4 h-4" />
            </a>
            <a href="#" className="hover:text-[#71717a] transition-colors duration-150">
              <Linkedin className="w-4 h-4" />
            </a>
          </div>

        </div>
      </footer>

    </div>
  )
}