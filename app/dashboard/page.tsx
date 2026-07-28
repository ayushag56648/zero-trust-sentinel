"use client"
import Link from "next/link"
import { ScanProvider } from "@/context/scan-context"
import { StatsHeader } from "@/components/dashboard/stats-header"
import { FileUploadZone } from "@/components/dashboard/file-upload-zone"
import { LivePipelinePanel } from "@/components/dashboard/live-pipeline-panel"
import { GithubCtaPanel } from "@/components/dashboard/github-cta-panel"

export default function Dashboard() {
  return (
    <ScanProvider> 
      <div className="min-h-screen bg-background text-foreground selection:bg-primary/30">
        
        {/* Simple Breadcrumb Navbar */}
        <div className="sticky top-0 z-50 w-full border-b border-white/10 bg-background/80 backdrop-blur-md">
          <div className="container mx-auto px-6 h-14 flex items-center text-sm font-medium text-muted-foreground">
            <Link href="/" className="hover:text-foreground transition-colors flex items-center gap-2">
              <span aria-hidden="true">&larr;</span> Back to Home
            </Link>
            <span className="mx-3 text-white/20">|</span>
            <span className="text-foreground">Dashboard</span>
          </div>
        </div>

        {/* Header with Stats */}
        <div className="mt-8">
          <StatsHeader />
        </div>

        {/* Main Content */}
        <main className="container mx-auto px-6 py-8">
          <div className="grid gap-6 lg:grid-cols-2">
            
            {/* Left Column (Upload) */}
            <div className="space-y-6">
              <div className="glass-card rounded-xl overflow-hidden transition-all duration-300 hover:border-primary/30 hover:shadow-[0_0_15px_rgba(99,102,241,0.1)] p-4">
                <FileUploadZone />
              </div>
            </div>

            {/* Right Column (Live Pipeline) */}
            <div>
              <div className="glass-card rounded-xl overflow-hidden transition-all duration-300 hover:border-primary/30 hover:shadow-[0_0_15px_rgba(99,102,241,0.1)] p-4">
                <LivePipelinePanel />
              </div>
            </div>
            
          </div>

          <div className="mt-6 glass-card rounded-xl overflow-hidden p-4">
            <GithubCtaPanel />
          </div>
        </main>
      </div>
    </ScanProvider>
  )
}
