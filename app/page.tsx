"use client"
import { ScanProvider } from "@/context/scan-context"
import { StatsHeader } from "@/components/dashboard/stats-header"
import { FileUploadZone } from "@/components/dashboard/file-upload-zone"
import { LivePipelinePanel } from "@/components/dashboard/live-pipeline-panel" // <-- Imported new panel
import { AuditLogsTable } from "@/components/dashboard/audit-logs-table"

export default function Dashboard() {
  return (
    // EVERYTHING is wrapped in ScanProvider so they can share data
    <ScanProvider> 
      <div className="min-h-screen bg-background">
        {/* Background Pattern */}
        <div className="fixed inset-0 -z-10">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-primary/5 via-background to-background" />
          <div className="absolute inset-0 bg-[url('data:image/svg+xml,%3Csvg%20width%3D%2260%22%20height%3D%2260%22%20viewBox%3D%220%200%2060%2060%22%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%3E%3Cg%20fill%3D%22none%22%20fill-rule%3D%22evenodd%22%3E%3Cg%20fill%3D%22%2322c55e%22%20fill-opacity%3D%220.03%22%3E%3Cpath%20d%3D%22M36%2034v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6%2034v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6%204V0H4v4H0v2h4v4h2V6h4V4H6z%22%2F%3E%3C%2Fg%3E%3C%2Fg%3E%3C%2Fsvg%3E')] opacity-50" />
        </div>

        {/* Header with Stats */}
        <StatsHeader />

        {/* Main Content */}
        <main className="container mx-auto px-6 py-8">
          <div className="grid gap-6 lg:grid-cols-2">
            
            {/* Left Column (Upload) */}
            <div className="space-y-6">
              <FileUploadZone />
              <AuditLogsTable />
            </div>

            {/* Right Column (Live Pipeline) */}
            <div>
              <LivePipelinePanel /> {/* <-- Swapped out the old static panel */}
            </div>
            
          </div>
        </main>
      </div>
    </ScanProvider>
  )
}