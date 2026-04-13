"use client"
// components/dashboard/file-upload-zone.tsx

import { useRef } from "react"
import { Upload, FileText, Lock, Hash, ShieldCheck, Download, AlertTriangle } from "lucide-react"
import { Card } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { useScan, StageId } from "@/context/scan-context"

// Stage order + what progress value each "done" event sets
const STAGE_CONF: { id: StageId; label: string; progressDone: number }[] = [
  { id: 'extract',     label: 'Extract content',    progressDone: 22  },
  { id: 'scan',        label: 'AI threat scan',      progressDone: 52  },
  { id: 'disarm',      label: 'Content disarm',      progressDone: 74  },
  { id: 'reconstruct', label: 'File reconstruction', progressDone: 100 },
]

const SEV_COLOR: Record<string, string> = {
  low:      'text-blue-400',
  medium:   'text-amber-400',
  high:     'text-orange-400',
  critical: 'text-red-400',
}

const RISK: Record<string, { label: string; color: string }> = {
  clean:    { label: 'Clean',    color: 'text-green-400'  },
  low:      { label: 'Low',      color: 'text-blue-400'   },
  medium:   { label: 'Medium',   color: 'text-amber-400'  },
  high:     { label: 'High',     color: 'text-orange-400' },
  critical: { label: 'Critical', color: 'text-red-400'    },
}

export function FileUploadZone() {
  const { state, setState, reset, updateStage } = useScan()
  const { pipelineStatus, progress, filename, stages, result, errorMsg } = state
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    // Reset to clean processing state
    setState({
      pipelineStatus: 'processing',
      progress:       3,
      filename:       file.name,
      stages: {
        extract:     { status: 'waiting', message: '' },
        scan:        { status: 'waiting', message: '' },
        disarm:      { status: 'waiting', message: '' },
        reconstruct: { status: 'waiting', message: '' },
      },
      result:   null,
      errorMsg: null,
    })

    const formData = new FormData()
    formData.append('file', file)

    try {
      const response = await fetch('/api/scan', { method: 'POST', body: formData })

      if (!response.ok || !response.body) {
        throw new Error(`Server returned ${response.status}`)
      }

      const reader  = response.body.getReader()
      const decoder = new TextDecoder()
      let   buffer  = ''

      while (true) {
        const { value, done } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })

        // Split on SSE double-newline boundary
        const parts = buffer.split('\n\n')
        buffer = parts.pop() ?? ''   // keep any incomplete chunk

        for (const part of parts) {
          const line = part.replace(/^data:\s*/, '').trim()
          if (!line) continue

          let event: any
          try { event = JSON.parse(line) } catch { continue }

          const conf = STAGE_CONF.find(s => s.id === event.stage)

          if (event.stage === 'complete') {
            setState(prev => ({
              ...prev,
              pipelineStatus: 'success',
              progress: 100,
              result: {
                score:             event.score,
                riskLevel:         event.riskLevel,
                signals:           event.signals ?? [],
                reconstructedFile: event.reconstructedFile,
                filename:          event.filename,
              },
            }))

          } else if (event.stage === 'error') {
            setState(prev => ({
              ...prev,
              pipelineStatus: 'error',
              errorMsg: event.message ?? 'Unknown error',
            }))

          } else if (conf) {
            // Update the matching stage
            updateStage(event.stage as StageId, {
              status:       event.status,
              message:      event.message ?? '',
              score:        event.score,
              riskLevel:    event.riskLevel,
              signals:      event.signals,
              elementCount: event.elementCount,
            })

            // Advance progress only when backend confirms the stage is done
            setState(prev => ({
              ...prev,
              progress: event.status === 'done'
                ? conf.progressDone
                // Show mid-stage progress slightly below done mark
                : Math.max(prev.progress, conf.progressDone - 16),
            }))
          }
        }
      }

    } catch (err: any) {
      setState(prev => ({
        ...prev,
        pipelineStatus: 'error',
        errorMsg: err?.message ?? String(err),
      }))
    }
  }

  const downloadSafeFile = () => {
    if (!result?.reconstructedFile) return
    const a  = document.createElement('a')
    a.href     = result.reconstructedFile
    a.download = result.filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
  }

  const riskInfo = result ? (RISK[result.riskLevel] ?? RISK.medium) : null

  return (
    <Card className="glass-card p-6">
      {/* Header */}
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-foreground">Secure File Upload</h2>
        <div className="flex items-center gap-2 rounded-full bg-primary/10 px-3 py-1 text-xs text-primary">
          <Lock className="h-3 w-3" />
          <span>Zero-Trust Architecture</span>
        </div>
      </div>

      {/* Drop zone */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileSelect}
        className="hidden"
        accept=".pdf,.txt"
      />
      <div
        onClick={() => pipelineStatus === 'idle' && fileInputRef.current?.click()}
        className={`relative mb-4 rounded-xl border-2 border-dashed border-border/50 bg-secondary/30 p-8 transition-all
          ${pipelineStatus === 'idle'
            ? 'cursor-pointer hover:border-primary/50 hover:bg-secondary/50'
            : 'opacity-50 pointer-events-none'}`}
      >
        <div className="flex flex-col items-center justify-center text-center">
          <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-primary/10">
            <Upload className="h-7 w-7 text-primary" />
          </div>
          <p className="mb-2 text-sm font-medium text-foreground">Click here to select a file</p>
          <p className="text-xs text-muted-foreground">Supported formats: PDF, TXT</p>
        </div>
      </div>

      {/* Warning banner */}
      <div className="mb-6 flex items-start gap-2 rounded-lg bg-amber-warning/10 px-4 py-3">
        <Lock className="mt-0.5 h-4 w-4 shrink-0 text-amber-warning" />
        <p className="text-xs text-amber-warning/90">
          <span className="font-medium">Zero-Trust Architecture:</span> Every file is treated as
          untrusted and will be fully reconstructed.
        </p>
      </div>

      {/* Processing panel — only shown while active */}
      {pipelineStatus !== 'idle' && (
        <div className="rounded-lg border border-border/50 bg-secondary/30 p-4 space-y-4">

          {/* File row */}
          <div className="flex items-center gap-3">
            <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg
              ${pipelineStatus === 'success'    ? 'bg-primary/20'
              : pipelineStatus === 'error'      ? 'bg-destructive/20'
              : 'bg-primary/10'}`}>
              <FileText className={`h-5 w-5
                ${pipelineStatus === 'success'  ? 'text-primary'
                : pipelineStatus === 'error'    ? 'text-destructive'
                : 'text-primary'}`} />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-foreground truncate">{filename}</p>
            </div>
            {pipelineStatus === 'processing' && (
              <div className="flex items-center gap-2">
                <div className="h-2 w-2 animate-pulse rounded-full bg-amber-warning" />
                <span className="text-xs text-amber-warning">Scanning…</span>
              </div>
            )}
            {pipelineStatus === 'success' && (
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-primary" />
                <span className="text-xs text-primary">Secured</span>
              </div>
            )}
            {pipelineStatus === 'error' && (
              <button onClick={reset} className="text-xs text-muted-foreground underline">
                Retry
              </button>
            )}
          </div>

          {/* Progress bar — advances only on real backend events */}
          <Progress value={progress} className="h-1.5 bg-secondary" />

          {/* Stage list */}
          <div className="space-y-1.5">
            {STAGE_CONF.map(({ id, label }) => {
              const s = stages[id]
              return (
                <div key={id} className="flex items-start gap-2 text-xs">
                  <span className={`mt-0.5 h-2 w-2 shrink-0 rounded-full
                    ${s.status === 'done'    ? 'bg-primary'
                    : s.status === 'running' ? 'bg-amber-warning animate-pulse'
                    : s.status === 'error'   ? 'bg-destructive'
                    : 'bg-muted-foreground/30'}`} />
                  <span className={`font-medium
                    ${s.status === 'done'    ? 'text-primary'
                    : s.status === 'running' ? 'text-amber-warning'
                    : s.status === 'error'   ? 'text-destructive'
                    : 'text-muted-foreground/50'}`}>
                    {label}
                  </span>
                  {s.message && (
                    <span className="text-muted-foreground ml-1 truncate">{s.message}</span>
                  )}
                </div>
              )
            })}
          </div>

          {/* Score row */}
          {result && (
            <div className="flex items-center gap-4 border-t border-border/30 pt-3">
              <div className="flex items-center gap-1.5">
                <Hash className="h-3 w-3 text-primary" />
                <span className="text-xs font-mono text-muted-foreground">
                  Threat score:{' '}
                  <span className="text-foreground font-semibold">{result.score} / 100</span>
                </span>
              </div>
              {riskInfo && (
                <span className={`text-xs font-semibold ${riskInfo.color}`}>
                  {riskInfo.label} risk
                </span>
              )}
            </div>
          )}

          {/* Signal list */}
          {result && result.signals.length > 0 && (
            <div className="rounded-md border border-border/30 bg-secondary/20 p-3 space-y-1 max-h-40 overflow-y-auto">
              {result.signals.map((sig, i) => (
                <div key={i} className="flex items-start gap-2 text-xs">
                  <AlertTriangle
                    className={`h-3 w-3 shrink-0 mt-0.5 ${SEV_COLOR[sig.severity] ?? 'text-muted-foreground'}`}
                  />
                  <span className="text-muted-foreground">{sig.detail}</span>
                </div>
              ))}
            </div>
          )}

          {/* Error detail */}
          {pipelineStatus === 'error' && errorMsg && (
            <div className="rounded-md bg-destructive/10 px-3 py-2">
              <p className="text-xs font-medium text-destructive mb-1">Error</p>
              <p className="font-mono text-xs text-destructive/80 break-all">{errorMsg}</p>
            </div>
          )}

          {/* Download + reset */}
          {pipelineStatus === 'success' && result && (
            <div className="space-y-2 pt-1">
              <button
                onClick={downloadSafeFile}
                className="flex w-full items-center justify-center gap-2 rounded-md bg-primary py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
              >
                <Download className="h-4 w-4" />
                Download {result.filename}
              </button>
              <button
                onClick={reset}
                className="flex w-full items-center justify-center gap-2 rounded-md border border-border/50 py-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                Scan another file
              </button>
            </div>
          )}
        </div>
      )}
    </Card>
  )
}