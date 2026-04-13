"use client"
// components/dashboard/live-pipeline-panel.tsx
// Replace your existing right-panel component with this file.

import { CheckCircle, Clock, AlertTriangle, Loader2 } from "lucide-react"
import { Card } from "@/components/ui/card"
import { useScan, StageId, StageStatus, ThreatSignal } from "@/context/scan-context"

interface StageMeta {
  id: StageId
  title: string
  subtitle: string
}

const STAGES: StageMeta[] = [
  { id: 'extract',     title: 'Extract content',     subtitle: 'Parse and extract file contents'    },
  { id: 'scan',        title: 'AI threat scan',       subtitle: 'Multi-signal deep analysis'         },
  { id: 'disarm',      title: 'Content disarm',       subtitle: 'Remove active content and macros'   },
  { id: 'reconstruct', title: 'File reconstruction',  subtitle: 'Rebuild safe document from scratch' },
]

const SEVERITY_COLOR: Record<string, string> = {
  low: 'text-blue-400', medium: 'text-amber-400', high: 'text-orange-400', critical: 'text-red-400',
}
const SEVERITY_DOT: Record<string, string> = {
  low: 'bg-blue-400', medium: 'bg-amber-400', high: 'bg-orange-400', critical: 'bg-red-500',
}
const RISK_BADGE: Record<string, { label: string; bg: string; text: string }> = {
  clean:    { label: 'Clean',     bg: 'bg-green-500/20',  text: 'text-green-400'  },
  low:      { label: 'Low risk',  bg: 'bg-blue-500/20',   text: 'text-blue-400'   },
  medium:   { label: 'Med risk',  bg: 'bg-amber-500/20',  text: 'text-amber-400'  },
  high:     { label: 'High risk', bg: 'bg-orange-500/20', text: 'text-orange-400' },
  critical: { label: 'Critical',  bg: 'bg-red-500/20',    text: 'text-red-400'    },
}

function StageIcon({ status }: { status: StageStatus }) {
  if (status === 'done')    return <CheckCircle className="h-4 w-4 text-primary" />
  if (status === 'running') return <Loader2 className="h-4 w-4 text-amber-400 animate-spin" />
  if (status === 'error')   return <AlertTriangle className="h-4 w-4 text-destructive" />
  return <Clock className="h-4 w-4 text-muted-foreground/40" />
}

function TimelineDot({ status }: { status: StageStatus }) {
  return (
    <div className={`relative z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border
      ${status === 'done'    ? 'border-primary bg-primary/10'
      : status === 'running' ? 'border-amber-400 bg-amber-400/10'
      : status === 'error'   ? 'border-destructive bg-destructive/10'
      : 'border-muted-foreground/20 bg-secondary/50'}`}
    >
      <StageIcon status={status} />
    </div>
  )
}

export function LivePipelinePanel() {
  const { state } = useScan()
  const { pipelineStatus, stages, result } = state

  const overallStatus =
    pipelineStatus === 'processing' ? 'Processing' :
    pipelineStatus === 'success'    ? 'Complete'   :
    pipelineStatus === 'error'      ? 'Error'      : 'Idle'

  const statusColor =
    pipelineStatus === 'processing' ? 'text-amber-400 bg-amber-400/10 border-amber-400/30' :
    pipelineStatus === 'success'    ? 'text-primary bg-primary/10 border-primary/30'        :
    pipelineStatus === 'error'      ? 'text-destructive bg-destructive/10 border-destructive/30' :
    'text-muted-foreground bg-secondary/50 border-border/30'

  return (
    <Card className="glass-card p-6">
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground">Live Threat Analysis &amp; CDR Pipeline</h2>
          <p className="text-xs text-muted-foreground mt-0.5">Real-time file processing status</p>
        </div>
        <span className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium ${statusColor}`}>
          {pipelineStatus === 'processing' && (
            <span className="h-1.5 w-1.5 rounded-full bg-amber-400 animate-pulse" />
          )}
          {overallStatus}
        </span>
      </div>

      {pipelineStatus === 'idle' && (
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-secondary/50">
            <Clock className="h-6 w-6 text-muted-foreground/40" />
          </div>
          <p className="text-sm text-muted-foreground">Awaiting file upload</p>
          <p className="text-xs text-muted-foreground/60 mt-1">Upload a file on the left to begin scanning</p>
        </div>
      )}

      {pipelineStatus !== 'idle' && (
        <div className="space-y-0">
          {STAGES.map(({ id, title, subtitle }, idx) => {
            const s = stages[id]
            const isLast = idx === STAGES.length - 1
            const riskBadge = id === 'scan' && s.riskLevel ? RISK_BADGE[s.riskLevel] : null
            return (
              <div key={id} className="flex gap-4">
                <div className="flex flex-col items-center">
                  <TimelineDot status={s.status} />
                  {!isLast && (
                    <div className={`w-px flex-1 my-1 min-h-[1.5rem] ${s.status === 'done' ? 'bg-primary/30' : 'bg-border/30'}`} />
                  )}
                </div>
                <div className={`mb-3 flex-1 rounded-lg border p-4 transition-colors
                  ${s.status === 'running' ? 'border-amber-400/40 bg-amber-400/5'
                  : s.status === 'done'    ? 'border-primary/20 bg-primary/5'
                  : s.status === 'error'   ? 'border-destructive/30 bg-destructive/5'
                  : 'border-border/20 bg-secondary/20 opacity-50'}`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-sm font-medium
                      ${s.status === 'done'    ? 'text-foreground'
                      : s.status === 'running' ? 'text-amber-300'
                      : s.status === 'error'   ? 'text-destructive'
                      : 'text-muted-foreground/50'}`}>
                      {title}
                    </span>
                    {riskBadge && (
                      <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${riskBadge.bg} ${riskBadge.text}`}>
                        {riskBadge.label}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground/60 mb-2">{subtitle}</p>
                  {s.status === 'waiting' && <p className="font-mono text-xs text-muted-foreground/40">Waiting…</p>}
                  {(s.status === 'running' || s.status === 'done') && s.message && (
                    <p className={`font-mono text-xs ${s.status === 'running' ? 'text-amber-400' : 'text-primary'}`}>
                      {s.message}
                    </p>
                  )}
                  {s.status === 'error' && (
                    <p className="font-mono text-xs text-destructive">{s.message || 'Stage failed'}</p>
                  )}
                  {id === 'scan' && s.status === 'done' && s.signals && s.signals.length > 0 && (
                    <div className="mt-3 space-y-1 max-h-36 overflow-y-auto">
                      {(s.signals as ThreatSignal[]).map((sig, i) => (
                        <div key={i} className="flex items-start gap-1.5 text-xs">
                          <span className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${SEVERITY_DOT[sig.severity] ?? 'bg-muted'}`} />
                          <span className={`font-medium shrink-0 ${SEVERITY_COLOR[sig.severity]}`}>{sig.severity}</span>
                          <span className="text-muted-foreground truncate">{sig.detail}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {id === 'scan' && s.status === 'done' && s.signals?.length === 0 && (
                    <p className="mt-2 text-xs text-primary">No threats detected</p>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {pipelineStatus === 'success' && result && (
        <div className="mt-2 rounded-lg border border-primary/20 bg-primary/5 px-4 py-3 flex items-center justify-between">
          <span className="text-xs text-muted-foreground font-mono">
            Final threat score: <span className="text-foreground font-semibold">{result.score} / 100</span>
          </span>
          {(() => {
            const b = RISK_BADGE[result.riskLevel] ?? RISK_BADGE.medium
            return <span className={`rounded-full px-3 py-1 text-xs font-semibold ${b.bg} ${b.text}`}>{b.label}</span>
          })()}
        </div>
      )}
    </Card>
  )
}
