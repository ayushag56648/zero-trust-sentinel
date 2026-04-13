"use client"
// context/scan-context.tsx

import { createContext, useContext, useState, useCallback, ReactNode } from "react"

export type StageId     = 'extract' | 'scan' | 'disarm' | 'reconstruct'
export type StageStatus = 'waiting' | 'running' | 'done' | 'error'

export interface ThreatSignal {
  type:     string
  severity: 'low' | 'medium' | 'high' | 'critical'
  detail:   string
  weight:   number
}

export interface StageState {
  status:       StageStatus
  message:      string
  score?:       number
  riskLevel?:   string
  signals?:     ThreatSignal[]
  elementCount?: number
}

export type PipelineStatus = 'idle' | 'processing' | 'success' | 'error'

export interface FinalResult {
  score:             number
  riskLevel:         string
  signals:           ThreatSignal[]
  reconstructedFile: string
  filename:          string
}

export interface ScanState {
  pipelineStatus: PipelineStatus
  progress:       number
  filename:       string | null
  stages:         Record<StageId, StageState>
  result:         FinalResult | null
  errorMsg:       string | null
}

const INITIAL_STAGES: Record<StageId, StageState> = {
  extract:     { status: 'waiting', message: '' },
  scan:        { status: 'waiting', message: '' },
  disarm:      { status: 'waiting', message: '' },
  reconstruct: { status: 'waiting', message: '' },
}

const INITIAL_STATE: ScanState = {
  pipelineStatus: 'idle',
  progress:       0,
  filename:       null,
  stages:         INITIAL_STAGES,
  result:         null,
  errorMsg:       null,
}

interface ScanContextValue {
  state:       ScanState
  setState:    React.Dispatch<React.SetStateAction<ScanState>>
  reset:       () => void
  updateStage: (id: StageId, patch: Partial<StageState>) => void
}

const ScanContext = createContext<ScanContextValue | null>(null)

export function ScanProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<ScanState>(INITIAL_STATE)

  const reset = useCallback(() => setState(INITIAL_STATE), [])

  const updateStage = useCallback((id: StageId, patch: Partial<StageState>) =>
    setState(prev => ({
      ...prev,
      stages: { ...prev.stages, [id]: { ...prev.stages[id], ...patch } },
    })), [])

  return (
    <ScanContext.Provider value={{ state, setState, reset, updateStage }}>
      {children}
    </ScanContext.Provider>
  )
}

export function useScan() {
  const ctx = useContext(ScanContext)
  if (!ctx) throw new Error('useScan must be used inside <ScanProvider>')
  return ctx
}