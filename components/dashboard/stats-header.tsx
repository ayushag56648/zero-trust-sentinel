"use client"

import { useState, useEffect } from "react"
import { Shield, Clock, Activity, Cpu } from "lucide-react"
import { Card } from "@/components/ui/card"
import { useScan } from "@/context/scan-context"

export function StatsHeader() {
  const { state } = useScan()
  const [timeUtc, setTimeUtc] = useState<string>("--:--:--")
  const [latency, setLatency] = useState<number>(18)

  // Card 1: System Time (UTC)
  useEffect(() => {
    const updateClock = () => {
      const now = new Date()
      // format HH:MM:SS in UTC
      const timeString = now.toISOString().substring(11, 19)
      setTimeUtc(timeString)
    }
    updateClock()
    const timer = setInterval(updateClock, 1000)
    return () => clearInterval(timer)
  }, [])

  // Card 2: Network Latency (simulated jitter)
  useEffect(() => {
    const updateLatency = () => {
      // Simulate network jitter around 18-24ms
      setLatency(Math.floor(18 + Math.random() * 7))
    }
    updateLatency()
    const timer = setInterval(updateLatency, 2500)
    return () => clearInterval(timer)
  }, [])

  // Card 3: CDR Buffer State logic
  let bufferStateText = "0 KB / FLUSHED"
  let bufferBadgeText = "STATELESS RAM"
  let bufferBadgeColor = "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
  let bufferTextColor = "text-foreground"
  
  if (state.pipelineStatus === 'processing') {
    bufferStateText = "2.4 MB INGEST" // Mocked file size for telemetry feel
    bufferBadgeText = "ALLOCATED"
    bufferBadgeColor = "bg-[#5b5fcf]/10 text-[#5b5fcf] border border-[#5b5fcf]/30"
    bufferTextColor = "text-[#5b5fcf]"
  } else if (state.pipelineStatus === 'success') {
    bufferStateText = "0 KB / PURGED"
  } else if (state.pipelineStatus === 'error') {
    bufferStateText = "0 KB / PURGED (ERR)"
    bufferBadgeColor = "bg-red-500/10 text-red-400 border border-red-500/20"
  }

  return (
    <header className="border-b border-border/50 bg-card/30 backdrop-blur-sm">
      <div className="container mx-auto px-6 py-4">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
          
          {/* Logo */}
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="absolute inset-0 rounded-lg bg-primary/20 blur-lg" />
              <div className="relative flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 border border-primary/30">
                <Shield className="h-6 w-6 text-primary" />
              </div>
            </div>
            <div>
              <h1 className="text-xl font-semibold tracking-tight text-foreground">
                Zero-Trust Sentinel
              </h1>
              <p className="text-xs text-muted-foreground">
                AI-Powered CDR Platform
              </p>
            </div>
          </div>

          {/* Live Stats Cards */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            
            {/* Card 1: Live System Time */}
            <Card className="glass-card px-4 py-3 relative overflow-hidden group">
              <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
              <div className="flex items-center gap-3 relative z-10">
                <div className="flex h-9 w-9 items-center justify-center rounded-md bg-secondary border border-border/50">
                  <Clock className="h-4 w-4 text-muted-foreground" />
                </div>
                <div>
                  <p className="text-[10px] font-mono tracking-widest text-muted-foreground uppercase">System Time (UTC)</p>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-lg font-mono font-semibold text-foreground tracking-tight">
                      {timeUtc}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5 mt-1">
                    <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-[pulse_2s_ease-in-out_infinite] shadow-[0_0_8px_#10b981]" />
                    <span className="text-[10px] font-mono font-medium text-emerald-500 tracking-wider">● NTP SYNC</span>
                  </div>
                </div>
              </div>
            </Card>

            {/* Card 2: Network Latency */}
            <Card className="glass-card px-4 py-3 relative overflow-hidden group">
              <div className="absolute inset-0 bg-gradient-to-br from-[#5b5fcf]/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
              <div className="flex items-center gap-3 relative z-10">
                <div className="flex h-9 w-9 items-center justify-center rounded-md bg-secondary border border-border/50">
                  <Activity className="h-4 w-4 text-muted-foreground" />
                </div>
                <div className="flex-1">
                  <p className="text-[10px] font-mono tracking-widest text-muted-foreground uppercase">Network Latency</p>
                  <div className="flex items-center justify-between mt-0.5">
                    <span className="text-lg font-mono font-semibold text-foreground tracking-tight w-16">
                      {latency} <span className="text-sm text-muted-foreground font-normal">ms</span>
                    </span>
                    {/* Animated signal bars */}
                    <div className="flex items-end gap-[3px] h-4 pb-0.5 opacity-80">
                      <div className="w-1 bg-[#5b5fcf] rounded-sm animate-[pulse_1s_ease-in-out_infinite] h-2" />
                      <div className="w-1 bg-[#5b5fcf] rounded-sm animate-[pulse_1.5s_ease-in-out_infinite] h-3" />
                      <div className="w-1 bg-[#5b5fcf] rounded-sm animate-[pulse_1.2s_ease-in-out_infinite] h-4" />
                      <div className="w-1 bg-white/20 rounded-sm h-1" />
                    </div>
                  </div>
                  <div className="mt-1">
                    <span className="text-[10px] font-mono font-medium text-[#5b5fcf] tracking-wider">TLS 1.3 SECURE</span>
                  </div>
                </div>
              </div>
            </Card>

            {/* Card 3: CDR Buffer State */}
            <Card className={`glass-card px-4 py-3 relative overflow-hidden group ${state.pipelineStatus === 'processing' ? 'glass-card-glow' : ''}`}>
              <div className="absolute inset-0 bg-gradient-to-br from-primary/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
              <div className="flex items-center gap-3 relative z-10">
                <div className={`flex h-9 w-9 items-center justify-center rounded-md border ${state.pipelineStatus === 'processing' ? 'bg-primary/20 border-primary/30 animate-cyber-pulse' : 'bg-secondary border-border/50'}`}>
                  <Cpu className={`h-4 w-4 ${state.pipelineStatus === 'processing' ? 'text-primary' : 'text-muted-foreground'}`} />
                </div>
                <div className="flex-1">
                  <p className="text-[10px] font-mono tracking-widest text-muted-foreground uppercase">CDR Buffer State</p>
                  <div className="flex items-center mt-0.5">
                    <span className={`text-lg font-mono font-semibold tracking-tight ${bufferTextColor}`}>
                      {bufferStateText}
                    </span>
                  </div>
                  <div className="mt-1 flex items-center">
                    <span className={`text-[9px] font-mono font-medium px-2 py-0.5 rounded-full uppercase tracking-wider ${bufferBadgeColor}`}>
                      {bufferBadgeText}
                    </span>
                  </div>
                </div>
              </div>
            </Card>

          </div>
        </div>
      </div>
    </header>
  )
}
