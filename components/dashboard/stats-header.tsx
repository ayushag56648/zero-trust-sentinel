"use client"

import { Shield, FileCheck, AlertTriangle, Activity } from "lucide-react"
import { Card } from "@/components/ui/card"

const stats = [
  {
    label: "Total Files Processed",
    value: "1,245",
    icon: FileCheck,
    trend: "+12% this week",
    color: "text-primary",
  },
  {
    label: "Threats Neutralized",
    value: "312",
    icon: AlertTriangle,
    trend: "23 in last 24h",
    color: "text-amber-warning",
  },
  {
    label: "System Status",
    value: "100%",
    subtitle: "0 False Negatives",
    icon: Activity,
    isStatus: true,
  },
]

export function StatsHeader() {
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

          {/* Stats Cards */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            {stats.map((stat) => (
              <Card
                key={stat.label}
                className={`glass-card px-4 py-3 ${
                  stat.isStatus ? "glass-card-glow" : ""
                }`}
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`flex h-9 w-9 items-center justify-center rounded-md ${
                      stat.isStatus
                        ? "bg-primary/20 animate-cyber-pulse"
                        : "bg-secondary"
                    }`}
                  >
                    <stat.icon
                      className={`h-5 w-5 ${
                        stat.isStatus ? "text-primary" : stat.color
                      }`}
                    />
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">{stat.label}</p>
                    <div className="flex items-baseline gap-2">
                      <span
                        className={`text-lg font-semibold ${
                          stat.isStatus ? "text-primary" : "text-foreground"
                        }`}
                      >
                        {stat.value}
                        {stat.isStatus && (
                          <span className="ml-1 text-xs font-normal text-primary/80">
                            Protection
                          </span>
                        )}
                      </span>
                    </div>
                    {stat.subtitle && (
                      <p className="text-xs text-primary/70">{stat.subtitle}</p>
                    )}
                    {stat.trend && (
                      <p className="text-xs text-muted-foreground">{stat.trend}</p>
                    )}
                  </div>
                </div>
              </Card>
            ))}
          </div>
        </div>
      </div>
    </header>
  )
}
