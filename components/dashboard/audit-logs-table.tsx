"use client"

import { FileText, FileSpreadsheet, MoreHorizontal } from "lucide-react"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Button } from "@/components/ui/button"

const auditLogs = [
  {
    id: 1,
    filename: "invoice_secure.pdf",
    fileType: "PDF",
    uploadedBy: "Alice Johnson",
    riskLevel: "low",
    action: "Clean",
    timestamp: "2 min ago",
  },
  {
    id: 2,
    filename: "resume_suspect.docx",
    fileType: "DOCX",
    uploadedBy: "Bob Smith",
    riskLevel: "critical",
    action: "Threat detected — file reconstructed",
    timestamp: "15 min ago",
  },
  {
    id: 3,
    filename: "report.pdf",
    fileType: "PDF",
    uploadedBy: "Charlie",
    riskLevel: "medium",
    action: "File scanned successfully",
    timestamp: "1 hour ago",
  },
]

function getRiskBadge(risk: string) {
  switch (risk) {
    case "low":
      return (
        <Badge className="bg-primary/20 text-primary hover:bg-primary/30 border-0">
          Low Risk
        </Badge>
      )
    case "medium":
      return (
        <Badge className="bg-amber-warning/20 text-amber-warning hover:bg-amber-warning/30 border-0">
          Medium Risk
        </Badge>
      )
    case "critical":
      return (
        <Badge className="bg-critical-red/20 text-critical-red hover:bg-critical-red/30 border-0">
          Critical Risk
        </Badge>
      )
    default:
      return null
  }
}

function getFileIcon(type: string) {
  switch (type) {
    case "PDF":
      return <FileText className="h-4 w-4 text-critical-red" />
    case "DOCX":
      return <FileSpreadsheet className="h-4 w-4 text-blue-400" />
    default:
      return <FileText className="h-4 w-4 text-muted-foreground" />
  }
}

export function AuditLogsTable() {
  return (
    <Card className="glass-card overflow-hidden">
      <div className="border-b border-border/50 px-6 py-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-foreground">
              Audit Logs & Recent Scans
            </h2>
            <p className="text-xs text-muted-foreground">
              System activity monitoring
            </p>
          </div>
          <Button variant="outline" size="sm" className="text-xs">
            View All Logs
          </Button>
        </div>
      </div>

      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow className="border-border/50 hover:bg-transparent">
              <TableHead className="text-xs font-medium text-muted-foreground">
                Filename
              </TableHead>
              <TableHead className="text-xs font-medium text-muted-foreground">
                Type
              </TableHead>
              <TableHead className="text-xs font-medium text-muted-foreground">
                Uploaded By
              </TableHead>
              <TableHead className="text-xs font-medium text-muted-foreground">
                Risk Level
              </TableHead>
              <TableHead className="text-xs font-medium text-muted-foreground">
                Action
              </TableHead>
              <TableHead className="text-xs font-medium text-muted-foreground text-right">
                Time
              </TableHead>
              <TableHead className="w-[50px]"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {auditLogs.map((log) => (
              <TableRow
                key={log.id}
                className="border-border/30 hover:bg-secondary/30"
              >
                <TableCell>
                  <div className="flex items-center gap-2">
                    {getFileIcon(log.fileType)}
                    <span className="text-sm font-medium text-foreground">
                      {log.filename}
                    </span>
                  </div>
                </TableCell>
                <TableCell>
                  <span className="rounded bg-secondary px-2 py-1 text-xs text-muted-foreground">
                    {log.fileType}
                  </span>
                </TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {log.uploadedBy}
                </TableCell>
                <TableCell>{getRiskBadge(log.riskLevel)}</TableCell>
                <TableCell>
                  <span
                    className={`text-sm ${
                      log.riskLevel === "critical"
                        ? "text-amber-warning"
                        : log.riskLevel === "low"
                        ? "text-primary"
                        : "text-foreground"
                    }`}
                  >
                    {log.action}
                  </span>
                </TableCell>
                <TableCell className="text-right text-xs text-muted-foreground">
                  {log.timestamp}
                </TableCell>
                <TableCell>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 text-muted-foreground hover:text-foreground"
                  >
                    <MoreHorizontal className="h-4 w-4" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </Card>
  )
}
