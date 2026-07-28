import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"

type AuditRow = {
  filename: string
  type: string
  uploadedBy: string
  riskLevel: "Low Risk" | "Medium Risk" | "Critical Risk"
  action: string
}

const auditRows: AuditRow[] = [
  {
    filename: "invoice_secure.pdf",
    type: "PDF",
    uploadedBy: "Alice Jhonson",
    riskLevel: "Low Risk",
    action: "Clean",
  },
  {
    filename: "resume_suspect.docx",
    type: "DOCX",
    uploadedBy: "Bob Smith",
    riskLevel: "Critical Risk",
    action: "Threat detected - file reconstructed",
  },
  {
    filename: "report.pdf",
    type: "PDF",
    uploadedBy: "Charlie",
    riskLevel: "Medium Risk",
    action: "File scanned successfully",
  },
]

function riskClass(level: AuditRow["riskLevel"]): string {
  if (level === "Low Risk") return "bg-green-500/15 text-green-400"
  if (level === "Critical Risk") return "bg-red-500/15 text-red-400"
  return "bg-amber-500/15 text-amber-400"
}

export function AuditLogsTable() {
  return (
    <Card className="glass-card p-6">
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <h3 className="text-xl font-semibold text-foreground">Audit Logs & Recent Scans</h3>
          <p className="text-sm text-muted-foreground">System activity monitoring</p>
        </div>
        <Button variant="outline" size="sm">
          View All Logs
        </Button>
      </div>

      <div className="overflow-x-auto rounded-md border border-border/40">
        <table className="w-full min-w-[760px] text-sm">
          <thead className="bg-secondary/40 text-left text-muted-foreground">
            <tr>
              <th className="px-4 py-3 font-medium">Filename</th>
              <th className="px-4 py-3 font-medium">Type</th>
              <th className="px-4 py-3 font-medium">Uploaded By</th>
              <th className="px-4 py-3 font-medium">Risk Level</th>
              <th className="px-4 py-3 font-medium">Action</th>
            </tr>
          </thead>
          <tbody>
            {auditRows.map((row) => (
              <tr key={`${row.filename}-${row.uploadedBy}`} className="border-t border-border/30">
                <td className="px-4 py-3 font-medium text-foreground">{row.filename}</td>
                <td className="px-4 py-3 text-muted-foreground">
                  <span className="rounded-md bg-secondary px-2 py-1 text-xs">{row.type}</span>
                </td>
                <td className="px-4 py-3 text-muted-foreground">{row.uploadedBy}</td>
                <td className="px-4 py-3">
                  <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${riskClass(row.riskLevel)}`}>
                    {row.riskLevel}
                  </span>
                </td>
                <td className="px-4 py-3 text-foreground">{row.action}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
