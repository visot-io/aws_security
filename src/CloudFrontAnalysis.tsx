import { useState } from 'react'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Shield, ShieldAlert, CloudCog } from "lucide-react"

interface CloudFrontCheck {
  type: string
  resource: string
  status: 'ok' | 'alarm' | 'skip'
  reason: string
  region?: string
  account?: string
  timestamp?: string
}

interface StatusCount {
  ok: number
  alarm: number
  skip: number
}

interface ChecksByType {
  [key: string]: CloudFrontCheck[]
}

export function CloudFrontAnalysis() {
  const [checks, setChecks] = useState<CloudFrontCheck[]>([])
  const [checksByType, setChecksByType] = useState<ChecksByType>({})
  const [error, setError] = useState<string>('')
  const [loading, setLoading] = useState(false)
  const [statusCounts, setStatusCounts] = useState<StatusCount>({ ok: 0, alarm: 0, skip: 0 })

  const fetchComprehensiveChecks = async () => {
    setLoading(true)
    setError('')
    try {
      const response = await fetch(`${import.meta.env.VITE_API_URL}/api/cloudfront/comprehensive-checks`)
      if (!response.ok) {
        throw new Error('Failed to fetch CloudFront security checks')
      }
      const data: CloudFrontCheck[] = await response.json()
      setChecks(data)
      
      // Group checks by type
      const grouped = data.reduce((acc: ChecksByType, check) => {
        if (!acc[check.type]) {
          acc[check.type] = []
        }
        acc[check.type].push(check)
        return acc
      }, {})
      setChecksByType(grouped)
      
      // Calculate overall status counts
      const counts = data.reduce((acc: StatusCount, check) => {
        acc[check.status]++
        return acc
      }, { ok: 0, alarm: 0, skip: 0 })
      setStatusCounts(counts)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="container mx-auto py-8">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">CloudFront Security Analysis</h1>
        <Button 
          onClick={fetchComprehensiveChecks}
          disabled={loading}
          className="flex items-center gap-2"
        >
          <CloudCog className="h-5 w-5" />
          {loading ? 'Loading...' : 'Analyze CloudFront'}
        </Button>
      </div>

      {error && (
        <Alert variant="destructive" className="mb-6">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="grid grid-cols-3 gap-4 mb-6">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-green-500 flex items-center gap-2">
              <Shield className="h-5 w-5" />
              OK
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{statusCounts.ok}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-red-500 flex items-center gap-2">
              <ShieldAlert className="h-5 w-5" />
              Alarm
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{statusCounts.alarm}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-gray-500 flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Skip
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{statusCounts.skip}</p>
          </CardContent>
        </Card>
      </div>

      {Object.entries(checksByType).map(([type, typeChecks]) => (
        <div key={type} className="mb-8">
          <h2 className="text-xl font-semibold mb-4">{type.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}</h2>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Resource</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="w-full">Details</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {typeChecks.map((check) => (
                  <TableRow key={`${check.type}-${check.resource}`}>
                    <TableCell className="font-medium">{check.resource.split('/').pop()}</TableCell>
                    <TableCell>
                      {check.status === 'ok' ? (
                        <Shield className="text-green-500" />
                      ) : check.status === 'alarm' ? (
                        <ShieldAlert className="text-red-500" />
                      ) : (
                        <Shield className="text-gray-500" />
                      )}
                    </TableCell>
                    <TableCell>{check.reason}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      ))}
    </div>
  )
}
