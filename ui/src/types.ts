export interface RunSummary {
  name: string
  started: string
  endpoint: string
  total: number
  bypassed: number
  bypass_rate: number
  has_scorecard: boolean
}

export interface Finding {
  id: string
  category: string
  severity: string
  success_rate: number
  mutations: string[]
  final_text: string
}

export interface RunReport {
  total: number
  bypassed: number
  blocked: number
  errored: number
  bypass_rate: number
  per_category: Record<string, [number, number]>
  per_mutation: Record<string, [number, number]>
  meta: { target: string; endpoint: string; harness: string; started: string; notes: string }
  findings: Finding[]
}

export interface RunDetail {
  name: string
  report: RunReport
  scorecard: string
}
