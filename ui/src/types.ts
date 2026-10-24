export interface RunSummary {
  name: string
  endpoint: string
  total: number
  bypassed: number
  bypass_rate: number
}

export interface Finding {
  id: string
  category: string
  seed: string
  mutations: string[]
  final_text: string
  success_rate: number
  severity: string
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

export interface Scorecard {
  bypass_rate: number
  over_block_rate: number
  benign_total: number
  over_blocked: number
}