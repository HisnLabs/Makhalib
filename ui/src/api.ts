import type { RunDetail, RunSummary } from './types'

// Read-only: the server only returns reports that a previous `redteam` run wrote.
async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url)
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} for ${url}`)
  return res.json() as Promise<T>
}

export const listRuns = () => getJson<RunSummary[]>('/api/runs')

export const loadRun = (name: string) =>
  getJson<RunDetail>(`/api/runs/${encodeURIComponent(name)}`)
