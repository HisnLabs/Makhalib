import { defineComponent, onMounted, onUnmounted, ref, computed } from 'vue'
import { listRuns, loadRun } from './api'
import type { RunDetail, RunSummary } from './types'

interface LiveEvent {
  phase: string
  depth?: number
  prompt: string
  category?: string
  mutations?: string[]
  score: number
  bypass: boolean
  tokens?: number
  tokens_used?: number
  token_limit?: number
  guardrail?: string
}

// The guardrail returns JSON; show it pretty-printed when it parses, else raw.
const pretty = (raw: string) => {
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}

const pct = (x: number) => `${(x * 100).toFixed(1)}%`

export default defineComponent({
  name: 'App',
  setup() {
    const runs = ref<RunSummary[]>([])
    const active = ref<string>('')
    const detail = ref<RunDetail | null>(null)
    const error = ref<string>('')
    const live = ref<LiveEvent[]>([])
    const liveDone = ref(false)
    let since = 0
    let timer: number | undefined

    const select = async (name: string) => {
      active.value = name
      error.value = ''
      try {
        detail.value = await loadRun(name)
      } catch (e) {
        error.value = String(e)
      }
    }

    // Poll the progress log so attacks appear as the search runs.
    const pollLive = async () => {
      if (!active.value) return
      try {
        const res = await fetch(`/api/live/${encodeURIComponent(active.value)}?since=${since}`)
        if (!res.ok) return
        const body = await res.json()
        if (body.since !== since) return
        live.value = live.value.concat(body.events as LiveEvent[])
        since = body.total
        liveDone.value = body.done
      } catch {
        /* server may be restarting; retry on the next tick */
      }
    }

    const resetLive = () => {
      live.value = []
      since = 0
      liveDone.value = false
    }

    onMounted(async () => {
      try {
        runs.value = await listRuns()
        if (runs.value.length) await select(runs.value[0].name)
      } catch (e) {
        error.value = String(e)
      }
      timer = window.setInterval(pollLive, 1000)
    })
    onUnmounted(() => window.clearInterval(timer))

    const report = computed(() => detail.value?.report)

    return () => (
      <div class="shell">
        <aside class="side">
          <div class="brand">
            Makha<span>lib</span>
          </div>
          <h4>Runs</h4>
          {runs.value.length === 0 && <p class="muted">No runs yet. Run a redteam first.</p>}
          {runs.value.map((r) => (
            <button
              class={['run', active.value === r.name ? 'active' : '']}
              onClick={() => {
                resetLive()
                select(r.name)
              }}
            >
              {r.name}
              <small>
                {r.bypassed}/{r.total} bypassed · {pct(r.bypass_rate)}
              </small>
            </button>
          ))}
        </aside>

        <main class="main">
          <div class="head">
            <h1>Guardrail red-team results</h1>
            <p>{detail.value ? `${detail.value.report.meta.endpoint} · ${detail.value.report.meta.notes}` : 'Select a run'}</p>
          </div>

          {error.value && <p class="error">{error.value}</p>}

          {report.value && (
            <>
              <div class="grid-kpi">
                <div class="card kpi">
                  <div class="label">Attempts</div>
                  <div class="value">{report.value.total}</div>
                </div>
                <div class="card kpi">
                  <div class="label">Bypassed</div>
                  <div class="value bad">{report.value.bypassed}</div>
                </div>
                <div class="card kpi">
                  <div class="label">Blocked</div>
                  <div class="value good">{report.value.blocked}</div>
                </div>
                <div class="card kpi">
                  <div class="label">Bypass rate</div>
                  <div class="value">{pct(report.value.bypass_rate)}</div>
                </div>
              </div>

              <div class="row">
                <div class="card">
                  <h3>By obfuscation</h3>
                  {Object.entries(report.value.per_mutation).map(([m, [hit, tot]]) => (
                    <div class="bar-row">
                      <span>{m}</span>
                      <div class="bar-track">
                        <div class={['bar-fill', hit / tot >= 0.5 ? 'hot' : '']} style={{ width: `${(hit / tot) * 100}%` }} />
                      </div>
                      <span class="muted">
                        {hit}/{tot}
                      </span>
                    </div>
                  ))}
                </div>
                <div class="card">
                  <h3>By category</h3>
                  {Object.entries(report.value.per_category).map(([c, [hit, tot]]) => (
                    <div class="bar-row">
                      <span>{c}</span>
                      <div class="bar-track">
                        <div class={['bar-fill', hit / tot >= 0.5 ? 'hot' : '']} style={{ width: `${(hit / tot) * 100}%` }} />
                      </div>
                      <span class="muted">
                        {hit}/{tot}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div class="card" style={{ marginTop: '16px' }}>
                <h3>Findings ({report.value.findings.length})</h3>
                <table>
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Category</th>
                      <th>Mutations</th>
                      <th>Prompt</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.value.findings.map((f) => (
                      <tr>
                        <td>
                          <span class={['pill', `sev-${f.severity}`]}>{f.severity}</span>
                        </td>
                        <td>{f.category}</td>
                        <td class="muted">{f.mutations.join(', ') || '—'}</td>
                        <td class="text-cell">{f.final_text}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          <div class="card" style={{ marginTop: '16px' }}>
            <h3>
              Live attack feed {liveDone.value ? '· finished' : '· running'} ({live.value.length} events)
            </h3>
            {live.value.length > 0 && (
              <p class="muted">
                Tokens used: {live.value[live.value.length - 1].tokens_used ?? 0}
                {live.value[live.value.length - 1].token_limit
                  ? ` / ${live.value[live.value.length - 1].token_limit}`
                  : ' (unlimited)'}
              </p>
            )}
            {live.value.length === 0 && <p class="empty">No live events for this run.</p>}
            {live.value.slice(-200).map((e) => (
              <div class="bar-row">
                <span class="muted">
                  {e.phase}
                  {e.depth !== undefined ? ` d${e.depth}` : ''}
                </span>
                <div class="bar-track">
                  <div class={['bar-fill', e.bypass ? 'hot' : '']} style={{ width: `${Math.min(e.score, 1) * 100}%` }} />
                </div>
                <span class={e.bypass ? 'pill sev-Critical' : 'muted'}>{e.bypass ? 'BYPASS' : pct(e.score)}</span>
                <span class="muted">{e.tokens ?? 0} tok</span>
                <details class="text-cell" style={{ gridColumn: '1 / -1' }}>
                  <summary>{e.prompt}</summary>
                  <pre class="scorecard">{pretty(e.guardrail ?? '')}</pre>
                </details>
              </div>
            ))}
          </div>
        </main>
      </div>
    )
  },
})
