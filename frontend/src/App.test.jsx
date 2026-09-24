import { describe, expect, it } from 'vitest'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import App, { mergeAlerts } from './App.jsx'

const alert = { alert_id: 'ALT-1', timestamp: '2026-09-24T12:00:00Z', threat_class: 'Observed threat', evidence: { reason: 'backend evidence' } }

describe('dashboard', () => {
  it('renders the dashboard shell and empty alert state', () => {
    const html = renderToStaticMarkup(<App />)
    expect(html).toContain('SPECTRA')
    expect(html).toContain('No alerts have been delivered.')
  })

  it('merges repeated alert IDs without duplicating rows and retains the received payload', () => {
    const merged = mergeAlerts([], [alert, alert])
    expect(merged).toHaveLength(1)
    expect(merged[0]).toBe(alert)
  })
})
