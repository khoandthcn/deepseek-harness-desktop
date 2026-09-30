import { describe, expect, it } from 'vitest'
import { buildAlertQuery } from '../src/query.ts'

describe('buildAlertQuery', () => {
  it('is empty with no filters', () => {
    expect(buildAlertQuery({})).toBe('')
  })

  it('joins severity and status', () => {
    expect(buildAlertQuery({ severity: 'high', status: 'NEW' })).toBe(
      'severity = "high" AND status = "NEW"',
    )
  })

  it('builds a bracketed time range', () => {
    expect(buildAlertQuery({ createdFrom: 100, createdTo: 200 })).toBe(
      '( created >= 100 AND created <= 200 )',
    )
  })

  it('combines a field and a time range', () => {
    expect(buildAlertQuery({ severity: 'high', createdFrom: 100, createdTo: 200 })).toBe(
      'severity = "high" AND ( created >= 100 AND created <= 200 )',
    )
  })

  it('passes a raw query on its own through exactly as written', () => {
    expect(buildAlertQuery({ rawQuery: 'custom = 1' })).toBe('custom = 1')
  })

  it('ANDs a raw query with the other filters instead of replacing them', () => {
    // It used to win outright: a period plus a raw tenant filter searched all
    // of time, silently, and every monthly count came out wrong.
    expect(buildAlertQuery({ rawQuery: 'tenant = "acme"', createdFrom: 10, createdTo: 20 }))
      .toBe('( tenant = "acme" ) AND ( created >= 10 AND created <= 20 )')
    expect(buildAlertQuery({ severity: 'high', rawQuery: 'custom = 1' }))
      .toBe('( custom = 1 ) AND severity = "high"')
  })

  it('parenthesises a raw query so an OR inside it cannot escape the period', () => {
    expect(buildAlertQuery({ rawQuery: 'a = 1 OR b = 2', createdFrom: 10 }))
      .toBe('( a = 1 OR b = 2 ) AND created >= 10')
  })

  it('escapes double quotes', () => {
    expect(buildAlertQuery({ severity: 'a"b' })).toBe('severity = "a\\"b"')
  })

  it('escapes backslashes before quotes', () => {
    // a\b -> a\\b in the DSL so the value cannot break out of the literal
    expect(buildAlertQuery({ severity: 'a\\b' })).toBe('severity = "a\\\\b"')
  })

  // Extra break-out coverage beyond the Python suite: a trailing backslash must
  // not escape the closing quote of the literal.
  it('escapes a trailing backslash', () => {
    expect(buildAlertQuery({ severity: 'a\\' })).toBe('severity = "a\\\\"')
  })

  it('escapes an already-escaped quote', () => {
    expect(buildAlertQuery({ status: '\\" OR 1=1' })).toBe('status = "\\\\\\" OR 1=1"')
  })

  // Python: created_from/created_to are independent, and 0 is a real bound.
  it('supports a lower bound only', () => {
    expect(buildAlertQuery({ createdFrom: 100 })).toBe('created >= 100')
  })

  it('supports an upper bound only', () => {
    expect(buildAlertQuery({ createdTo: 200 })).toBe('created <= 200')
  })

  it('treats 0 as a bound, not as absent', () => {
    expect(buildAlertQuery({ createdFrom: 0 })).toBe('created >= 0')
  })

  it('truncates float bounds to integers', () => {
    expect(buildAlertQuery({ createdFrom: 100.9, createdTo: 200.4 })).toBe(
      '( created >= 100 AND created <= 200 )',
    )
  })
})
