import assert from 'node:assert/strict'
import test from 'node:test'
import { summarizeChallenges } from './challenges.mjs'

test('one row per connection shows TLS, request, and response separately', () => {
  const events = [
    { connection_id: 'one', result: 'attempted', client_ip: '192.0.2.8', sni: 'example.com', time: '2026-10-21T01:00:00Z' },
    { connection_id: 'one', result: 'handshake_completed', client_ip: '192.0.2.8', sni: 'example.com', time: '2026-10-21T01:00:01Z' },
    { connection_id: 'one', result: 'request', request_id: 'r1', time: '2026-10-21T01:00:02Z' },
    { connection_id: 'one', result: 'upstream_response', request_id: 'r1', status_code: 200, time: '2026-10-21T01:00:03Z' },
    { connection_id: 'two', result: 'attempted', client_ip: '192.0.2.8', sni: 'example.com', time: '2026-10-21T01:01:00Z' },
    { connection_id: 'two', result: 'handshake_completed', client_ip: '192.0.2.8', sni: 'example.com', time: '2026-10-21T01:01:01Z' }
  ]

  const rows = summarizeChallenges(events)
  assert.equal(rows.length, 2)
  assert.equal(rows[0].requestCount, 0)
  assert.equal(rows[0].result, 'handshake_completed')
  assert.equal(rows[1].requestCount, 1)
  assert.equal(rows[1].responseCount, 1)
  assert.equal(rows[1].lastStatus, 200)
})

test('earlier events without connection IDs combine start and result without guessing requests', () => {
  const rows = summarizeChallenges([
    { result: 'attempted', client_ip: '192.0.2.8', sni: 'example.com', time: '2026-10-21T01:00:00Z' },
    { result: 'handshake_completed', client_ip: '192.0.2.8', sni: 'example.com', time: '2026-10-21T01:00:01Z' },
    { result: 'request', client_ip: '192.0.2.8', sni: 'example.com', time: '2026-10-21T01:00:02Z' }
  ])

  assert.equal(rows.length, 1)
  assert.equal(rows[0].result, 'handshake_completed')
  assert.equal(rows[0].requestCount, null)
})
