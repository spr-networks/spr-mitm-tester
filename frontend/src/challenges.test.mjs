import assert from 'node:assert/strict'
import test from 'node:test'
import { summarizeChallenges, summarizeRequests } from './challenges.mjs'

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

test('WebSocket and TCP data are attributed to their own TLS connections', () => {
  const rows = summarizeChallenges([
    { connection_id: 'ws', result: 'handshake_completed', client_ip: '192.0.2.8', sni: 'ws.example', time: '2026-10-21T01:00:00Z' },
    { connection_id: 'ws', result: 'websocket_opened', time: '2026-10-21T01:00:01Z' },
    { connection_id: 'ws', result: 'websocket_message', direction: 'client_to_server', data_bytes: 17, time: '2026-10-21T01:00:02Z' },
    { connection_id: 'ws', result: 'websocket_message', direction: 'server_to_client', data_bytes: 8, time: '2026-10-21T01:00:03Z' },
    { connection_id: 'tcp', result: 'handshake_completed', client_ip: '192.0.2.8', sni: 'broker.example', time: '2026-10-21T01:01:00Z' },
    { connection_id: 'tcp', result: 'tcp_opened', time: '2026-10-21T01:01:01Z' },
    { connection_id: 'tcp', result: 'tcp_data', direction: 'client_to_server', data_bytes: 5, time: '2026-10-21T01:01:02Z' }
  ])

  assert.equal(rows.length, 2)
  assert.equal(rows[0].protocol, 'TCP')
  assert.equal(rows[0].clientDataBytes, 5)
  assert.equal(rows[0].requestCount, 0)
  assert.equal(rows[1].protocol, 'WebSocket')
  assert.equal(rows[1].clientDataBytes, 17)
  assert.equal(rows[1].serverDataBytes, 8)
})

test('upstream TLS failure is shown on the matching accepted client connection', () => {
  const rows = summarizeChallenges([
    { connection_id: 'one', result: 'attempted', client_ip: '192.0.2.8', sni: 'diag.meethue.com', time: '2026-10-21T01:00:00Z' },
    { connection_id: 'one', result: 'upstream_tls_failed', detail: 'certificate verify failed', time: '2026-10-21T01:00:01Z' },
    { connection_id: 'one', result: 'handshake_completed', time: '2026-10-21T01:00:02Z' }
  ])

  assert.equal(rows.length, 1)
  assert.equal(rows[0].result, 'handshake_completed')
  assert.equal(rows[0].upstreamError, 'certificate verify failed')
})

test('header-only and interrupted requests remain visible without double-counting', () => {
  const events = [
    { connection_id: 'one', result: 'attempted', client_ip: '192.0.2.8', sni: 'diag.meethue.com', time: '2026-10-21T01:00:00Z' },
    { connection_id: 'one', result: 'upstream_tls_completed', time: '2026-10-21T01:00:01Z' },
    { connection_id: 'one', result: 'handshake_completed', time: '2026-10-21T01:00:02Z' },
    { connection_id: 'one', result: 'request_headers', request_id: 'r1', method: 'POST', url: 'https://diag.meethue.com/', time: '2026-10-21T01:00:03Z' },
    { connection_id: 'one', result: 'request_incomplete', request_id: 'r1', detail: 'connection closed', time: '2026-10-21T01:00:04Z' },
    { connection_id: 'one', result: 'connection_closed', time: '2026-10-21T01:00:05Z' }
  ]
  const row = summarizeChallenges(events)[0]
  assert.equal(row.requestCount, 1)
  assert.equal(row.completedRequestCount, 0)
  assert.equal(row.upstreamTls, true)
  assert.equal(row.closed, true)
  assert.equal(row.protocolError, 'connection closed')
  assert.equal(summarizeRequests(events)[0].result, 'request_incomplete')
})

test('completed request replaces its headers preview', () => {
  const events = [
    { connection_id: 'one', result: 'handshake_completed', client_ip: '192.0.2.8', sni: 'example.com', time: '2026-10-21T01:00:00Z' },
    { connection_id: 'one', result: 'request_headers', request_id: 'r1', time: '2026-10-21T01:00:01Z' },
    { connection_id: 'one', result: 'request', request_id: 'r1', body_bytes: 15, time: '2026-10-21T01:00:02Z' }
  ]
  const row = summarizeChallenges(events)[0]
  assert.equal(row.requestCount, 1)
  assert.equal(row.completedRequestCount, 1)
  assert.equal(summarizeRequests(events)[0].result, 'request')
})
