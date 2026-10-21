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
