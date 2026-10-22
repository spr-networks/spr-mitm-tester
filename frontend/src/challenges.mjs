const challengeResults = new Set([
  'attempted', 'handshake_completed', 'handshake_failed', 'disconnected_before_result'
])

export function summarizeChallenges(events) {
  const byConnection = new Map()
  const legacyPending = new Map()
  const rows = []

  for (const event of events) {
    const isChallenge = challengeResults.has(event.result)
    const key = event.connection_id ? `connection:${event.connection_id}` : null
    let row = key ? byConnection.get(key) : null

    if (!key && isChallenge && event.result !== 'attempted') {
      const pair = `${event.client_ip}\0${event.sni}`
      const pending = legacyPending.get(pair) || []
      row = pending.shift() || null
    }

    if (!row && isChallenge) {
      row = {
        key: key || `legacy:${rows.length}`,
        client_ip: event.client_ip,
        sni: event.sni,
        time: event.time,
        result: event.result,
        requestCount: key ? 0 : null,
        completedRequestCount: 0,
        requestIds: new Set(),
        completedRequestIds: new Set(),
        responseCount: 0,
        lastStatus: null,
        upstreamError: null,
        upstreamTls: false,
        protocolError: null,
        closed: false,
        protocol: null,
        clientDataBytes: 0,
        serverDataBytes: 0,
        clientDataMessages: 0,
        serverDataMessages: 0
      }
      rows.push(row)
      if (key) {
        byConnection.set(key, row)
      } else if (event.result === 'attempted') {
        const pair = `${event.client_ip}\0${event.sni}`
        const pending = legacyPending.get(pair) || []
        pending.push(row)
        legacyPending.set(pair, pending)
      }
    }

    if (!row) continue

    if (isChallenge && event.result !== 'attempted') {
      row.result = event.result
      row.time = event.time
    } else if (event.result === 'request_headers' || event.result === 'request_incomplete' || event.result === 'request') {
      if (!row.requestIds.has(event.request_id)) {
        row.requestIds.add(event.request_id)
        row.requestCount += 1
      }
      if (event.result === 'request' && !row.completedRequestIds.has(event.request_id)) {
        row.completedRequestIds.add(event.request_id)
        row.completedRequestCount += 1
      }
      if (event.result === 'request_incomplete') row.protocolError = event.detail || 'Request interrupted'
    } else if (event.result === 'upstream_response') {
      row.responseCount += 1
      row.lastStatus = event.status_code
    } else if (event.result === 'upstream_tls_completed') {
      row.upstreamTls = true
    } else if (event.result === 'upstream_tls_failed' || event.result === 'upstream_connect_failed') {
      row.upstreamError = event.detail || 'unknown error'
    } else if (event.result === 'http_error' || event.result === 'tcp_error') {
      row.protocolError = event.detail || 'unknown error'
    } else if (event.result === 'connection_closed') {
      row.closed = true
      if (event.detail && !row.protocolError) row.protocolError = event.detail
    } else if (event.result === 'websocket_opened' || event.result === 'tcp_opened') {
      row.protocol = event.result === 'websocket_opened' ? 'WebSocket' : 'TCP'
    } else if (event.result === 'websocket_message' || event.result === 'tcp_data') {
      row.protocol = event.result === 'websocket_message' ? 'WebSocket' : 'TCP'
      if (event.direction === 'client_to_server') {
        row.clientDataBytes += event.data_bytes || 0
        row.clientDataMessages += 1
      } else {
        row.serverDataBytes += event.data_bytes || 0
        row.serverDataMessages += 1
      }
    }
  }

  return rows.sort((a, b) => (b.time || '').localeCompare(a.time || ''))
}

export function summarizeRequests(events) {
  const ranks = { request_headers: 0, request_incomplete: 1, request: 2 }
  const byRequest = new Map()
  for (const event of events) {
    if (!(event.result in ranks) || !event.request_id) continue
    const previous = byRequest.get(event.request_id)
    if (!previous || ranks[event.result] >= ranks[previous.result]) {
      byRequest.set(event.request_id, event)
    }
  }
  return [...byRequest.values()].reverse()
}
