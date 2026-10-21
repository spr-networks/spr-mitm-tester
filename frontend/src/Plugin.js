import React, { useEffect, useState } from 'react'
import {
  api, Badge, BadgeText, Button, ButtonText, Card, HStack, ListHeader, Page,
  SectionHeader, Text, VStack
} from '@spr-networks/plugin-ui'

const PLUGIN_BASE = `/plugins/${api.pluginURI() || 'spr-mitm-tester'}`
const BRIDGE = 'mitmtst0'

const eventLabel = {
  attempted: 'Challenge started',
  handshake_completed: 'TLS handshake completed',
  handshake_failed: 'TLS handshake failed (inconclusive)',
  disconnected_before_result: 'Disconnected (inconclusive)'
}

export default function Plugin() {
  const [status, setStatus] = useState(null)
  const [topology, setTopology] = useState(null)
  const [events, setEvents] = useState([])
  const [expandedRequest, setExpandedRequest] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        const [nextStatus, nextTopology, nextEvents] = await Promise.all([
          api.get(`${PLUGIN_BASE}/status`),
          api.get(`${PLUGIN_BASE}/topology`),
          api.get(`${PLUGIN_BASE}/events`)
        ])
        if (!active) return
        setStatus(nextStatus)
        setTopology(nextTopology)
        setEvents(nextEvents || [])
        setError('')
      } catch (err) {
        if (active) setError(`Could not load MITM tester status: ${err.message}`)
      }
    }
    load()
    const timer = setInterval(load, 5000)
    return () => { active = false; clearInterval(timer) }
  }, [])

  const sink = topology?.Sinks?.find((item) => item.Iface === BRIDGE)
  const ready = Boolean(status?.ready && sink?.Online)
  const challenges = events.filter((event) => event.result !== 'request')
  const requests = events.filter((event) => event.result === 'request').reverse().slice(0, 20)

  return (
    <Page testID="mitm-tester-page">
      <ListHeader
        title="MITM tester"
        description="Challenge selected devices with an affected eMudhra intermediate on their normal TLS destinations"
        mark="CA"
        status={ready ? 'Sink ready' : 'Authority or proxy unavailable'}
        statusAction={ready ? 'success' : 'warning'}
      />
      <Card>
        <SectionHeader title="Forwarding sink" />
        <VStack space="sm">
          <Text>Bridge: {BRIDGE} · Sink IP: {sink?.IP || 'not detected'}</Text>
          <Text>Authority: {status?.authority
            ? `${status.authority.name} / ${status.authority.issued_by}`
            : 'No validated authority available; check container logs'}</Text>
          <Text>In SPR, create a forwarding rule for the devices you want to test. Select the MITM tester sink as the destination and limit the rule to TCP port 443 while preserving the original destination.</Text>
          <Text>For clients that prefer QUIC, add a separate UDP/443 block for those devices in SPR so they can fall back to TCP TLS.</Text>
          <Text>The plugin advertises the sink and records TLS results. Device selection and forwarding rules are managed in SPR.</Text>
          {error && <Text color="$red600">{error}</Text>}
        </VStack>
      </Card>
      <Card>
        <SectionHeader title="Recent TLS challenges" />
        <VStack space="sm">
          <Text>A completed forged-certificate handshake is evidence that this connection accepted the affected chain. A failed handshake is inconclusive.</Text>
          {challenges.length === 0 && <Text>No challenges recorded yet.</Text>}
          {[...challenges].reverse().slice(0, 50).map((event, index) => (
            <HStack key={`${event.time}-${index}`} space="sm" alignItems="center" justifyContent="space-between">
              <Text>{event.time} · {event.client_ip} · {event.sni}</Text>
              <Badge action={event.result === 'handshake_completed' ? 'error' : 'warning'} variant="outline">
                <BadgeText>{eventLabel[event.result] || event.result}</BadgeText>
              </Badge>
            </HStack>
          ))}
        </VStack>
      </Card>
      <Card>
        <SectionHeader title="Recent requests" count={requests.length} />
        <VStack space="md">
          <Text>Requests are shown after the device completes the TLS handshake. Bodies are streamed to the destination; the log keeps the first 8 KiB of each body.</Text>
          {requests.length === 0 && <Text>No requests captured yet.</Text>}
          {requests.map((request) => (
            <VStack key={request.request_id} space="xs">
              <HStack space="sm" alignItems="center" justifyContent="space-between">
                <VStack space="xs" flex={1}>
                  <Text fontWeight="bold" sx={{ '@base': { overflowWrap: 'anywhere' } }}>
                    {request.method} {request.url}{request.url_truncated ? '…' : ''}
                  </Text>
                  <Text size="sm">{request.time} · {request.client_ip} · {request.sni}</Text>
                </VStack>
                <Button size="xs" variant="outline" onPress={() => setExpandedRequest(
                  expandedRequest === request.request_id ? null : request.request_id
                )}>
                  <ButtonText>{expandedRequest === request.request_id ? 'Hide details' : 'View details'}</ButtonText>
                </Button>
              </HStack>
              {expandedRequest === request.request_id && (
                <VStack space="xs">
                  <Text fontWeight="bold">Headers{request.headers_truncated ? ' (truncated)' : ''}</Text>
                  {(request.headers || []).map(([name, value], index) => (
                    <Text key={`${name}-${index}`} size="sm" fontFamily="$mono" selectable sx={{ '@base': { overflowWrap: 'anywhere' } }}>
                      {name}: {value}
                    </Text>
                  ))}
                  <Text fontWeight="bold">Body · {request.body_bytes || 0} bytes{request.body_truncated ? ' (preview truncated)' : ''}</Text>
                  {request.body_bytes > 0 && (
                    <Text size="sm" fontFamily="$mono" selectable sx={{ '@base': { whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' } }}>
                      {request.body_encoding === 'base64' ? 'Base64: ' : ''}{request.body_preview}
                    </Text>
                  )}
                  {!request.body_bytes && <Text size="sm">No request body.</Text>}
                </VStack>
              )}
            </VStack>
          ))}
        </VStack>
      </Card>
    </Page>
  )
}
