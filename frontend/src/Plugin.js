import React, { useEffect, useState } from 'react'
import {
  api, Badge, BadgeText, Button, ButtonText, Card, HStack, Link, LinkText,
  ListHeader, Page, SectionHeader, Text, Toggle, VStack
} from '@spr-networks/plugin-ui'
import { summarizeChallenges, summarizeRequests } from './challenges.mjs'

const PLUGIN_BASE = `/plugins/${api.pluginURI() || 'spr-mitm-tester'}`
const BRIDGE = 'mitmtst0'

const eventLabel = {
  attempted: 'Connecting',
  handshake_completed: 'TLS handshake completed',
  handshake_failed: 'TLS handshake failed',
  disconnected_before_result: 'Disconnected before handshake'
}

const formatTime = (value) => {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

export default function Plugin() {
  const [status, setStatus] = useState(null)
  const [topology, setTopology] = useState(null)
  const [events, setEvents] = useState([])
  const [expandedRequest, setExpandedRequest] = useState(null)
  const [expandedData, setExpandedData] = useState(null)
  const [error, setError] = useState('')
  const [settingsError, setSettingsError] = useState('')
  const [savingSettings, setSavingSettings] = useState(false)

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

  const toggleUpstreamVerification = async () => {
    if (savingSettings || typeof status?.configured_verify_upstream_tls !== 'boolean') return
    const verify_upstream_tls = !status.configured_verify_upstream_tls
    setSavingSettings(true)
    setSettingsError('')
    try {
      await api.put(`${PLUGIN_BASE}/settings`, { verify_upstream_tls })
      setStatus((current) => ({ ...current, configured_verify_upstream_tls: verify_upstream_tls }))
    } catch (err) {
      setSettingsError(`Could not save upstream TLS setting: ${err.message}`)
    } finally {
      setSavingSettings(false)
    }
  }

  const toggleLegacyChain = async () => {
    if (savingSettings || typeof status?.configured_emudhra_old !== 'boolean') return
    const emudhra_old = !status.configured_emudhra_old
    setSavingSettings(true)
    setSettingsError('')
    try {
      await api.put(`${PLUGIN_BASE}/settings`, { emudhra_old })
      setStatus((current) => ({ ...current, configured_emudhra_old: emudhra_old }))
    } catch (err) {
      setSettingsError(`Could not save eMudhra chain setting: ${err.message}`)
    } finally {
      setSavingSettings(false)
    }
  }

  const sink = topology?.Sinks?.find((item) => item.Iface === BRIDGE)
  const ready = Boolean(status?.ready && sink?.Online)
  const sprHost = typeof window === 'undefined' ? 'SPR_HOST' : window.location.hostname
  const webToken = status?.mitmweb?.token
  const webUrl = webToken ? `http://127.0.0.1:18081/?token=${encodeURIComponent(webToken)}` : ''
  const challenges = summarizeChallenges(events).slice(0, 50)
  const requests = summarizeRequests(events).slice(0, 20)
  const dataEvents = events.filter((event) => event.result === 'websocket_message' || event.result === 'tcp_data')
    .reverse().slice(0, 20)
  const responses = new Map(events.filter((event) => event.result === 'upstream_response')
    .map((event) => [event.request_id, event.status_code]))

  return (
    <Page testID="mitm-tester-page">
      <ListHeader
        title="MITM tester"
        mark="CA"
        status={ready ? 'Sink ready' : 'Authority or proxy unavailable'}
        statusAction={ready ? 'success' : 'warning'}
      />
      <Card>
        <SectionHeader title="Sink" />
        <VStack space="sm">
          <Text>Bridge: {BRIDGE} · Sink IP: {sink?.IP || 'not detected'}</Text>
          <Text>Authority: {status?.authority
            ? `${status.authority.name} / ${status.authority.issued_by}`
            : 'No validated authority available; check container logs'}</Text>
          <HStack alignItems="center" justifyContent="space-between" space="md">
            <VStack flex={1} space="xs">
              <Text>Verify destination certificates</Text>
              <Text size="sm">Turn off to accept any server certificate. Applies to new connections.</Text>
            </VStack>
            <Toggle
              value={status?.configured_verify_upstream_tls !== false}
              label="Verify destination certificates"
              onPress={toggleUpstreamVerification}
              disabled={savingSettings || typeof status?.configured_verify_upstream_tls !== 'boolean'}
            />
          </HStack>
          <HStack alignItems="center" justifyContent="space-between" space="md">
            <VStack flex={1} space="xs">
              <Text>Prefer legacy eMudhra chain</Text>
              <Text size="sm">Send the AAA Certificate Services cross-sign first for older trust stores. Applies to new connections.</Text>
            </VStack>
            <Toggle
              value={status?.configured_emudhra_old === true}
              label="Prefer legacy eMudhra chain"
              onPress={toggleLegacyChain}
              disabled={savingSettings || typeof status?.configured_emudhra_old !== 'boolean'}
            />
          </HStack>
          {status && status.verify_upstream_tls !== status.configured_verify_upstream_tls &&
            <Text size="sm">Applying upstream TLS setting…</Text>}
          {status && status.emudhra_old !== status.configured_emudhra_old &&
            <Text size="sm">Applying eMudhra chain setting…</Text>}
          {settingsError && <Text color="$red600">{settingsError}</Text>}
          <Text>Select mitm-tester as a route destination in Topology.</Text>
          <Link isExternal href="https://192.168.2.1/admin/topology">
            <LinkText>Open Topology</LinkText>
          </Link>
          {error && <Text color="$red600">{error}</Text>}
        </VStack>
      </Card>
      <Card>
        <SectionHeader title="mitmproxy flow view" />
        <VStack space="sm">
          <Text>Run this SSH tunnel on your computer:</Text>
          <Text fontFamily="$mono" selectable sx={{ '@base': { overflowWrap: 'anywhere' } }}>
            ssh -N -L 127.0.0.1:18081:{sink?.IP || 'SINK_IP'}:8081 root@{sprHost}
          </Text>
          {status?.mitmweb?.ready && webUrl
            ? <Link isExternal href={webUrl}><LinkText>Open mitmproxy</LinkText></Link>
            : <Text size="sm">mitmproxy flow view is starting or unavailable.</Text>}
        </VStack>
      </Card>
      <Card>
        <SectionHeader title="Recent connections" />
        <VStack space="sm">
          {challenges.length === 0 && <Text>No connections recorded yet.</Text>}
          {challenges.map((event) => (
            <HStack key={event.key} space="sm" alignItems="center" justifyContent="space-between">
              <VStack space="xs" flex={1}>
                <Text fontWeight="bold">{event.client_ip} · {event.sni}</Text>
                <Text size="sm">{formatTime(event.time)}</Text>
              </VStack>
              <VStack space="xs" alignItems="flex-end">
                <Badge action={event.result === 'handshake_completed' ? 'success' : 'warning'} variant="outline">
                  <BadgeText>{eventLabel[event.result] || event.result}</BadgeText>
                </Badge>
                {event.upstreamError && <Text size="sm">Destination connection failed: {event.upstreamError}</Text>}
                {event.protocolError && <Text size="sm">Connection error: {event.protocolError}</Text>}
                {event.result === 'handshake_completed' && event.requestCount === null &&
                  <Text size="sm">Older record · data not linked</Text>}
                {event.result === 'handshake_completed' && event.requestCount !== null && (
                  <>
                    {event.requestCount > 0 && <Text size="sm">Device started {event.requestCount} HTTP request{event.requestCount === 1 ? '' : 's'}{event.completedRequestCount < event.requestCount ? ' · incomplete' : ''}</Text>}
                    {event.clientDataBytes > 0 && <Text size="sm">Device sent {event.clientDataBytes} bytes over {event.protocol}</Text>}
                    {event.serverDataBytes > 0 && <Text size="sm">Server sent {event.serverDataBytes} bytes over {event.protocol}</Text>}
                    {!event.upstreamError && !event.protocolError && event.requestCount === 0 && event.clientDataBytes === 0 && event.serverDataBytes === 0 &&
                      <Text size="sm">{event.closed ? 'Connection closed without a parsed request or data' : 'No application data recorded yet'}{event.upstreamTls ? ' · destination TLS completed' : ''}</Text>}
                  </>
                )}
                {event.responseCount > 0 && <Text size="sm">Destination replied · HTTP {event.lastStatus}</Text>}
              </VStack>
            </HStack>
          ))}
        </VStack>
      </Card>
      <Card>
        <SectionHeader title="HTTP requests" count={requests.length} />
        <VStack space="md">
          {requests.length === 0 && <Text>No HTTP request headers captured yet.</Text>}
          {requests.map((request) => (
            <VStack key={request.request_id} space="xs">
              <HStack space="sm" alignItems="center" justifyContent="space-between">
                <VStack space="xs" flex={1}>
                  <Text fontWeight="bold" sx={{ '@base': { overflowWrap: 'anywhere' } }}>
                    {request.method} {request.url}{request.url_truncated ? '…' : ''}
                  </Text>
                  <Text size="sm">{formatTime(request.time)} · {request.client_ip} · {request.sni}</Text>
                  {request.result === 'request_headers' && <Text size="sm">Headers received · request not complete</Text>}
                  {request.result === 'request_incomplete' && <Text size="sm">Request interrupted: {request.detail}</Text>}
                  {responses.has(request.request_id) && <Text size="sm">Destination replied · HTTP {responses.get(request.request_id)}</Text>}
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
                  {request.result !== 'request_headers' && <Text fontWeight="bold">Body · {request.body_bytes || 0} bytes{request.body_truncated ? ' (preview truncated)' : ''}</Text>}
                  {request.body_bytes > 0 && (
                    <Text size="sm" fontFamily="$mono" selectable sx={{ '@base': { whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' } }}>
                      {request.body_encoding === 'base64' ? 'Base64: ' : ''}{request.body_preview}
                    </Text>
                  )}
                  {request.result !== 'request_headers' && !request.body_bytes && <Text size="sm">No request body.</Text>}
                </VStack>
              )}
            </VStack>
          ))}
        </VStack>
      </Card>
      <Card>
        <SectionHeader title="WebSocket and TCP data" count={dataEvents.length} />
        <VStack space="md">
          {dataEvents.length === 0 && <Text>No WebSocket or TCP data captured yet.</Text>}
          {dataEvents.map((event, index) => {
            const eventKey = `${event.time}-${index}`
            const protocol = event.result === 'websocket_message' ? 'WebSocket' : 'TCP'
            const direction = event.direction === 'client_to_server' ? 'Device → server' : 'Server → device'
            return (
              <VStack key={eventKey} space="xs">
                <HStack space="sm" alignItems="center" justifyContent="space-between">
                  <VStack space="xs" flex={1}>
                    <Text fontWeight="bold">{protocol}{event.message_type ? ` ${event.message_type}` : ''} · {direction} · {event.data_bytes} bytes</Text>
                    <Text size="sm">{formatTime(event.time)} · {event.client_ip} · {event.sni}</Text>
                  </VStack>
                  <Button size="xs" variant="outline" onPress={() => setExpandedData(
                    expandedData === eventKey ? null : eventKey
                  )}>
                    <ButtonText>{expandedData === eventKey ? 'Hide data' : 'View data'}</ButtonText>
                  </Button>
                </HStack>
                {expandedData === eventKey && (
                  <VStack space="xs">
                    <Text fontWeight="bold">Data preview{event.data_truncated ? ' (truncated)' : ''}</Text>
                    <Text size="sm" fontFamily="$mono" selectable sx={{ '@base': { whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' } }}>
                      {event.data_encoding === 'base64' ? 'Base64: ' : ''}{event.data_preview || '(empty)'}
                    </Text>
                  </VStack>
                )}
              </VStack>
            )
          })}
        </VStack>
      </Card>
    </Page>
  )
}
