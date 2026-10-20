import React, { useEffect, useState } from 'react'
import {
  Badge, BadgeText, Button, ButtonText, Card, HStack, ListHeader,
  Page, SectionHeader, Text, VStack
} from '@spr-networks/plugin-ui'
import { api } from '@spr-networks/plugin-ui'

const URI = 'spr-mitm-tester'
const BRIDGE = 'mitmtst0'
const TAG = 'mitm-tester'
const FORWARD_NAME = 'MITM tester: TLS 443'
const BLOCK_NAME = 'MITM tester: block QUIC'

const forwardRule = (ip) => ({
  RuleName: FORWARD_NAME,
  Client: { Tag: TAG },
  Protocol: 'tcp',
  OriginalDst: { IP: '0.0.0.0/0' },
  OriginalDstPort: '443',
  Dst: { IP: ip },
  DstPort: '',
  DstInterface: BRIDGE,
  Disabled: false,
  Condition: '',
  Expiration: 0
})

const blockRule = () => ({
  RuleName: BLOCK_NAME,
  Client: { Tag: TAG },
  Protocol: 'udp',
  Dst: { IP: '0.0.0.0/0' },
  DstPort: '443',
  Disabled: false,
  Condition: '',
  Expiration: 0
})

const eventLabel = {
  attempted: 'Challenge started',
  handshake_completed: 'TLS handshake completed',
  handshake_failed: 'TLS handshake failed (inconclusive)',
  disconnected_before_result: 'Disconnected (inconclusive)'
}

export default function Plugin() {
  const [status, setStatus] = useState(null)
  const [topology, setTopology] = useState(null)
  const [pfw, setPfw] = useState(null)
  const [firewall, setFirewall] = useState(null)
  const [devices, setDevices] = useState([])
  const [events, setEvents] = useState([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const load = async () => {
    const results = await Promise.allSettled([
      api.get(`/plugins/${URI}/status`),
      api.get(`/plugins/${URI}/topology`),
      api.get('/plugins/pfw/config'),
      api.get('/firewall/config'),
      api.get('/devices'),
      api.get(`/plugins/${URI}/events`)
    ])
    if (results[0].status === 'fulfilled') setStatus(results[0].value)
    if (results[1].status === 'fulfilled') setTopology(results[1].value)
    if (results[2].status === 'fulfilled') setPfw(results[2].value)
    if (results[3].status === 'fulfilled') setFirewall(results[3].value)
    if (results[4].status === 'fulfilled') {
      const value = results[4].value
      setDevices(Array.isArray(value) ? value : Object.values(value || {}))
    }
    if (results[5].status === 'fulfilled') setEvents(results[5].value || [])
  }

  useEffect(() => {
    load()
    const timer = setInterval(load, 5000)
    return () => clearInterval(timer)
  }, [])

  const ip = topology?.Sinks?.find((sink) => sink.Iface === BRIDGE)?.IP || ''
  const forwards = pfw?.ForwardingRules || []
  const blocks = pfw?.BlockRules || []
  const managedForward = forwards.find((rule) => rule.RuleName === FORWARD_NAME)
  const managedBlock = blocks.find((rule) => rule.RuleName === BLOCK_NAME)
  const routed = Boolean(
    managedForward && !managedForward.Disabled && managedForward.Client?.Tag === TAG &&
    managedForward.Protocol === 'tcp' && managedForward.OriginalDstPort === '443' &&
    managedForward.DstInterface === BRIDGE && managedForward.Dst?.IP === ip &&
    managedBlock && !managedBlock.Disabled && managedBlock.Client?.Tag === TAG &&
    managedBlock.Protocol === 'udp' && managedBlock.DstPort === '443'
  )
  const conflict = forwards.some((rule) =>
    !rule.Disabled && rule.DstInterface === BRIDGE && rule.RuleName !== FORWARD_NAME
  )
  const accessReady = (firewall?.CustomInterfaceRules || []).some((rule) =>
    !rule.Disabled && rule.Interface === BRIDGE && String(rule.SrcIP || '').replace(/\/32$/, '') === ip &&
    (rule.Policies || []).includes('wan')
  )

  const enable = async () => {
    if (!status?.ready || !ip || !pfw || !accessReady || conflict) return
    setBusy(true)
    setError('')
    try {
      const current = await api.get('/plugins/pfw/config')
      const forwardIndex = (current.ForwardingRules || []).findIndex((rule) => rule.RuleName === FORWARD_NAME)
      if (forwardIndex < 0) await api.put('/plugins/pfw/forward', forwardRule(ip))
      else await api.put(`/plugins/pfw/forward/${forwardIndex}`, forwardRule(ip))
      const blockIndex = (current.BlockRules || []).findIndex((rule) => rule.RuleName === BLOCK_NAME)
      if (blockIndex < 0) await api.put('/plugins/pfw/block', blockRule())
      else await api.put(`/plugins/pfw/block/${blockIndex}`, blockRule())
      await load()
    } catch (e) {
      setError(`Could not enable the sink: ${e.message}`)
    } finally {
      setBusy(false)
    }
  }

  const disable = async () => {
    setBusy(true)
    setError('')
    try {
      const current = await api.get('/plugins/pfw/config')
      const forwardIndexes = (current.ForwardingRules || [])
        .map((rule, index) => rule.RuleName === FORWARD_NAME ? index : -1)
        .filter((index) => index >= 0).sort((a, b) => b - a)
      for (const index of forwardIndexes) await api.delete(`/plugins/pfw/forward/${index}`, {})
      const blockIndexes = (current.BlockRules || [])
        .map((rule, index) => rule.RuleName === BLOCK_NAME ? index : -1)
        .filter((index) => index >= 0).sort((a, b) => b - a)
      for (const index of blockIndexes) await api.delete(`/plugins/pfw/block/${index}`, {})
      await load()
    } catch (e) {
      setError(`Could not disable the sink: ${e.message}`)
    } finally {
      setBusy(false)
    }
  }

  const setTag = async (device, enabled) => {
    const identity = device.MAC || device.WGPubKey
    if (!identity) return
    setBusy(true)
    setError('')
    try {
      const tags = Array.isArray(device.DeviceTags) ? device.DeviceTags : []
      const next = enabled ? [...new Set([...tags, TAG])] : tags.filter((tag) => tag !== TAG)
      await api.put(`/device?identity=${encodeURIComponent(identity)}`, { DeviceTags: next })
      await load()
    } catch (e) {
      setError(`Could not update device tag: ${e.message}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Page testID="mitm-tester-page">
      <ListHeader
        title="MITM tester"
        description="Challenge selected devices with an affected intermediate on their normal TLS destinations"
        mark="CA"
        status={status?.ready ? (routed ? 'Sink routing enabled' : 'Proxy ready') : 'Authority required'}
        statusAction={status?.ready ? 'success' : 'warning'}
      />
      <Card>
        <SectionHeader title="Authority and sink" />
        <VStack space="md">
          <Text>Issuer: {status?.authority ? `${status.authority.name} / ${status.authority.issued_by}` : 'No validated authority installed'}</Text>
          <Text>Bridge: {BRIDGE} · Container IP: {ip || 'not detected'} · Selector tag: {TAG}</Text>
          {!pfw && <Text color="$orange600">SPR PFW is required to route tagged traffic into this sink.</Text>}
          {status?.ready && !accessReady && <Text color="$orange600">Waiting for SPR to apply the sink's WAN firewall access.</Text>}
          <Text>Only TCP/443 is intercepted. UDP/443 is blocked for tagged devices so they can fall back to TLS over TCP. Other device traffic follows its usual route.</Text>
          {conflict && <Text color="$red600">Another forwarding rule targets this sink. Remove that rule before enabling the audit.</Text>}
          {error && <Text color="$red600">{error}</Text>}
          <HStack space="sm">
            <Button onPress={enable} isDisabled={busy || !status?.ready || !ip || !pfw || !accessReady || conflict || routed}>
              <ButtonText>Enable sink routing</ButtonText>
            </Button>
            <Button action="secondary" onPress={disable} isDisabled={busy || !pfw || (!managedForward && !managedBlock)}>
              <ButtonText>Disable sink routing</ButtonText>
            </Button>
          </HStack>
        </VStack>
      </Card>
      <Card>
        <SectionHeader title="Devices" />
        <VStack space="sm">
          <Text>Add the audit tag only to devices you intend to test. Each device and SNI is challenged once per proxy run; later connections are passed through.</Text>
          {devices.map((device) => {
            const identity = device.MAC || device.WGPubKey
            if (!identity) return null
            const tagged = (device.DeviceTags || []).includes(TAG)
            return (
              <HStack key={identity} space="sm" alignItems="center" justifyContent="space-between">
                <Text>{device.Name || identity} · {device.RecentIP || identity}</Text>
                <Button size="sm" action={tagged ? 'secondary' : 'primary'} isDisabled={busy} onPress={() => setTag(device, !tagged)}>
                  <ButtonText>{tagged ? 'Remove tag' : 'Audit device'}</ButtonText>
                </Button>
              </HStack>
            )
          })}
        </VStack>
      </Card>
      <Card>
        <SectionHeader title="Recent TLS challenges" />
        <VStack space="sm">
          <Text>A completed forged-certificate handshake is evidence that this connection accepted the affected chain. A failed handshake does not establish that the device is protected.</Text>
          {events.length === 0 && <Text>No challenges recorded yet.</Text>}
          {[...events].reverse().slice(0, 50).map((event, index) => (
            <HStack key={`${event.time}-${index}`} space="sm" alignItems="center" justifyContent="space-between">
              <Text>{event.time} · {event.client_ip} · {event.sni}</Text>
              <Badge action={event.result === 'handshake_completed' ? 'error' : 'warning'} variant="outline">
                <BadgeText>{eventLabel[event.result] || event.result}</BadgeText>
              </Badge>
            </HStack>
          ))}
        </VStack>
      </Card>
    </Page>
  )
}
