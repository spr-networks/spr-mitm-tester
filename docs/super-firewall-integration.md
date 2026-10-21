# SUPER firewall integration for the MITM sink

This is a handoff for a possible SUPER fix. It records the October 2026 live test of `spr-mitm-tester` on a KVM SPR host.

## What worked

SPR PFW routed a Mac client's TCP/443 connection for `74.207.241.245` through `mitmtst0`. After two temporary host nft map entries were added, the plugin recorded `GET https://www.asdfasdf.com/` from `192.168.2.118`, including its headers. A subsequent challenge for the distinct SNI `asdfasdf.com` showed curl receiving a leaf with `subject: CN=asdfasdf.com` and `issuer: C=US; O=eMudhra Inc; CN=EM OV TLS CA - G3C`. These observations confirm transparent interception, certificate substitution, and HTTP request capture on this route. The curl test used `-k`, so it does **not** prove that an IoT client trusts the forged eMudhra chain. At the time of this capture, the plugin challenged each client IP and SNI only once, so a repeat curl saw the normal Let's Encrypt issuer. The probe now challenges every SNI-bearing connection while forwarding is active.

The test addresses are examples, not values to hard-code: Mac `192.168.2.118`, guest `192.168.1.10`, bridge `mitmtst0`, guest MAC `02:53:50:52:4b:17`, remote server `74.207.241.245`. The plugin declares `NetworkCapabilities.Interface`, `DeviceMAC`, and `Policies: ["wan", "dns"]` in `plugin.json`.

## Failure 1: spoofed return packets hit `DROP_MAC_SPOOF`

The guest's transparent proxy sends the client a SYN-ACK with the **original remote server IP** as source. A host capture showed:

```text
eth1      In   192.168.2.118:53997 -> 74.207.241.245:443  SYN
mitmtst0  Out  192.168.2.118:53997 -> 74.207.241.245:443  SYN
mitmtst0  In   74.207.241.245:443 -> 192.168.2.118:53997  SYN-ACK
```

The SYN-ACK repeated on `mitmtst0` and did not reach the Mac. An nft trace previously identified the host `inet filter DROP_MAC_SPOOF` path as the drop. In `super/base/scripts/nft_rules.sh`, `FORWARD` checks `DROP_MAC_SPOOF` **before** `F_EST_RELATED`. The `ethernet_filter` key is `ip saddr . iifname . ether saddr`; SUPER's plugin setup adds only the guest's own IP (`192.168.1.10 . mitmtst0 . guest MAC`). A legitimate transparent reply instead has `74.207.241.245` as source, so it misses that entry and is dropped.

A temporary `ethernet_filter` entry for `74.207.241.245 . mitmtst0 . guest MAC` allowed this one test destination. It cannot cover unknown IoT destinations and is not a production solution. A broad source-IP exception for the bridge would also weaken the anti-spoof boundary.

The existing `ethernet_filter` map has exact IPv4 keys and no interval flag: `0.0.0.0` matches only that address, not every remote IP. For a temporary all-destinations diagnostic on the live host, a narrower chain rule can return only established TCP/443 replies from the declared guest MAC:

```sh
nft insert rule inet filter DROP_MAC_SPOOF iifname "mitmtst0" ether saddr 02:53:50:52:4b:17 tcp sport 443 ct state established return
nft -a list chain inet filter DROP_MAC_SPOOF
```

Insert places the rule before the map lookup. Confirm that the first SYN-ACK is accepted, then remove the test rule by its listed handle with `nft delete rule inet filter DROP_MAC_SPOOF handle HANDLE`. This rule is not tied to PFW's selected flows and is not a durable authorization model. The `0.0.0.0` test element can be deleted with `nft 'delete element inet filter ethernet_filter { 0.0.0.0 . "mitmtst0" . 02:53:50:52:4b:17 }'`.

### SUPER dev return-path rule

SUPER dev adds `NetworkCapabilities.TransparentSink` and registers the declared interface in `transparent_sink_interfaces`. In `DROP_MAC_SPOOF`, its new rules require that interface, an authorized guest MAC, conntrack reply direction and established state, and a live matching PFW `site_forward` or `site_forward_tcp_port` entry before allowing the remote-IP source. The tester declares `TransparentSink: true` in `plugin.json`. Verify the first SYN-ACK and cleanup on plugin removal in an integration test. Unselected flows, unsolicited packets, wrong-MAC packets, and other plugin interfaces must still hit the ordinary anti-spoof rule.

Relevant SUPER code: `base/scripts/nft_rules.sh` (`FORWARD`, `DROP_MAC_SPOOF`, `ethernet_filter`, `site_forward*`), `api/code/plugins.go` (`ensurePluginDeviceEthernetRule`), and the PFW rule writer in `api/code`.

## Failure 2: saved WAN policy, absent `fwd_iface_wan` entry

The live `api.json` plugin entry and `firewall.json` `CustomInterfaceRule` both requested `wan` for `mitmtst0` and guest IP `192.168.1.10`. Nevertheless, a trace of the guest's upstream SYN showed `iif mitmtst0`, `oif ppp0`, source `192.168.1.10`, then a fallthrough to `DROPLOGFWD` (`drop:forward`). The expected live map entry was absent:

```text
inet filter fwd_iface_wan: "mitmtst0" . 192.168.1.10 : accept
```

Adding that entry temporarily allowed the guest to connect upstream. This is separate from the client-facing SYN-ACK drop above; both paths must work.

The exact event that removed or failed to populate the map was not established. The code contains a plausible persistence gap: `applyPluginCustomInterfaceRule` compares the desired rule with **saved** `CustomInterfaceRules` and skips `modifyCustomInterfaceRulesImpl` when they match, without checking the live `fwd_iface_wan` map. The five-minute plugin reconciliation therefore may report success while the map entry is absent. A full firewall reapply flushes `fwd_iface_wan` and rebuilds it from saved rules, but `applyContainerInterfaces` does not propagate per-rule errors to its caller. This needs a reproduction before assigning the precise cause.

### Proposed SUPER work

Make reconciliation verify the live `fwd_iface_wan` element for a plugin whose saved rule has `wan`, and restore it if missing. Also ensure firewall reapply reports and retries failures when repopulating custom-interface maps. Check startup, plugin update, route change, and firewall reload ordering so the guest's current IP is used. An already-saved rule must not be treated as proof that its nft entries exist.

Relevant SUPER code: `api/code/plugins.go` (`checkCurrentPluginNetworkRules`, `applyPluginCustomInterfaceRule`, `reconcilePluginNetworkCapabilities`) and `api/code/firewall.go` (`applyCustomInterfaceRule`, `applyContainerInterfaces`, `applyFirewallRulesLocked`).

## Verification for a SUPER change

1. Install/start the KVM plugin with its declared `wan` policy. Check that the saved custom-interface rule **and** the live `fwd_iface_wan` entry exist. Delete only the live entry in a test fixture, run reconciliation, and assert that it returns.
2. Create a PFW rule for a test client and arbitrary TCP/443 destination. Verify the client's SYN goes to the sink and the guest's remote-source SYN-ACK reaches the client without a per-destination `ethernet_filter` entry. Repeat with a second destination without changing host rules.
3. Assert that a wrong MAC, an unsolicited remote-source packet, and traffic on a plugin interface without the transparent-sink capability are still dropped. Test the first SYN-ACK, not just packets after TCP establishment.
4. Verify the guest's upstream SYN passes `fwd_iface_wan` and reaches the WAN; then confirm the client sees the forged certificate and the plugin records a request. For an actual IoT verdict, inspect its `handshake_completed` event without a client-side `-k` equivalent.
5. Reload the firewall, update/restart the plugin, and remove/re-add the PFW route. Both directions must continue to work. Disable/uninstall the plugin and verify that any scoped allow entries are removed.

Useful read-only checks on the SPR host are `nft list map inet filter ethernet_filter`, `nft list map inet filter fwd_iface_wan`, `nft list chain inet filter FORWARD`, `nft list chain inet filter DROP_MAC_SPOOF`, and simultaneous captures on the LAN, `mitmtst0`, and WAN interfaces. KVM Docker does not support `docker exec` here; plugin events are available through its Unix socket.
