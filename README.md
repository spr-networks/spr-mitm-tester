# SPR MITM tester 

This plugin tests network devices for MITM issues, in particular the [eMudhra subordinate CA issue](https://emudhra.com/en/post/certificate-security-incident).

Devices with CA stores that were updated after April 30, 2025 could carry the vulnerable certificate. 
```The key sequence of events:

April 30, 2025: The eight intermediates were created in a Key Generation Ceremony.
Mid-2025: The hierarchy was included in browser trust lists. It has since passed two independent audit cycles.
October 18, 2026 (late evening, India time): We were made aware of the issue. The researcher notified Apple, Google, Microsoft and Mozilla at the same time.
October 19, 2026: We revoked all eight intermediates.
``` 

To use this plugin install it on the plugins page. Next, select a device in topology you'd like to route to the destination.

The sink for this plugin is named `mitm tester`

<img width="458" height="624" alt="image" src="https://github.com/user-attachments/assets/138a8cb1-625e-4e49-9f52-0579fff860e9" />


Once set up, navigate to the plugin in the menu bar


<img width="1009" height="600" alt="image" src="https://github.com/user-attachments/assets/a9b87b0f-2963-4de1-a4c0-0f66b54bd8e1" />



AI notes below

## Notes


This plugin tests selected IoT devices using their **normal destinations**. SPR PFW routes selected TCP/443 flows to a dedicated `mitmtst0` sink. In the container, nftables redirects those connections to mitmproxy's transparent listener. Mitmproxy connects to the original server and presents a leaf certificate for the destination signed by a compromised eMudhra TLS intermediate. The connection is then relayed to the Internet.

The plugin records client IP, SNI, timestamp, selected intermediate, and TLS handshake outcome. After a successful handshake it also records HTTP request method, URL, headers, total body size, and the first 8 KiB of the body. Binary previews are base64 encoded; headers and URLs have explicit size limits. It does not save responses or flow files. Request data can contain credentials, so the local event log is mode `0600` and the UI exposes it only through the plugin's sandboxed API. It challenges every TCP/443 connection with SNI while the SPR forwarding rule is active. TCP/443 without SNI is passed through. SPR can separately block UDP/443 for selected devices so clients that support fallback use TCP TLS. Other ports are outside this sink.

For example, when a selected device opens TLS to `www.whatever.com`, the proxy connects to `www.whatever.com` and presents the device with a new `www.whatever.com` certificate signed by the selected affected eMudhra intermediate. A completed client handshake is the observation this audit seeks.


## Affected authority

A clean install automatically uses the [reporter's public `EM OV TLS CA - G3C` example](https://gist.github.com/Fluepke/9a103c7f990c3cc2fb5002f7476f2f48) under the emSign root. The image build downloads the exact published key with a pinned SHA-256 checksum and includes it with the matching public certificate. No fetch or configuration step is needed on the router. This key is already publicly disclosed; the image does not contain any administrator-supplied key. Startup still validates the certificate against the [published incident list](https://emudhra.we-have-a-problem.com/impacted-intermediates.json), checks that the key matches, and verifies that the certificate can sign leaves. Only one certificate chain is active per run.

To override the bundled example, supply `authority.crt` and `authority.key` together in `configs/plugins/spr-mitm-tester`. For example, to use the AAA cross-sign with the same public key, run this optional helper from the plugin source directory:

```sh
./scripts/fetch-example-authority.sh /path/to/super/configs/plugins/spr-mitm-tester aaa
```

The helper checks the certificate fingerprint and key pair before installing both files. Restart the plugin after changing the override. To test another affected intermediate, supply its matching certificate and key and restart. If either override file exists but validation fails, startup reports the error and leaves interception disabled rather than silently using the bundled example. A successful result for one affected chain establishes exposure; failure for one chain does not clear the other chains.

## Run in SPR

Install the plugin source as a dedicated SPR plugin. Its UI reports **Sink ready** after the bundled authority validates and mitmproxy's listener is reachable. The `NetworkCapabilities` declaration asks SPR to apply the plugin's WAN/DNS firewall access for `mitmtst0` automatically. On SUPER dev, `TransparentSink: true` also enables the PFW-scoped return path for replies whose source is the original remote server. Its `/topology` response advertises a live `Sinks` entry with the bridge, IP, and readiness, following the same SPR forwarding destination contract as the mitmproxy and tunnel plugins. SPR PLUS/PFW is required for transparent routing.

In SPR:

1. Confirm the selected intermediate and sink IP in the plugin UI.
2. In [SPR Topology](https://192.168.2.1/admin/topology), select **mitm-tester** as the route destination for the devices under test.
3. If those devices use QUIC, block UDP/443 for them in SPR so they can fall back to TCP TLS.
4. Review recent connections, HTTP requests, and WebSocket or TCP data in the plugin UI. **Certificate accepted** means the device completed TLS with the forged certificate. The connection row then shows whether HTTP requests or other application data were recorded. A destination HTTP status confirms a response. Failed or disconnected handshakes are inconclusive.
5. Remove the SPR forwarding and UDP block rules when finished.

The sandboxed plugin UI reads only its own status, topology, and event endpoints. It does not call the SPR PFW, firewall, or device APIs. Installing or starting this plugin does not intercept device traffic by itself. If the proxy stops while forwarding rules remain, selected TCP/443 traffic can fail until routing is disabled.

The container listens for redirected TLS on TCP port `9999` inside its network namespace, and serves its plugin API on a Unix socket. The `8080-8081/tcp` text in `docker ps` is inherited `EXPOSE` metadata from the mitmproxy base image; the plugin does not listen on those ports, and the Compose files publish no host ports.

The event log records all parsed HTTP methods and bounded request-body previews. It also records WebSocket text or binary messages and generic TCP chunks in both directions when mitmproxy identifies those protocols. Each WebSocket or TCP record includes direction, byte count, and up to 8 KiB of text or Base64 data. TCP chunks are arbitrary stream segments, not application messages; the plugin does not decode MQTT. The local event file is capped at 2 MiB. Connections recorded before version 0.0.2 lack connection IDs, so their old handshake rows cannot be matched reliably to request or data records.

For the current SUPER host-firewall behavior observed with this KVM sink, see the [firewall integration handoff](docs/super-firewall-integration.md). It describes the return-path anti-spoof drop and a missing live `fwd_iface_wan` entry despite the saved WAN policy, with proposed SUPER fixes and verification steps.

## Upstream TLS verification

By default, mitmproxy verifies destination server certificates against the system roots and the pinned [Root YR cross-sign by ISRG Root X1](https://letsencrypt.org/certificates/). If a device uses a destination with a private or untrusted CA, the connection row shows the upstream TLS failure.

To allow any destination certificate during a test, turn off **Verify destination certificates** in the plugin UI. The choice is saved in `state/plugins/spr-mitm-tester/settings.json` and applies to new connections without restarting the plugin. Turn the switch back on to restore verification.

For a file-based initial setting, create `configs/plugins/spr-mitm-tester/settings.json` on the SPR host with:

```json
{"verify_upstream_tls": false}
```

Restart the plugin after changing that initial setting. A UI choice takes precedence over the file-based setting. This setting controls only the proxy's connection to destination servers; it does not change the forged eMudhra certificate shown to devices. While it is `false`, the proxy does not authenticate destination servers.

At startup the plugin copies its probe addon into `/run/mitm-tester` before launching mitmproxy. The reproducible build normalizes image file timestamps to epoch 0, which mitmproxy's script watcher does not load; the runtime copy gives it a current timestamp so challenge and request events are recorded.

The plugin's SPR management name is `spr-mitm-tester`, matching its URI and repository name. Installations made from older manifests may still be saved in SPR as `MITM tester`; changing the manifest does not rename an existing SPR configuration entry. That saved entry needs an administrator to rename it in SPR's configuration before the management API can address it by the new name.

## Scope and interpretation

- The catalogue includes the six affected TLS intermediate keys under two root chains each. Code signing intermediates are outside this TLS probe.
- The supplied gist contains one verified affected key. To assess another intermediate, provision its own matching key and certificate; the proxy will not infer safety from other chains.
- SNI based certificate generation cannot reliably challenge clients that omit SNI; those connections are passed through and produce no verdict.
- A completed TLS handshake is strong evidence that the client's TLS stack accepted the presented chain. Some applications perform further checks after the handshake, so inspect application behavior before assigning a final device risk classification.
- A failed handshake is **inconclusive**, never reported as “safe.”
- This intentionally changes every matching TLS connection while forwarding is active and may interrupt connections from clients that reject the forged chain. Use the tag on devices you are authorized to test.

The transparent certificate generation and pass-through behavior follow [mitmproxy's certificate model](https://docs.mitmproxy.org/stable/concepts/certificates/) and [TLS event hooks](https://docs.mitmproxy.org/stable/api/events.html).

## Local certificate acceptance test

With Docker available, run `python3 tests/run_acceptance.py` from this directory. The runner downloads the reporter's pinned public example key into a temporary directory, runs five isolated loopback tests in the pinned mitmproxy image, and removes the key when finished. The test container has no external network access. It uses a synthetic HTTPS server for `www.whatever.com` and a client that trusts either the affected root or the affected intermediate, testing both the emSign and AAA certificate chains.

The four certificate acceptance cases each make two consecutive connections with the same client IP and SNI. They verify that the client accepts both forged hostname certificates, check their SAN and signature against the affected intermediate, send a POST body through each connection to the synthetic upstream, and find matching handshake, request, and response events for each connection. One case also sends WebSocket messages and binary TCP data in both directions and verifies their previews. A fifth case rejects the synthetic upstream's untrusted certificate and checks that the upstream TLS failure is recorded. These exercise certificate generation and client acceptance in regular proxy mode; the SPR PFW and nftables transparent routing path requires a separate device or network test. The synthetic upstream uses a self-signed certificate, so the four relay cases enable mitmproxy's `ssl_insecure` option only in the isolated test process; the plugin's production startup keeps upstream verification enabled by default.

After building an image, run `python3 tests/run_packaged_smoke.py ghcr.io/spr-networks/spr-mitm-tester:latest` to exercise the bundled authority and probe addon from the reproducible image. CI runs this after building pull requests and after publishing a main image. It catches packaging failures such as an addon file whose normalized timestamp prevents mitmproxy from loading it.

## Reproducible image and CI

`reproducible.env` pins the mitmproxy, Node, BuildKit, Dockerfile syntax, and SPR krun helper images by digest. The public example authority key is pinned by SHA-256 in the Dockerfile. The final image installs its OS packages from a pinned Debian snapshot. The frontend uses the committed Yarn lockfile, including a resolved commit for `spr-plugin-ui`. `build_docker_compose.sh` passes the pins to Buildx and normalizes image timestamps with `SOURCE_DATE_EPOCH=0` and `rewrite-timestamp=true`.
The upstream Root YR cross-sign is committed at `data/upstream/root-yr-by-x1.pem` (file SHA-256 `b3858d7a4d598b4ab6ed2892a1b8c0ee035154876dd40a082a3b05387eea11a4`).

Run `./build_docker_compose.sh --load` for a local build. Run `./update-pins.sh` only when deliberately updating dependencies, and review the resulting diff. GitHub Actions validates the manifests, runs the five acceptance cases, builds pull requests, and builds and publishes `linux/amd64` and `linux/arm64` images on `main` to `ghcr.io/spr-networks/spr-mitm-tester`. A `#patch`, `#minor`, or `#major` commit bumps the Git tag before the image build; the release image receives matching version, `latest`, and commit SHA tags plus the `org.supernetworks.version` label shown by SPR. The release job attaches and verifies a keyless Sigstore SLSA provenance attestation for the published digest, as required by SPR's plugin updater. The published image includes the pinned, publicly disclosed example key; any administrator-supplied override remains in the SPR config directory.
