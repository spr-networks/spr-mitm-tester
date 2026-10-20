# SPR MITM tester sink

This plugin tests selected IoT devices using their **normal destinations**. SPR PFW routes tagged TCP/443 flows to a dedicated `mitmtst0` sink. In the container, nftables redirects those connections to mitmproxy's transparent listener. Mitmproxy connects to the original server and presents a leaf certificate for the destination signed by a compromised eMudhra TLS intermediate. The connection is then relayed to the Internet.

The plugin records only client IP, SNI, timestamp, selected intermediate, and TLS handshake outcome. It does not save HTTP requests, responses, or flow files. It challenges the first connection for each client IP and SNI per proxy run; later connections for that pair are passed through unchanged. TCP/443 without SNI is passed through. UDP/443 is blocked for tagged devices so clients that support fallback use TCP TLS. Other ports are outside this sink.

For example, when a tagged device opens TLS to `www.whatever.com`, the proxy connects to `www.whatever.com` and presents the device with a new `www.whatever.com` certificate signed by the selected affected eMudhra intermediate. A completed client handshake is the observation this audit seeks.

## Provision an affected authority

The private key is deliberately excluded from this source tree. Supply `authority.crt` and `authority.key` in the SPR config directory for this plugin. Startup validates that the certificate fingerprint matches one of the 12 TLS intermediates in [the published incident list](https://emudhra.we-have-a-problem.com/impacted-intermediates.json), that the key matches, and that the certificate can sign leaves. Only one certificate chain is active per run.

For the [reporter's public `EM OV TLS CA - G3C` example](https://gist.github.com/Fluepke/9a103c7f990c3cc2fb5002f7476f2f48), from the plugin source directory run:

```sh
./scripts/fetch-example-authority.sh /path/to/super/configs/plugins/spr-mitm-tester emsign
```

The script downloads the gist's pinned key, pairs it with the bundled public certificate, and checks the certificate fingerprint and key pair before renaming them into place. Container startup checks the installed pair against the full incident catalogue. Pass `aaa` instead of `emsign` to use the `AAA Certificate Services` cross-sign with the same key, then restart the plugin. To test another affected intermediate, supply its matching certificate and key and restart. A successful result for one affected chain establishes exposure; failure for one chain does not clear the other chains.

## Run in SPR

Install the plugin source as a dedicated SPR plugin and start it after provisioning the authority, or restart it after adding the authority files. Its UI reports **Proxy ready** only after authority validation and after mitmproxy's listener is reachable. The `NetworkCapabilities` declaration asks SPR to apply the plugin's WAN/DNS firewall access for `mitmtst0` automatically. SPR PLUS/PFW is required for transparent routing.

In the plugin UI:

1. Confirm the selected intermediate and sink IP.
2. Enable sink routing. This creates a tag scoped PFW rule for TCP/443 preserving the original destination, plus a UDP/443 block for the same tag.
3. Apply the `mitm-tester` tag to the devices under test. Only tagged devices are routed through the proxy.
4. Review recent TLS challenges. **TLS handshake completed** means the client completed a handshake with the forged certificate. Failed or disconnected handshakes are inconclusive; they can also reflect pinning, revocation, protocol incompatibility, upstream failure, or application behavior.
5. Remove the device tags and disable sink routing when finished.

The UI can add and remove the tag on SPR devices. PFW rule creation is separate from tagging, so installing or starting this plugin does not intercept device traffic by itself. If the proxy stops while PFW rules remain, tagged TCP/443 traffic can fail until routing is disabled.

## Scope and interpretation

- The catalogue includes the six affected TLS intermediate keys under two root chains each. Code signing intermediates are outside this TLS probe.
- The supplied gist contains one verified affected key. To assess another intermediate, provision its own matching key and certificate; the proxy will not infer safety from other chains.
- SNI based certificate generation cannot reliably challenge clients that omit SNI; those connections are passed through and produce no verdict.
- A completed TLS handshake is strong evidence that the client's TLS stack accepted the presented chain. Some applications perform further checks after the handshake, so inspect application behavior before assigning a final device risk classification.
- A failed handshake is **inconclusive**, never reported as “safe.”
- This intentionally changes the first matching TLS connection and may interrupt that connection. Use the tag on devices you are authorized to test.

The transparent certificate generation and pass-through behavior follow [mitmproxy's certificate model](https://docs.mitmproxy.org/stable/concepts/certificates/) and [TLS event hooks](https://docs.mitmproxy.org/stable/api/events.html).

## Local certificate acceptance test

With Docker available, run `python3 tests/run_acceptance.py` from this directory. The runner downloads the reporter's pinned public example key into a temporary directory, runs four isolated loopback tests in the pinned mitmproxy image, and removes the key when finished. The test container has no external network access. It uses a synthetic HTTPS server for `www.whatever.com` and a client that trusts either the affected root or the affected intermediate, testing both the emSign and AAA certificate chains.

Each test verifies that the client accepts the forged hostname certificate, checks its SAN and signature against the affected intermediate, retrieves the synthetic upstream response through the proxy, and finds a `handshake_completed` event. This exercises certificate generation and client acceptance in regular proxy mode; the SPR PFW and nftables transparent routing path requires a separate device or network test. The synthetic upstream uses a self-signed certificate, so this test enables mitmproxy's `ssl_insecure` option only in the isolated test process; the plugin's production startup leaves upstream verification enabled.
