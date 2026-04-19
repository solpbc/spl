# ios

iOS client for spl. **Stub directory** — the real project files land when the iOS build begins.

## status

Not started. Lineage: the iOS client extends [extro-phone](https://github.com/solpbc/extro-phone)'s stack, replacing its `SSHTransport.swift` (~500 lines) with a `CFTunnelTransport.swift` that speaks the spl framing protocol over a WebSocket to `solcf`.

## what will reuse

Most of the iOS stack is already proven in extro-phone and will be imported unchanged or nearly so:

- `Sources/Tunnel/PortForwardingServer.swift` — `NIOTSListenerBootstrap` on loopback
- `Sources/Tunnel/GlueHandler.swift` — 2-buffer bidirectional pump with backpressure
- `Sources/Tunnel/KeychainStore.swift` — `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- `Sources/Tunnel/HostKeyValidator.swift` — adapted to pin the TLS cert fingerprint instead of SSH host key
- `Sources/Services/AppConfig.swift` — gains spl fields (solcf endpoint, device token, paired-home instance id)
- App lifecycle (foreground-only with 20s grace)

## what is new

- `Sources/SPLTunnel/CFTunnelTransport.swift` — replaces `SSHTransport.swift`. Opens the WS to `solcf`, runs the spl framing layer, demultiplexes streams back to `GlueHandler`'s API.
- A TLS 1.3 client inside the tunnel using Apple's `Network.framework`, fed by the demultiplexed byte stream. Client cert + private key come from Keychain (set at pair time).

## non-goals

v1 is iOS-only. Android parity is deferred to H3 per the product roadmap. The primitives exist on Android (loopback listener, OkHttp with client cert); the architectural risk in deferring is nil.

See [`../AGENTS.md`](../AGENTS.md) §6 for the broader MVP frame.
