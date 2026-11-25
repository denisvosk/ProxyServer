# GOST runtime library desktop patch

This directory contains `github.com/go-gost/x v0.28.1`, commit
`006b432a7d0472d49ec3ca77a37a133c71e8c0f3`, with two bounded corrections.
It is used by the adjacent GOST v3.3.3 source through a local `go.mod` replace.
The complete change is in `DESKTOP_PATCH.diff`, including regression tests.

## Changes

1. Encrypted DNS defaults: DoT now verifies the resolver certificate and host
   against the system trust roots, with TLS 1.2 as the minimum and the URL
   hostname as ServerName. The HTTPS transport also receives an explicit
   verifying TLS configuration. Stock DoH actually used a nil transport TLS
   configuration, which already invoked Go's default certificate verification;
   this patch does not describe stock DoH as accepting arbitrary certificates.
   Explicit TLSConfigOption overrides remain unchanged. The implicit port for
   tls:// and dot:// is corrected to 853; UDP/TCP remain 53, including IPv6.
2. HTTP forwarding: remove headers named by Connection plus standard hop-by-hop
   headers on requests and responses, while retaining negotiated WebSocket
   Upgrade and TE trailers. Go net/http keeps responsibility for message framing.

No MITM interception or TLS certificate bypass is enabled by the desktop
configuration. The fork is identified in the compiled GOST version as
`3.3.3-desktop.1`, and is not an unmodified upstream release binary.

## Validation

`go test ./handler/http ./resolver/exchanger` passes on Linux with Go 1.26.11.
The new TLS tests use loopback DoT/DoH servers and verify rejection of an unknown
CA and a mismatched hostname, acceptance with the matching trusted certificate,
minimum version defaults, port 853, and IPv6 address formatting. The HTTP
regression covers Connection token removal and retained WebSocket/trailer
negotiation. This is not a claim of Windows GUI or VDS end-to-end validation.

Upstream license remains in `LICENSE`. All other upstream source is unchanged.
