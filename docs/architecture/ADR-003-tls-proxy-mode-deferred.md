# ADR-003: TLS Proxy Mode — Deferred Scope

## Status

Deferred (config field exists; listener logic not implemented)

## Context

The `[proxy]` configuration section includes a `tls_mode` field (type `string`, default `"disabled"`). The value is parsed and stored in `ProxySettings.TLSMode` (`internal/config/config.go`). However, `internal/proxy/server.go` contains **no TLS listener logic** — all proxy listeners bind plain TCP sockets regardless of the `tls_mode` value.

Two distinct capabilities could fall under "TLS proxy":

1. **Inbound TLS termination** — The SOCKS5/HTTP listener accepts TLS connections from local or remote clients, decrypting before forwarding through the WARP tunnel.
2. **Outbound TLS wrapping** — The WARP tunnel dialer wraps its outbound connection in an additional TLS layer (beyond the WireGuard encryption already in place).

These have very different security properties and implementation surfaces.

## Decision

**Leave `tls_mode` in the config surface as a documented intent field. Accept `"disabled"` as the only supported value; non-`"disabled"` values are rejected by config validation with a clear "not implemented" message.**

### Rationale

- The config field exists and is parsed. Removing it would break existing configs.
- The current proxy implementation in `internal/proxy/server.go` does not import `crypto/tls` and has no TLS configuration surface.
- Adding inbound TLS termination would require certificate management (`tls.Config`, cert/key paths, auto-generation or ACME). Adding outbound TLS wrapping would require changes to the tunnel dialer and may conflict with WireGuard's own encryption.
- Neither use case has been explicitly scoped by the user.

### Alternatives considered

| Alternative | Rejected because |
| ----------- | ---------------- |
| Implement inbound TLS termination | Requires cert management; scope unclear; no user requirement stated |
| Implement outbound TLS wrapping | May conflict with WireGuard encryption; unclear benefit; no user requirement stated |
| Remove `tls_mode` field | Breaks existing configs; loses documented intent |
| Silently accept non-`"disabled"` values | Would mislead users into thinking TLS proxy works; silent acceptance was an earlier interim approach since replaced by explicit rejection |

## Consequences

- `tls_mode = "disabled"` is the only value with observable effect (plain TCP listeners).
- Other values are rejected by config validation until TLS proxy support is implemented.
- When TLS support is implemented, it should be scoped to a specific use case (inbound or outbound) and accompanied by a dedicated ADR.
