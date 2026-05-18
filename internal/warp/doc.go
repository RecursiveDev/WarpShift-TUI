// Package warp defines WARP management boundaries for local connection quality,
// health reporting, endpoint recovery, identity handling, profile storage,
// private-use API workflows, and policy gates.
//
// Account registration, deregistration, device status, and user-owned WARP+ license
// binding are exposed through consent-gated callers with injectable HTTP clients for
// tests. Profile storage and endpoint pool expansion are local capabilities; advanced
// workflows should keep explicit user consent gates, caller-injected probes, and
// secret-safe errors/status output.
package warp
