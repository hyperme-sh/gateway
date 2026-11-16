# Digest count producer

Gateway #57 selects digest billing only from Plane's authenticated ticket pull.
An absent `digest_meters` field preserves the existing byte/session path. Chat
payloads cannot select or change meters. Selected digest leases require
`HYPERMESH_DIGEST_METERS_ENABLED=true` and `HYPERMESH_DIGEST_QUEUE_PATH` pointing
to a persistent SQLite file. The default is off; keep it off until Payment #112
and the owning configuration are complete.

Before forwarding a request, Gateway commits a count-only pending marker. It
requests streaming usage from the host and uses `usage.total_tokens` as the
integer token count. Each accepted prompt counts once. Missing, invalid or
conflicting token totals keep the marker pending; bytes are never converted to
tokens. The JSON/SSE parser has a 1 MiB bound and retains no response or prompt
text on disk. The same request UUID is the batch ID for each declared meter.

Unresolved work is bounded to 128 requests per lease and 1,024 per tenant.
Definitive pre-host failures and explicit no-work rejections retire their marker;
ambiguous delivery remains pending. Fully acknowledged requests are deleted
transactionally; batch IDs remain durable until every declared meter is accepted.

Completed batches commit before their first POST. Restarts and lost responses
reuse the original batch IDs and quantities. A named post never falls back to
legacy charged counters. Failed authorization, reassignment or unavailable Plane
leaves the batch pending. Ordinary byte/session metrics continue independently.

Plane #144 provides authoritative selection and the pre-close handshake.
`POST /api/v1/hypermesh-gateway/leases/{lease_id}/meter-drain` requires the Gateway
service credential and tenant scope. It fences new requests durably, flushes
completed batches and returns success only when no pending request remains.
In-flight work may finish after the fence; Plane retries the handshake before
claiming close. Fences survive restarts. Unknown counts after abrupt termination
block settlement and need an owner repair through a separately reviewed API;
no automatic zero count, deletion, database repair or provider operation is
permitted. Operator cancellation does not discard already produced counts.

The scheduled CI batch owns cross-service scenarios. Unit/contract checks cover
scope rejection, durable retry, parser bounds and flush-before-close. No package
version, wallet asset, enterprise redemption rule or provider setting changes.
