# Trusted runtime count consumer

Gateway #70 consumes the measured CPU protocol from Host #217 and the durable
owner protocol from Plane #166. It is disabled unless digest metering is
explicitly configured. Gateway #69 implements interrupted-request recovery, archive
retrieval/dispute retirement, and restart reconciliation using Plane #169 and
Host #220. See [the repair endpoint and retained-history contract](../README.md#interrupted-trusted-counts). Infra #1638 owns the
independent issuer, verifier distribution, approved profiles, deployment
configuration and scheduled qualification. This source change activates none
of those capabilities.

## Request and billing behavior

Both renter and IR chat doors keep existing tenant, ticket, purpose, peer,
safety and run-control checks. Digest leases require the trusted consumer;
they never fall back to ordinary host HTTP or provider usage totals. Ordinary
non-digest leases retain their existing behavior.

The first profile accepts 1–64 text messages with system/user/assistant roles,
explicit `max_tokens` from 1 to 128, and greedy decoding (`temperature: 0` or
omitted). It refuses streaming, tools, multimodal content and unsupported
options rather than silently changing the request. The original messages and
generation limit pass inside guest TLS. The initial engine caps processed
input at 2048 and disables cache reuse and speculation.

Bill processed input plus accepted output, including hidden output once.
Hidden output is a subset of accepted output. Cache hits and rejected
speculative tokens are record-only; this initial profile requires their actual
counts to be zero. Prompts remain record-only. Plane owns quantity forwarding;
existing pricing, failure refunds, wallet payments and enterprise accounting
remain unchanged.

## Authorization and durable ordering

Gateway creates an ephemeral Ed25519 TLS key at startup. A dedicated TLS 1.3
relay uses the same key. Each guest connection verifies the attested server key
before sending a sensitive body; certificate names and dates do not grant
execution authority. Only the initial channel challenge can discover an unverified key. Historical
challenges send only the batch identity and original public runtime key. Plane signs the complete scope and fresh channel nonce, and the
guest verifies possession of the Gateway key and its protected-clock window.

Before inference, Gateway validates the frozen Plane binding against the
assigned tenant, lease, Gateway, device and locally approved model profile.
It independently verifies the raw SNP report using an approved verifier binary
and requires a separate policy issuer signature over the exact statement.
Plane then verifies and registers that same statement/report. Runtime identity,
measurement, model/tokenizer/template/runtime hashes and protected-time policy
are never selected by host response metadata.

The HTTPS relay accepts only signed start-v2, renew-v2 and checkpoint records
for an in-memory active request and its verified runtime key. The record
signature authenticates the caller; no incoming HTTP bearer header or arbitrary
TLS certificate grants relay access. The guest pins the relay server key to its
Plane-authorized Gateway key. Gateway checks full scope, sequence, hash chain,
monotonic counters and budgets, verifies Plane's signed reply and persists the
count-only state before acknowledging it to the guest.

A completed reply is exposed only after a signed terminal checkpoint was
anchored and Plane's matching recovery result committed. The SQLite journal
stores scope, original attestation/session, signed count records and recovery
proofs, never prompt text, output text or private keys. The recovery proof is
committed locally before authenticated guest retirement. Lost replies, quota
refusals, interrupted execution and failed retirement retain pending markers.
No uncertain work is treated as zero or automatically rerun. Pre-admission
failures can discard their unstarted local marker.

Legacy provider-total batches are retained without forwarding. Their explicit
reconciliation belongs to #69; they are not upgraded to trusted quantities.

## Owning configuration

`HYPERMESH_DIGEST_METERS_ENABLED` remains `false` by default. Enabling it
requires a durable `HYPERMESH_DIGEST_QUEUE_PATH` and
`HYPERMESH_TRUSTED_METER_CONFIG` naming a bounded JSON policy file. Missing configuration refuses startup. Expired execution policy or an empty
profile registry refuses new work; historical repair can still use the configured
owner trust without restoring execution. The policy schema is
`trusted_meter/policy.py:Policy`:

- `owner_key`, `issuer`, `issuer_key`: independently provisioned public trust.
- `issuer_command` and `verifier`: absolute executable path and exact SHA-256
  (`executable`, `sha256`), approved by the owning deployment configuration.
- `profiles`: catalog IDs mapped to exact model, tokenizer, template and runtime
  SHA-256 values plus the 48-byte SNP measurement in lowercase hex.
- AMD `product`, `minimum_tcb`, `minimum_launch_tcb`, `policy_expires_at`, and
  `revoked_runtime_keys`: explicit current vendor policy.
- `relay_bind`, `relay_port`, `relay_url`: dedicated HTTPS listener reachable
  from the measured guest at `/trusted-meter/relay`. Its URL port must match the
  listener. A terminating TLS proxy cannot substitute another server key.
- `guest_port`: opaque assigned tunnel port, default 8080. Destination addresses
  come from the assigned ticket and must be literal IP interfaces.

The verifier is the approved google/go-sev-guest `check` executable, invoked
with CRL/network checks, explicit product/TCB/measurement/report-data constraints
and bounded execution time. The issuer command receives only
`{"record": <attestation>, "snp_report": <hex>}` on stdin and returns the strict
`{"record": ..., "signature": <hex>}` envelope on stdout. It must independently
validate the measured workload, chip-to-Host assignment and protected-time /
rollback policy before signing, using owner-managed trust. Gateway does not
supply an issuer private key or fabricate platform qualification. Configured
commands have bounded input/output/time and never receive prompts or outputs.
Policy is reloaded for every request; changing the relay endpoint requires a
Gateway restart. Running services follow the moving TEST channel.

Unit and contract checks use fake owner/guest transports and isolated local
storage. Cross-service and hardware coverage belongs to the scheduled CI batch.
