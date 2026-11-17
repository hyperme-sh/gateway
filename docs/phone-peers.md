# Phone peers

Phone provisioning is disabled unless `HYPERMESH_PHONE_CONFIG_FILE` names an
absolute private JSON file (no group/other permissions). It uses `wg-phone`
and the dedicated nftables table `inet hm_phone`; it never uses host peer
configuration. Infra owns the gateway key, endpoint, subnet and service wiring.
No configuration values or credentials are embedded in the package.

Configuration fields:

| Field | Meaning |
| --- | --- |
| `control_plane_id`, `plane_token` | One trusted Plane and its dedicated bootstrap token |
| `gateway_id`, `authority_origin`, `authority_token` | AIuditor's registered Gateway ID, HTTPS origin and verification token |
| `gateway_address` | Dedicated private IPv4 address/prefix, between /24 and /30 |
| `private_key_file` | Absolute private file holding this Gateway's separate WireGuard key |
| `listen_port`, `public_endpoint` | Dedicated UDP listener and advertised host:port |
| `conductor_origin` | HTTPS origin with the explicit private Conductor IPv4 address and TCP port |

The runtime image includes WireGuard, `ip` and nftables. The operator must
provision IPv4 forwarding and CAP_NET_ADMIN. Startup checks forwarding without
changing it. A process lock prevents two workers from managing this phone
interface. Restart resets only that interface and its firewall state; phones
must request fresh authorization. TEST follows its moving service channel.

Plane checks the current phone owner and enrollment, then obtains an opaque
grant from AIuditor's `client-mesh-grant` contract. It sends that grant with
`tenant_id`, `device_id`, and `request_id` to
`POST /api/v1/hypermesh-gateway/phone-peers`, authenticated by
`X-Control-Plane-ID`, `X-Phone-Plane-Token`, and the `X-Tenant-ID` cross-check.
This server door accepts neither renter nor host credentials. It never accepts
a phone private key, caller-selected address, route or application origin.

Gateway independently verifies the grant with AIuditor and matches the entire
authorization response. The phone public key can belong to only one active
registration. The response binds the identity, phone and server public keys,
address, endpoint, Conductor origin, allowed IP and absolute expiry. Plane
returns this public configuration to the native phone consumer.

Only the configured Conductor TCP destination is reachable from the phone
interface. Local Gateway services, host subnets and IPv6 are dropped. A kernel
timeout closes traffic even if the process crashes or cleanup fails. It expires
slightly before the grant deadline to account for command execution time.
Refresh must obtain fresh Plane/AIuditor authorization before expiry; a peer
handshake does not extend permission. Expired peers are removed by a periodic
sweep, and uncertain removal never frees their address for another phone.

An authenticated Plane can request immediate removal with the same identity
at `POST /api/v1/hypermesh-gateway/phone-peers/remove`. Failed-attempt cleanup
includes its `grant`, so it cancels only
that attempt and cannot remove a different request's newer peer. Omitting the
grant performs enrollment-wide removal and fences all pending authorization.
Revocation must stop
issuing grants; the timeout bounds access if removal cannot reach Gateway.
Native clients must treat expiry or an unavailable response as disconnected.
Conductor still applies its own AIuditor checks to every application request.

Unit contracts mock all HTTP and kernel commands. No package check applies
WireGuard or firewall rules. Operator configuration and the native consumer
remain separate from this service implementation.
