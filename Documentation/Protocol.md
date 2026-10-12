# Authority and service protocols

The current wire representation is bounded canonical CBOR. Signatures cover exact
purpose-separated bytes, network/incarnation identity and the fields defined by
[WireContract](WireContract.md). Parsers reject alternate encodings, unknown
fields, duplicate fields, trailing data and values outside the declared bounds.
There is one current protocol representation.

[AuthorityContract](AuthorityContract.md) specifies challenge freshness,
requester streams, acknowledged positions, ordered consensus results and
checkpoint/history verification. [PolicyContract](PolicyContract.md) specifies
explicit capabilities, restrictive state and exact-version dependencies. A client
must verify the complete result and its current retained floor before displaying
protected content or completing a serving effect.

Network peer connections use TLS1.3 with pinned transport identities. Redirects,
ambient proxies, public trust roots and implicit endpoint discovery do not change
those pins. The installed authority and service control sockets are private local
interfaces. They do not expose a public reader transport or promise anonymity.

## Exact requests and retries

A requester signs and durably retains its complete operation before sending it.
The stream binds its generation, sequence and acknowledged position. Retrying an
uncertain operation reuses the exact bytes; a new body needs a new operation.
Quorum results bind the original request, disposition and typed domain result.
A historical success is not fresh permission for another action.

A serving recipient independently validates the authority result and records the
remote claim before an effect. Received content and exact completion reports are
retained before requester acknowledgement. Interrupted caches are reconstructed
from certified results; missing, conflicting or stale durable state is refused.

Immutable Page sources, approved bundles and media manifests have exact content
identities. Required objects form a finite declared input closure. Content is
never reinterpreted as commands or used to choose local credential files,
application programs or unapproved network routes.

## Domain contracts

- [Pages](Pages.md) and [PageMedia](PageMedia.md): publication, review, explicit reads and canonical media.
- [Federation](Federation.md): separate network trust, bilateral leases and qualified foreign provenance.
- [MailProtocol](MailProtocol.md): owner-bound mailbox identity and one-use MLS packages.
- [TransferProtocol](TransferProtocol.md): immutable encrypted offers and recipient-selected placement.
- [SshProtocol](SshProtocol.md): native key possession and supervised fixed-command access.
- [ApplicationProtocol](ApplicationProtocol.md): independently consented restricted application credentials.

All numeric wire, object and proof bounds are part of these contracts. Discovery
responses include complete item provenance up to the actual encoded/proof
capacity, then return a continuation after the last disclosed item. Revoked or
expired permissions remain authoritative during pagination and retries.
