# Scoped admission

Scoped admission is an optional native authority contract for a private registrar.
The original signed invitation, membership and grant workflows remain available.
An owner authorises a registrar public key and a distinct descriptor signing key.
The registrar has no general membership, delegation, administration, publication
or hosting grant. The authority accepts only the fixed policy's role templates.

A policy can reserve up to 64 participant slots. Each slot can contain a reader
(role 0), a chat participant (role 1), or both. Each role generates its own member
key and separate relay possession key. Reader authority is action 0; chat also
gets action 30 for one exact application service. Route authority is action 0 for
the exact authority and destination routes. All generated grants have delegation
depth zero. Hosting and application-level moderation are outside this contract.
Core does not interpret Person/Agent classification or application operator
consent. It certifies an opaque application binding alongside the role identities;
the application independently enforces its own consent and class policy.

Policies and memberships support finite validity or `UntilWithdrawn`, subject to
the current parent grant and its ancestors. Candidate possession challenges last
at most 60 seconds. Current authority disclosures and execution proofs retain
their ordinary finite deadlines. Route vouchers last between 120 seconds and one
day, additionally bounded by current service and host consent. Permanent
membership does not authorise an expired voucher, stale clock, withdrawn service
or expired execution proof.

The policy names a delegated owner grant with actions 0, 10 and 11 (and 30 for
chat), exact relay/authority/destination routes, role limits, voucher quotas and
validity. Its templates and descriptor key are immutable. The owner may withdraw
the policy; renewal and new admissions then stop. A new descriptor key requires
a new explicit policy and link acceptance rooted in the retained network trust.
The private registrar configuration must not be writable by the public listener.

## Reuse and replay

A claim is 32 bytes. Its first eight bytes encode a nonzero big-endian issuance
ordinal; the remainder is random. Issuance is serialised across this network's
registrars. New ordinals must exceed the fresh authority disclosure's claim floor.
An exact existing claim can resume without spending another slot or changing its
request, keys or application binding. Unknown old ordinals cannot create effects.

Retirement preserves the slot, material predecessors and monotonically increasing
assignment generation. A later explicit admission can reuse that bounded slot;
it cannot resurrect the old claim. Native requester streams use an assignment
origin and refuse old-generation operations. Retired requester streams are removed
only by their owning native transition. Generic grant revocation tombstones are
never deleted. Route renewal uses the same four-or-fewer voucher identifiers;
early handover preserves usage and the original active-session deadlines.

A previous manual account can be adopted only when the owner policy pins its
exact initial membership in the legacy roster and the candidate proves its own
existing keys. Adoption records a terminal successor for that manual membership,
retains its existing requester floor and stream, and issues restricted native
role grants. Old grant records remain but cannot add powers to the scoped account.
Only that first adoption preserves the old stream. After retirement, a new
admission uses a new scoped origin; uncertain local effects remain in the client's
journal. Neither migration nor rejoin resets a floor or reprovisions an identity.

## Wire contract

`AuthorityAdmission` is a versioned ordinary authority operation. Governance
records 180 and 181 contain the policy and slot respectively. Unsupported record
or operation versions fail closed. Native slot proofs include exact role keys,
signed join requests, claim digest, application binding, assignment and current
material. Descriptor-purpose inspection is a finite `AuthorityAdmissionContext`
read, independently verified by Suite. No private registrar or participant keys
appear in this disclosure.

The packaged administration and candidate commands are documented in Suite's
`Documentation/ScopedAdmission.md`. Shared password/invitation listeners must
reserve their outer claim durably before publishing the native claim, retain
unresolved outcomes, and verify native certified principals and application
binding before handing them to an application admission extension.

A network retains at most four immutable registrar policies. Withdrawing a policy
does not erase its purpose or claim fences. Participant slots within each policy
remain reusable; changing passwords or invitations does not create a new policy.
