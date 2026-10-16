# Network policy and recovery custody

The authority maintains the current NetworkPolicy record100 and its linked
RecoveryPolicy record114. The bootstrap supplies their initial values; later
changes use the normal ordered authority protocol. A policy change preserves the
network identity, requester history and existing content. It does not itself
grant membership, hosting, reviewing, voting or confidential-content access.

The separate HyperNetSuite provides `authority-inspection policy get`, `prepare`,
`inspect`, `sign`, `assemble`, `apply`, `discover` and `accept`. Its
`Documentation/NetworkPolicies.md` describes the installed command workflow.
[PolicyContract](PolicyContract.md) defines the canonical fields and constraints.

## Ordered replacement

`AuthorityPolicyApply` requires a current AdministerPolicy capability over the
network. Application identities cannot perform this operation. The request binds
the exact predecessor policy and recovery records, the next policy generation,
its predecessor digest and the complete permission snapshot. The resulting
governance must remain valid; changing configuration does not bypass capability
checks or the mandatory manual-review baseline.

If custody is unchanged, the new policy retains the exact recovery reference.
If custody changes, record114 also advances by one generation and binds its exact
predecessor. Both records commit atomically at the same authority order. Stale
predecessors, changed dependencies and mismatched snapshots refuse. An interrupted
request resumes its original signed bytes; it is not silently reconstructed under
new permissions.

## Recovery custody

OwnerSingle uses one key. OwnerThreshold uses two of three keys attributed to one
owner. SharedThreshold uses two of three distinct enrolled principals and their
keys. A newly introduced principal must have current membership. Signatures and
declared identities are verifiable; software cannot establish that different
people independently control them.

A custody replacement needs the old policy's threshold approval and a separate
acceptance from the new custody set. Both cohorts sign the exact new record114.
The new signatures must match its declared `acceptedBy` set, whose values are
SHA256 fingerprints of the public keys, matching bootstrap custody. Duplicate,
foreign or mixed-payload signatures cannot satisfy the threshold. Current and
historical key-role reservations prevent custody keys from being reassigned to
another authority class.

An immutable shared-custody policy must remain shared and immutable within the
same network identity. Neither an administrator nor an owner-only recovery path
can override that restriction. Other permitted threshold reductions or
shared-to-owner changes remain subject to each client's explicit trust acceptance.

## Discovery and client acceptance

An already admitted ordinary requester stream can discover only the current
network policy and its linked recovery custody without administrative inspection
capability. Discovery accepts no content, mailbox, search or file selection. It
does not admit an arbitrary new signer or restore a revoked capability. Historical
requester streams may inspect this limited network contract without regaining
content or service authority.

Normal permission-dependent requests discover policy before selecting private
resources and bind its exact generation. Capability results include both policy
records. A concurrent replacement cannot silently authorise the effect under a
different contract. Recipient and sealed publication records bind their prepared
context; submission does not insert discovery after that context was signed.

Clients retain certified policy changes for inspection. A weaker route or custody
contract requires acceptance of the exact printed trust digest before ordinary
work continues. Acceptance cannot disable the client's separate route,
publication or placement minima. Intrinsic withdrawal, revocation and finite
owner-metadata inspection remain available under their own ownership checks;
they confer no new serving authority or confidential-content access.

## Authority loss

[Exceptional network recovery](NetworkRecovery.md) is a separate operation. It
uses the latest recovery policy authenticated by the retained requester floor,
including committed custody replacements. Missing evidence for a newer retained
generation cannot be replaced with the bootstrap policy or obsolete custody keys.
Retain the current policy bytes, floor and epoch evidence together.

Recovery after authority loss establishes a new network identity and requires
independent acceptance. It cannot restore revoked grants, recipient access or
old host consents as live authority. Content archives and recipient-root recovery
also remain separate; neither changes the network's recovery custody.
