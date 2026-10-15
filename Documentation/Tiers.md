# Tier administration

Tier rank orders policy for display. Explicit grant actions and scopes determine
authority. A current tier restricts every grant pinned to that tier's authenticated
history; an older grant reference cannot restore removed rights. Changing a tier
does not rewrite grants or silently increase their actions, scopes, limits or
delegation depth. Each operation intersects the grant with current actions, exact scopes, quotas
and delegation depth across its complete parent chain. Removing SearchCatalogue
can leave ReadPage available. Narrower quotas constrain actual use rather than
invalidating surviving rights. New grants must fit the parent's complete current
intersection; dormant rights or excess depth cannot be issued in anticipation of
a later policy widening. Revoked grants cannot
be restored by a tier edit or by restoring an old local checkpoint.

The separate Suite supports list, context, proposal preview and reviewed apply.
Tier creation and editing require AdministerPolicy9 in every old and new scope.
Applications cannot administer tiers. Listing all tiers requires network-scoped
administration. A scoped administrator can request an exact permitted tier's
context or create a tier inside the administrative grant's scope. At most256
active tiers are admitted; IDs, generations and exact predecessors are durable.

## Wire interface

Discovery uses `[200,1,action,grantId,tierIdOrAfterOrNull,minimumPoint]`, with action
AuthorityTierContext or AuthorityTierList. Discovery has revision0 and no expected
versions. Context returns `[201,1,action,versions,recordBytesList]`; list adds a
sixth next-tier-ID-or-null field and returns up to32 tier rows. The versions cover
the administrator's complete capability closure and selected current tiers.

A specification is `[id,rank,label,actions,scopes,maximumDelegationDepth,limits]`.
Preview and apply use
`[200,1,action,grantId,previousTierBytesOrNull,specification,expectedSnapshot,token]`.
Action is AuthorityTierPreview or AuthorityTierApply. The signed resource is the
tier ID; revision is1 for creation or the exact previous generation plus1. The
signed expected versions equal expectedSnapshot's references. A proposal digest
binds network, incarnation, requester, grant, previous bytes, specification and
exact dependencies. Read-only progress may advance the causal point without
changing that proposal.

The certified preview response is `[201,1,action,versions,previewPage]` where
`previewPage = [requestDigest,effectiveDigest,impactDigest,impactCount,pageIndex,
impacts,nextPageToken]`. The encompassing signed intent supplies operation identity
and Snapshot; the signed OperationResult supplies Permit/Refuse and its refusal
code. These fields are the operational mapping of PolicyPreview106. A permitted
page has code0; refusal never presents a partial preview as complete.

EffectiveDigest binds the exact proposal and all current governance and domain
versions. Impacts conservatively enumerate records whose dependencies refer to
the affected tier or grant, recursively, with a digest of each subject's complete affected version set and the
proposal digest. These are affected dependencies, not claims that each changes its
effective permission. The proposed specification or grant and the authenticated
capability closure explain the resulting restrictions. Each impact is
`[category,id,beforeDigest,proposalDigest,4]`. Each category/ID appears once;
beforeDigest hashes the canonical array of its exact affected VersionRefs, sorted
by kind and ID. Reason4 denotes a capability
intersection requiring review. Categories follow PolicyContract's Impact contract.

Dependency extraction includes validated recipient and sealed-record payloads,
native author and reviewer statements, and signed application consent. Opaque
content and foreign signed metadata are not decoded as local authority dependencies.

Pages hold at most128 entries and the complete preview at most65536. The client
verifies consecutive page indexes, identical request/effective/impact digests,
unique entries and the complete count and digest before offering reviewed apply.
A cursor cannot be moved to a changed policy view. Apply supplies effectiveDigest
as token, rechecks complete current authority and exact dependencies, and compares
the policy view atomically at commit. A concurrent relevant change refuses with
StaleSnapshot12; an invalid continuation returns CursorScope32; excess impacts
return PreviewLimit33. Apply returns the exact new record and creation height.
Signed mandatory mutation evidence and the record commit together.

## Delegation and revocation

AuthorityGrantPreview and AuthorityGrantApply wrap existing exact delegation or
revocation parameters:
`[200,1,action,originalParametersBytes,tokenOrNull]`.
The original action is AuthorityDelegateGrant or AuthorityRevokeGrant. The outer
signed resource, revision, expected dependencies and causal floor retain the
original operation's meaning. Preview uses the same seven-field preview response;
apply compares the same complete policy view before the original mutation runs.
Its reply is the original finite mutation result with action AuthorityGrantApply.

Delegation still requires action11 and attenuation of parent and current tier
rights, scopes, validity, quotas and depth. Revocation still requires action12,
the exact target and current authorising chain. Its tombstone permanently rejects
the target and descendant chains. Preview creates no grant, reservation or audit
mutation. Apply evidence retains the signed outer review token and derives the
original exact grant or tombstone. Existing direct APIs remain available to
programmatic clients; the installed administrative workflow uses reviewed apply.
