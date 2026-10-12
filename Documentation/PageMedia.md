# Static Page media

Page media consists of approved static assets on explicitly consented media
hosts. A Page binds each asset's profile, dimensions, exact byte length, SHA-256
digest, selected host identities and required copies. It also binds alternative
text and finite local motion parameters. Viewers generate animation frames
locally; the network transfers the static asset.

`HyperNetRaster/1` contains row-major RGB bytes. `HyperNetVector/1` contains
bounded typed geometry. The [HyperPage contract](HyperPage.md) defines both
profiles. Media consumers validate these canonical objects and do not interpret
SVG, XML, fonts, stylesheets or executable content. Importing an external format
is a separate local conversion step and cannot extend the accepted wire grammar.

## Host and placement authority

Media hosting uses the admitted deployment's dedicated role 2 service identity.
Page bundle hosting uses role 1 and does not inherit media storage rights. The
operator signs an `AuthorityPageHostProfile` that embeds the exact deployment
manifest and selects its role, service key, writable volume, namespaces, state
admission, maximum asset bytes and retention. Those values must fit the admitted
role and volume consent. Retention is at most seven days.

`PageHostRegister` records this profile under current runtime management and
hosting capabilities. The authority separately checks the exact deployment,
operator consent, service registration, registrar and manager. `PageHostWithdraw`
advances the host record to a withdrawn state. Possessing a service key, a member
identity or an old signed profile cannot restore current hosting rights.

`PageMediaPolicy` requires `AdministerPlacement` (21) for the named namespace.
It sets a minimum of one through three distinct selected host identities. With
no explicit policy, the minimum is one. Approval requires the greatest of the
Page manifest count, its retained reservation count and the current namespace
minimum. Distinct identities alone do not prove independent physical machines
or availability.

## Submission and review

Submitting a Page reserves every declared asset against exact current media
host versions. Each selected host is charged the complete declared byte length and a
conservative canonical encoding of its exact asset, host reference and complete
copy receipt. The physical state admission covers two banks and their headers;
only the usable serialized capacity of one bank admits live reservations.
Existing unexpired reservations count against this same budget. The publisher's current signed limits and
the canonical record and state budgets also apply. There is no additional fixed
per-author asset-count quota.

An asset reservation binds its immutable Page revision, descriptor, selected
hosts, copy requirement, upload deadline and expiry. Upload ends within 24 hours
and no later than the reservation expiry. Retention ends at the earliest author
statement, deployment or selected host retention deadline. A changed source
creates a different revision and new reservations; old bytes cannot silently
be reassigned to it.

A media host's copy receipt signs the network and incarnation, exact asset and
host versions, request digest, complete object digest, byte length and recording
time. `PageMediaReceipt` commits that receipt only for the current pending
revision and selected live host. The host or the authorised publisher may
submit it. The receipt demonstrates the host's assertion of an exact complete
copy; it is not a review decision.

A reviewer must independently retrieve and validate the complete asset, inspect
its static representation, then issue `PageMediaInspect` naming the retained
copy receipt. The authority binds this acknowledgement to the reviewer's exact
grant, application policy if applicable, request and short expiry. Final Page
approval requires this reviewer's current inspection of every asset and enough
current consenting hosts with matching complete-copy receipts. Copy receipts
alone cannot approve content. Approval of text cannot omit its declared media.

## Finite media effects

`PageMediaAuthorise` names one exact asset, host, operation, offset and byte
count. Upload also binds the exact chunk digest. A request handles one through
32768 bytes and must remain within the declared object. Upload is restricted to
the current pending author; inspection requires the pending revision and review
rights; read requires its current approved publication. The selected service is
the only permitted effect recipient.

The service verifies the quorum result and its durable recipient state before
an effect. Its signed effect receipt reports the exact certified request and
completion; importing a receipt cannot authorise another effect. The receipt
also permits the requester to resolve an interrupted operation without repeating
an uncertain effect. Authority or host withdrawal denies fresh permissions.
Previously downloaded copies cannot be erased remotely.

Native applications require explicit `MediaSubmit`, `MediaInspect` or
`MediaRead` in their dual-signed Page application policy, intersected with the
current native grant, namespace and optional Page scope. An asset digest, Page
read permission or general application admission grants no independent upload
or review authority.

Page metadata and object delivery use the ordered authority contract described
in [Pages](Pages.md). Bulk media bodies stay with the consented hosts. Federation
and reader relay routes have separate admission and privacy contracts; these
native media records do not authorise a direct Internet reader route or a
foreign publication.
