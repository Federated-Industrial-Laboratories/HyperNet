# Scoped applications

An application uses its own Ed25519 request key. A member approves its exact
signed consent. The application never receives the member's private key and
never becomes a member. Independent clients use the same TLS request endpoint
and envelope as HyperNetSuite; the daemon has no client or model dependency.

The profile delegates native Pages and separately consented static media. A grant explicitly intersects
permissions, one to eight exact namespaces and optionally one to sixteen page
identifiers. There are no wildcards, namespace inheritance, updates or
subdelegation. A changed grant requires a new application key. Mail's existing
separate device grants remain independent. Application grants confer no mail,
transfer, SSH, hosting, replica, imported-page, federation or membership access.

Media bytes require separate `MediaRead`, `MediaSubmit` or `MediaInspect` rights.
Adding images to a page does not expand a text review or model disclosure grant.
`MediaInspect` requires a current administrator owner and explicit acknowledgement
after independent byte validation and static inspection.

Manual page review remains the default. `ReviewInspect` permits queue inspection.
`ReviewDecide` additionally permits exact pending approval or rejection and
requires `ReviewInspect`, a policy digest and an explicit `Manual` or `Automatic`
mode. Both review permissions require the owner to remain a current administrator.
Manual mode records an explicit client-selected decision; it is not cryptographic
evidence that a person was present. A program holding that credential can sign
Manual decisions. A policy digest identifies operator-selected policy bytes; it
does not prove that a model applied that policy correctly. An Automatic grant is an explicit delegation
of consequential review authority. Isolate its private key from untrusted content
and model tools, and give it the smallest useful namespace and expiry.

## Provisioning and use

1. Provision every broker under the current authority state-9 contract. Preserve
   authority floors, voter credentials and retained security history. Application
   commands preserve that exact schema; no earlier state format is accepted.
2. Provision a distinct application Ed25519 identity and the network's normal TLS
   trust. Keep the identity file private. Do not reuse a membership, authority,
   mail device, mail address owner or native SSH key.
3. Have the application sign `ApplicationConsent` with the exact owner's public
   key, expiry, resource lists and permissions. Send this proof privately to the
   owner. Both the proof and owner's approval must meet request freshness limits.
4. Have the owner sign `ApplicationGrantCreate` containing that exact envelope.
   Check the returned record and preserve the exact request for an uncertain retry.
5. The application checks `ApplicationGrantGet`, then signs permitted ordinary
   Page commands with its own key. List and queue requests must specify an allowed
   namespace. Specific-page operations must also match any page-ID restriction.
6. For review, inspect the pending submission, verify its signed bytes and send
   the existing exact-content `PageReview` fields. Supply the grant's policy digest
   and mode from trusted local configuration, plus a signed `reviewExpires` at most
   300 seconds ahead. Bound it to the review job's own expiry. Neither content nor output
   selects keys, policy, endpoints, permissions or executable commands.
7. The owner or application can sign `ApplicationGrantRevoke`. Check its confirmed
   response. Revocation remains available after owner or grant expiry or revocation.

[Application protocol](ApplicationProtocol.md) defines the independent wire API.
[Page protocol](Protocol.md) defines the content and publication proofs.
HyperNetSuite supplies application commands and a bounded private review-file
exchange. Other clients may implement the same contract. Provision credentials to
clients explicitly; a grant response contains public evidence, never private keys.

## Lifetime and recovery

A grant lasts at most seven days and never exceeds its owner's membership expiry.
Each operation checks the current owner, resource scope, grant expiry and
revocation. Review scope also checks current administrator status. A revoked or
expired application cannot replay an old successful page mutation to bypass these
checks. The owner can read or revoke their retained grant after losing membership;
this permits inspection and attenuation, not new access or delegation.

Published author and reviewer keys remain the actual signing identities. A page
signed by an application becomes unavailable if that application's grant or owner
loses the required permission. Authority and replica freshness is bounded to five
seconds and ends sooner at grant or owner expiry. Archived signatures prove exact
bytes, not current authorisation. Federation preserves this rule for a human
publication reviewed by an application; application authors cannot opt into
federation because their grants confer no federation-sharing permission.

The authority retains at most eight application records per owner and 64 globally.
Owner listing uses byte-bounded pages because exact signed proofs can be large.
Follow each returned `next` key as `after` until `next` is null; the complete reply
is at most 262144 bytes, and every admitted individual record fits one page.
Expired records without page, live replica-ticket or mutation-receipt references
are reclaimed when creating a grant. Revoked records remain until their original
expiry. Referenced records reserve their keys, including page ownership tombstones;
revocation does not erase publication history or copied content. Live receipts can
retain an otherwise expired record for the normal request retry period. Capacity
failure does not partly create a grant. Avoid unnecessary identity churn and plan
long-lived authored pages around these documented record bounds.

State 8 retains service role histories, transaction receipts and clock floors. Application reclamation refuses any backward authority time;
page application checks use at least the saved clock floor. Restore state only
through the normal authority recovery procedure. Do not remove referenced grants,
reset the schema or discard floors to downgrade a network.
