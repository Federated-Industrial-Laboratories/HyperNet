# Permission scopes in 0.9.1

[Documentation](ReadMe.md) | [Policy contract](PolicyContract.md) |
[Application streams](ApplicationStreams.md) | [Upgrade and recovery](UpgradeRecovery.md)

Version 0.9.0 used action codes 29 and 30 for both application streams and sealed
publication. A network-wide grant could satisfy either resource check. Version
0.9.1 requires a purpose-specific terminal grant before either family can act.

The terminal grant is the grant submitted for the operation. It and every
non-root ancestor must have the same resource purpose. The complete parent chain,
current tiers, admission, expiry, revocation and operation-specific consent still
apply.

## Action interpretation

| Terminal grant scopes | Action 29 | Action 30 | Permitted use |
| --- | --- | --- | --- |
| Service only, kind 3 | Manage application service | Connect application service | Streams for the explicitly listed service IDs |
| Object and/or Namespace only, kinds 2 and 1 | Review sealed Page | Finalise sealed Page | Sealed operations within the listed objects or namespaces |
| Network, mixed purpose, or another scope kind | Ambiguous for execution | Ambiguous for execution | Neither family may use this terminal grant |

Every scope in the terminal grant must belong to the selected family. Merely
including one matching Service or Object scope is insufficient. Adding a Network
scope does not make a specific grant acceptable. Current scope matching still
requires the exact service or the permitted object/namespace.

Sealed publication checks require both 29 and 30 under the existing operation
contract. The hotfix does not separate those existing checks into new operations.
Other permission codes retain their existing meanings.

For the current sealed finalisation CLI, select an exact Object scope for the
publication object. Its policy-context and freeze steps require that exact scope;
a Namespace-only grant does not complete that workflow by itself.

An accepted bootstrap root may remain broad when it authorises an explicitly
reviewed, narrower child through ordinary delegation. Broad tiers may restrict
that chain under the existing rules. A broad root cannot itself execute either
family as the terminal grant. Every non-root ancestor must have the same purpose
as the terminal grant. This prevents a broad delegated grant from obtaining
sealed access by issuing an Object-scoped child. Ordinary attenuation also
prevents a Service-scoped parent from delegating Object or Namespace access.

## Existing networks and grants

Signed records, bootstrap identities, action numbers and stored history retain
their bytes. There is no automatic conversion of old grants, no new root grant,
and no interpretation of an old signature as permission for a new action code.
Correctly scoped grants remain eligible subject to all current checks.

A Network-scoped or mixed-purpose non-root grant anywhere in the chain stops
these operations. A later tier restriction does not rewrite a grant's signed
scope set.
Inspection of historic signed records does not prove present permission. Repeated
reads and live service checks apply the new restriction too.

Before upgrading, inventory grants used by stream service owners, applications
and sealed reviewers. Record their IDs, subjects, current tiers, complete scopes,
all ancestors, expiry and active service/publication dependencies. Use separate
Service-only and Object/Namespace-only grants when a role needs both families.
Review the exact proposed scope and action names before issuing each grant.

Existing root grants can authorise ordinary delegation when they retain action
11, sufficient depth and current tier/limit coverage. The bootstrap's reserved
administrator identities cannot be used as delegated child subjects. Use an
ordinary admitted principal for the scoped role. Delegation does not itself
admit a member.

The Suite's grant workflow is `authority-inspection grants delegate-preview`
followed by `grants apply` with the exact reviewed preview digest. Supply the
existing audit context, parent grant, finite validity, current tier, limits and
an admitted subject. Start from accepted bootstrap authority or an already
purpose-specific ancestor chain; creating a narrow child beneath a broad
non-root grant cannot repair the chain. Never edit a signed grant file or restore an old checkpoint
to bypass the restriction.

For an already admitted application, the accepted grant reference is exact.
Same-rights renewal cannot change its scope. Use the supported withdrawal and
fresh admission workflow (applications withdraw --application-key OLD_KEY, then
new offer, acceptance and registration) with explicit owner/application consent when the
existing admission cannot bind a replacement grant. A withdrawn application key cannot be registered again; use a fresh application
key and retain the previous identity in audit history. Do not describe this as
unchanged identity or rights.

A service registration binds its original owner and management grant. If that
grant is broad and the owner is an ordinary admitted principal, issue a scoped
replacement grant and register the next service generation with the same owner
and operator. A bootstrap administrator cannot obtain a delegated child grant.
For such a root-owned service, withdraw the old service and create a fresh
service ID under an ordinary admitted owner with a scoped management grant. A
withdrawn service ID cannot be reused. Update the receiving binding and client
targets through their normal explicit consent steps.

Sealed publications recheck their original review authority during live use.
An old broad reviewer grant can therefore make already published sealed content
unavailable for new protected reads. Obtain a fresh scoped review and publication
through the normal sealed workflow. A new grant alone does not rewrite an old
review statement or publication. Already disclosed plaintext cannot be retracted.

## Coordinated upgrade

Stop new ordered mutations from clients, services and automation, and drain active
streams. Resolve pending mutations through their retained status and recovery
workflow, including an explicit fence where required, while the complete authority
committee still runs 0.9.0. Finish every voter's old-version catch-up before replacing
any binary.

Use a fresh Suite `authority-inspection inspect` result to verify the final quorum
state. Check each voter's `authority-replica live-status`, then stop the complete
committee and retain each final `Stopped` result. Use `authority-replica status`
with that voter's independently retained minimum generation to inspect its stopped
journal. Every voter must report `appliedHeight == committedHeight`, and those
heights must match across the committee. Retain the certified inspection and all
stopped results together with the complete current journals, state objects,
history and independent generation floors. A local status alone does not prove
quorum readiness.

If any voter is behind or has committed but unapplied commands, do not start it
with 0.9.1. Complete catch-up and application using the intact old-version committee,
then repeat the stopped checks. Do not initialise a replacement journal, lower a
floor or substitute an older backup to obtain matching heights.

This boundary is required because committed but unapplied commands are executed
by the running version. An old broad-grant command could succeed under 0.9.0 and
refuse under 0.9.1. Fully applied state is retained without re-executing its past
effects; preserving signed bytes alone does not make a pending old suffix safe.
An automatic checkpoint cutover or mixed-version replay is not provided.

Once these checks pass, upgrade the complete authority committee and corresponding
Core endpoints and Suite clients before resuming protected operations. Old binaries
retain the earlier broad interpretation; a mixed authority committee is unsupported
even though the wire encoding and protocol number are unchanged.

Use independently authenticated signed packages and the normal stopped,
side-by-side replacement process. Retain profiles, keys, requester floors,
journals, content stores, pending operation records and package trust. Resolve
uncertain effects from retained state after current permission is established.

After upgrade, check a refused broad grant, a successful explicit scoped grant,
cross-family refusal, expiry/revocation and the affected service/publication
workflow. A refusal is not a transport failure and must not trigger a direct
connection fallback. Downgrading to 0.9.0 would restore the earlier permission
interpretation and is not a permission-recovery procedure.
