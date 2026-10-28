# Scoped applications

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

An application uses its own Ed25519 identity and a separately retained authority
floor. Its owner and the application approve the same exact grant. Neither
receives the other's private key. Registration establishes an application class;
it does not make the application a member, host, reviewer or voter.

The owner needs current DelegateGrant authority through the exact parent grant.
InspectAudit is not required. A scoped delegation context reveals only that
parent's dependencies, the selected tier and an optional child issued by the
owner. It cannot enumerate other owners' applications or audit records.

## Consent and registration

1. Initialise separate owner and application profiles from an independently
   accepted bootstrap. Independently authenticate the owner's public key.
2. Obtain the owner's scoped delegation context and create the exact child grant.
   It is inert until the application is registered.
3. Prepare an offer containing that grant and the owner's signed acceptance.
   The application inspects the offer and signs the identical acceptance bytes.
4. Refresh the owner's context and submit registration. Retain the signed request
   and the resulting historical confirmation for interruption recovery.
5. Initialise or reopen the application's own floor, obtain its stream status and
   inspect its lifecycle record. Never import the owner's cache or floor.

Grant actions and scopes use [PolicyContract](PolicyContract.md). The application
grant cannot include DelegateGrant or further delegation depth. Its validity is
at most seven days and lies within the accepted grant's validity. Changed rights
require a new application key. Acceptance has a separate interval of at most
24 hours and binds the exact network, incarnation, parties, grant and validity.
A later unrelated authority operation does not alter this agreement.

Every domain use must verify the exact grant named by ApplicationAdmission,
the application's current validity, absence of withdrawal, the full grant chain,
current owner and ancestor admission, tiers, revocations and domain restrictions.
An unrelated grant addressed to the same application cannot add permissions.
Registration and historical confirmation alone never authorise a domain action.
Mail, files, SSH, hosting, media and publication retain their own consent rules.

## Inspection and withdrawal

The owner or application can inspect its retained admission, accepted grant and
withdrawal. The owner can list its complete application set as bounded metadata.
These operations report lifecycle records, not current permission to use a domain.
They remain available after ordinary grant expiry or revocation.

Either party can withdraw consent through its own permanent request stream.
Withdrawal is restrictive and does not require RevokeGrant or a still-current
delegation grant. It creates an immutable ApplicationWithdrawal record. Neither
an old acceptance nor an exact registration retry clears that record.

Revoking the accepted grant or any ancestor also removes its effective authority.
Revoking only an owner's initial reader grant does not revoke that membership
or unrelated grants. Previous disclosure cannot be undone: withdrawal does not
erase plaintext or other bytes already retained by an authorised recipient.

## Persistence and bounds

Version 1 ApplicationAdmission and all ApplicationWithdrawal records are create-only.
Explicit renewal replaces a version 2 admission and its current signed evidence. Application keys remain reserved after expiry
or withdrawal. Streams are permanent; admission never resets a fenced stream.
The authority supports 256 total requester streams, including root subjects and
ordinary members, and 2048 governance records. Capacity refusal creates no partial
admission, stream or mutation evidence. No expiry-based reclamation is performed.

Owner listing returns the complete sorted metadata set without pagination or
truncation. With a distinct owner, at most 63 application entries can exist.
Full grant bodies are available through individual inspection. Ordinary request
dependencies retain their 64-reference bound; listing uses a separate bound.

Retries preserve the exact durable request and completion. A fresh certificate
can prove an earlier registration after its acceptance expires; that historical
proof does not restore access. Keep each profile's private journal, causal floor,
generation minima and pending request together. Do not reset them to recover
from an uncertain outcome.

[ApplicationProtocol](ApplicationProtocol.md) defines the wire records and
operations. The independent HyperNetSuite application commands provide the local
consent and lifecycle workflow. They do not start a model, provider or domain
service on the application's behalf.

## Same-rights renewal

Renewal preserves the application key, owner, immutable grant, actions, scopes,
limits, tier and exact parent. It replaces the admission's finite validity and
increments its generation. The first explicit renewal migrates a version 1
admission to version 2. Old registration bytes retain their original meaning.

Fresh owner and application signatures approve each new validity interval of at
most seven days. The owner must still have DelegateGrant through the same exact
parent, and every current ancestor, tier, admission and revocation check applies.
An expired application can renew while its parent remains valid. A version 2
admission supplies its exact leaf grant's effective validity; it never extends
another grant or changes the grant's rights. Withdrawal and revocation cannot
be undone by renewal. A compromised application requires replacement, not renewal.

The operation replaces one admission and its current consent evidence. It does
not create another child grant or requester slot. Requester generations, sequence
floors and unresolved requests remain intact. Retry the exact pending renewal
before starting another owner operation. No unattended renewal permission is
implied by a prior acceptance.
