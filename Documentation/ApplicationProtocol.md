# Application authority protocol

Use the signed version-1 Request and Envelope in [Protocol](Protocol.md) over the
configured TLS authority endpoint. Exact payload bytes, public signing key and
network are signed under the existing `HyperNet/Request/1` domain. Public keys
are 32-byte lowercase hexadecimal Ed25519 keys. Request IDs are 16-byte lowercase
hexadecimal values. Application commands use no bearer token or impersonated
member identity. Unknown and duplicate fields are refused by the strict schema.

## Consent and creation

An application signs this command in a normal fresh envelope:

```json
{
  "type": "ApplicationConsent",
  "ownerKey": "OwnerPublicKeyHex",
  "expires": 2000000000,
  "namespaces": ["Board"],
  "pageIds": null,
  "permissions": ["PagesRead", "PagesSubmit"],
  "reviewPolicyDigest": null,
  "reviewMode": null
}
```

`ApplicationConsent` is proof of possession and agreement, not an executable
command. The owner signs `ApplicationGrantCreate { "consent": Envelope }`.
The authority verifies both envelopes, both timestamps, network and exact owner.
The consent signer must be a separate unassigned identity. Retained application
records, existing roles and active pending invitations exclude key reuse.
Configured authority signing keys also cannot become applications.

`expires` is an integer Unix timestamp, later than authority time, at most seven
days ahead and no later than current owner membership expiry. `namespaces` holds
one to eight sorted, unique strings valid under the existing Pages namespace
syntax. `pageIds` is null for all pages in those namespaces, or one to sixteen
sorted, unique 16-byte lowercase hexadecimal IDs. Permission strings are unique,
lexicographically sorted and drawn from:

| Permission | Commands |
| --- | --- |
| `PagesRead` | `PageList`, `PageRead` |
| `PagesSubmit` | `PageSubmit`, own `PageWithdraw` |
| `ReviewInspect` | `PageQueue`, `PageInspect` |
| `ReviewDecide` | `PageReview` with Approve or Reject |

`ReviewDecide` requires `ReviewInspect`, a canonical 32-byte hexadecimal
`reviewPolicyDigest` and `reviewMode` equal to `Manual` or `Automatic`. Otherwise
both policy fields are null. Review permissions require an administrator owner.

A successful creation returns `result.application`:

```text
ApplicationRecord {
  ownerKey, applicationKey, grant, grantDigest, expires,
  namespaces, pageIds, permissions, reviewPolicyDigest, reviewMode, revoked
}
```

`grant` is the exact owner's signed envelope, including the nested consent.
`grantDigest` is its normal request digest. All remaining scope fields repeat
that consent; `revoked` starts false. No private keys are returned.

## Lifecycle

| Command | Fields | Caller and result |
| --- | --- | --- |
| `ApplicationGrantGet` | `applicationKey` | Recorded owner or application; `application`, `authorityRevision` |
| `ApplicationGrantList` | `after` (key or null) | Current ordinary owner; `entries`, `next`, `authorityRevision` |
| `ApplicationGrantRevoke` | `applicationKey` | Recorded owner or application; `applicationKey`, `revoked: true` |

List includes only the caller's own records in application-key order, strictly
after `after` when supplied. At most eight entries exist per owner, and each
complete reply is bounded to 262144 bytes. Large retained proofs can require
multiple pages. When more records remain, `next` is the last returned application's
key; supply it as `after` for the next request. The final or empty page has
`next: null`. Exact signed grant bytes are never rewritten to reduce a page. Get and revoke remain available after grant or owner
expiry or revocation while the record exists. Applications cannot list grants,
create another grant or delegate their access. There is no update command.

Create and revoke use ordinary exact-request transaction receipts. Retrying the
same signed request returns its receipt only to the authorised caller; a reused
request ID with different bytes returns `RequestConflict`. Read operations create
no mutation receipt. Every successful application command preserves schema 8.

## Page integration

Applications sign ordinary Page commands. List and queue require an explicit
allowed namespace; returned entries additionally obey the page-ID restriction.
ReviewInspect is required even for inspection of an application's own submission.
PagesSubmit permits withdrawal only of that application's own page. It does not
allow withdrawing an owner's or another application's page.

An application `PageReview` includes these additional fields:

```json
{
  "applicationPolicyDigest": "PolicySha256Hex",
  "applicationReviewMode": "Automatic",
  "reviewExpires": 2000000000
}
```

Policy and mode must exactly match the grant. `reviewExpires` is required for an
application review, later than authority time and at most 300 seconds ahead. It
is checked on admission and again immediately before the publication transaction.
An ordinary human PageReview omits policy and mode; it may carry `reviewExpires`
when a bounded external-review job supplies the recommendation.
Existing page ID, expected version, revision, digest, profile, author, namespace,
audience, submission digest and decision bindings remain mandatory and unchanged.
PageDescriptor and PageBundle shapes remain unchanged; proofs retain the actual
application author or reviewer key. Current authority permission is always checked
separately from archived signature verification.

Typical refusals are `InvalidApplicationConsent`, `InvalidApplicationScope`,
`SeparateApplicationIdentityRequired`, `ApplicationPermissionDenied`,
`ApplicationNamespaceRequired`, `ApplicationReviewMismatch`,
`ApplicationUnavailable`, `ApplicationQuotaExceeded`, `InvalidReviewExpiry`,
`ApplicationReviewExpiryRequired`, `InvalidExpiry`,
`StaleRequest` and `ClockRollback`. Common authority and Pages errors also apply.
Errors do not commit partial state. Capacity and bounded-resource details are in
[Applications](Applications.md).
