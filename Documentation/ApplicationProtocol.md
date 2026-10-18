# Application authority protocol

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

Application operations use the canonical signed intent, fresh recipient challenge,
ordered request, executed-result certificate and durable requester stream in
[WireContract](WireContract.md). Three distinct eligible authority signatures
certify an executed result. Transport authentication alone grants no authority.
The lifecycle interface uses the explicit local authority control channel.

All identifiers and public keys below are nonzero32-byte values. VersionRef,
Validity and Snapshot have their [PolicyContract](PolicyContract.md) meanings.
N and I denote network and incarnation. Arrays have exact arity and canonical
encoding. Unknown fields, actions, alternate encodings and duplicate signatures
are refused. No legacy permission-string consent is accepted.

## Identity and agreement

```
[127,1,N,I,1,null,ApplicationKey,OwnerKey,GrantVersionRef,Validity,Snapshot]
[128,1,N,I,1,null,ApplicationAdmissionVersionRef,WithdrawerKey,Snapshot]
```

Kind127 is ApplicationAdmission; kind128 is ApplicationWithdrawal. Both use the
application key as lookup ID. Generation is 1 with null previous. Both are
create-only and retain exact signed mutation evidence. Identity classification
and stream reservation survive expiry, withdrawal and grant revocation.

The inert acceptance payload is:

```
[200,1,"AuthorityApplicationAcceptance",N,I,ApplicationKey,OwnerKey,
 GrantVersionRef,ApplicationValidity,Nonce,AcceptanceValidity]
```

The exact owner and application signatures cover identical payload bytes. The
complete signed envelope is at most 1024 bytes. Nonce is a nonzero32-byte value.
ApplicationValidity spans at most 604800000milliseconds within the accepted grant;
AcceptanceValidity spans at most 86400000milliseconds within application validity.
Both must conservatively cover the original registration. Acceptance contains no
mutable Snapshot or requester sequence.

The accepted kind102 grant has the application as subject, the owner as issuer,
and an exact parent whose subject is that owner. It has zero remaining delegation
depth and excludes DelegateGrant. The owner must currently hold DelegateGrant
through that parent, including all ancestor, tier, scope, admission and revocation
checks. No member, reserved role or existing application key can be reassigned.

The offline offer is bounded to8192 bytes:

```
[200,1,"AuthorityApplicationOffer",OfferEnvelope,GrantBytes]
```

Acceptance replaces the owner-only envelope with the exact dual-signed envelope;
the grant bytes remain identical. An application authenticates its owner against
an independently verified key pin or the accepted genesis administrator set.

## Scoped delegation context

```
[200,1,"AuthorityDelegationContext",ParentGrantId,ChildTierId,
 OwnedChildGrantIdOrNull,MinimumPoint,MinimumVersions]
```

The requester must currently own the parent and have DelegateGrant through it.
InspectAudit is unnecessary. Optional child disclosure requires that exact child
to be issued by the requester under that parent and tier. Missing or unrelated
children share the same finite refusal.

A permitted value is:

```
[201,1,"AuthorityDelegationContext",Versions,[RecordBytes]]
```

The result contains the exact selected dependency closure, selected tier and
optional child, including policy dependencies, current admissions and relevant
revocations. It is limited to64 references and98304 encoded bytes. Pinned bootstrap
records may be supplied locally when constructing the typed view. This closure
is complete for its named selectors, not a complete governance enumeration.
Its private cache is separately typed and scoped.

MinimumPoint supplies a causal floor. Relevant returned records must meet their
retained generation minima, including equal-digest checks at equal generations.
Unrelated retained minima are preserved without demanding their disclosure.
The consumer verifies the quorum and ancestry and saves its protected floor
before exposing the result or installing its cache.

## Lifecycle operations

```
[200,1,"AuthorityApplicationRegister",ParentGrantVersionRef,
 AcceptedEnvelope,Snapshot]
[200,1,"AuthorityApplicationGet",ApplicationKey,MinimumVersions]
[200,1,"AuthorityApplicationList",OwnerKey,MinimumVersions]
[200,1,"AuthorityApplicationWithdraw",ApplicationAdmissionVersionRef,Snapshot]
```

Registration requires the current consenting owner. It atomically creates127,
its exact signed mutation evidence, the application stream and the owner's
completion receipt. Snapshot and expected dependencies name the exact pre-state.
An inert grant alone creates no application identity or stream.

Get permits only the recorded owner or application. List permits only the named
owner, equal to the requester. Neither requires live DelegateGrant or InspectAudit.
A permitted Get value is:

```
[201,1,"AuthorityApplicationGet",Versions,AdmissionBytes,
 AcceptedGrantBytes,WithdrawalBytesOrNull]
```

A permitted List value is:

```
[201,1,"AuthorityApplicationList",Versions,
 [[ApplicationKey,AdmissionVersionRef,GrantVersionRef,WithdrawalVersionRefOrNull]]]
```

List contains the complete owner's set, sorted by application key. There is no
pagination or truncation. At most63 rows fit the64 permanent stream slots when
the owner is distinct. Only this result permits up to192 returned version
references; ordinary exact expectations and dependency closures remain limited
to64. Get and List report lifecycle state, not current domain permission.

Withdrawal permits the recorded owner or application even after grant or ordinary
owner admission expiry or revocation. It is a restrictive consent veto through
the caller's permanent stream; it does not require RevokeGrant. The exact target
and current Snapshot are mandatory. The resulting128 record is permanent.

Registration and withdrawal return:

```
[201,1,Action,DependenciesAndCreatedRecord,CreatedRecordBytes]
```

Every refusal is `[201,1,Action,[]]` with effect zero. A permit has effect one.
There is no Pending result. Limits, invalid authority, stale Snapshot, expiry,
identity conflict and capacity use the finite authority refusal codes. Refusal
cannot commit a partial identity, stream, record or audit entry.

## Retry and historical evidence

The client retains the exact signed request before transmission. A lost reply
resumes that request with a fresh challenge; it never invents a new registration
or resets an application's advanced stream. A retained completed registration
can be disclosed after acceptance expiry without reapplying it. Withdrawal is
not cleared, and the original completion bytes and dependencies remain exact.

The historical confirmation is bounded to65536 bytes:

```
[201,1,"AuthorityApplicationConfirmation",SignedIntent,SignedChallenge,
 OrderedRequest,OperationResult,ExecutedResultCertificate,CommittedNode]
```

The client reserves this output capacity before submission and saves the
confirmation inside its protected completion workflow.

Offline confirmation verifies the exact acceptance, ordered request, result,
quorum certificate and committed node. It reports the certificate's height and
`currentPermission: false`; this may be a later exact-disclosure height. It does
not import a caller's floor or provide a current capability.

Each domain operation still checks the exact grant named by127, no128, current
application validity, grant/tier chain, revocations, owner and ancestor admission,
and all domain object, consent, audience and route requirements. Another grant
to the same application does not expand its accepted authority. Archived proof
or successful lifecycle inspection cannot bypass these checks.
