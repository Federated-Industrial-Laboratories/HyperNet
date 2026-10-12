# SSH service protocol

SSH management uses the canonical authority request, challenge, ordered command
and quorum-result envelopes in [WireContract](WireContract.md). It uses the
`AuthorityDomain` action. Network, incarnation, service, session and native-key
identifiers are 32-byte values. Times are Unix milliseconds. A three-of-four executed result
is accepted only through the configured consensus proof and retained history.
An individual authority signature does not authorise a session.

Native OpenSSH carries the selected program's input and output. Pages cannot
launch SSH or construct a remote command. The fixed command belongs to the
locally consented image; its SHA256 is independently pinned by the operator.
Reader connections remain subject to the required relay policy.

## Finite domain state

The authority application's domain state is
`[200,1,"AuthorityDomainState",network,incarnation,records,keyReservations]`.
Records and reservations are sorted and unique. A reservation is
`[class,nativeKey,owner]`: class0 is a native SSH host key owned by its service;
class1 is a native SSH user key owned by its admitted member. Reservations survive
withdrawal, revocation and expiry. They cannot be converted into member,
operator, service, transport, monitor or authority credentials.

Domain records have the common form
`[kind,1,network,incarnation,generation,predecessor,id,payload]`.
The first generation has a null predecessor; each subsequent record names the
exact digest of its predecessor. The implemented SSH kinds are:

| Kind | Identifier | Payload |
| --- | --- | --- |
| 132 | service key | `[operatorProfile,managerKey,managementGrantRef,withdrawn]` |
| 133 | session ID | `[serviceKey,serviceRef,memberKey,nativeUserKey,memberGrantRef,purpose,expiresMs,accepted,revoked,nativeProof,creationIntentDigest]` |

A service starts at generation1 and withdrawal creates generation2. A session
starts at generation1. Acceptance and revocation each advance it once. A revoked
session cannot subsequently be accepted. Only one accepted, unrevoked, unexpired
session can exist per service. A session's service reference is exact; it cannot
silently acquire a different command, host key, endpoint or operator.

The signed profile uses the common canonical Ed25519 envelope. Its payload is:

```text
[200,1,"AuthoritySshProfile",network,incarnation,deployment,
 serviceKey,operatorKey,nativeHostKey,commandSha256,endpointId,
 purpose,maximumSeconds,[notBeforeMs,expiresMs],deploymentProfileRef,consentRef]
```

`deploymentProfileRef` is kind117 and `consentRef` is kind105 for the same
deployment. The profile's service must be the deployment's exact role8 identity.
The endpoint must occur in its signed host consent. The operator signs the
profile. `maximumSeconds` is1..300. The account is the fixed `HyperNetService`;
profiles cannot select another operating-system account.

## Commands and authority

Parameters are
`[200,1,"AuthorityDomain",grantRefOrNull,command,[point,expectedRefs]]`.
The signed intent repeats the exact resource, mutation flag and snapshot floor.
Mutations require the complete current dependency set and exact prior authority
point. Inspection accepts a retained causal point, with no permission rollback.
The operation-specific command arrays are:

| Command | Fields after name | Required authority |
| --- | --- | --- |
| `SshContext` | action, scope kind, resource | Current explicit20 or deployment-scoped26 |
| `SshServiceRegister` | signed profile | Current manager26, admitted registrar13, operator profile and exact host consent |
| `SshServiceWithdraw` | service, expected generation | Its exact operator or service; restrictive, including after expiry |
| `SshServiceGet` | service | Current member20, or intrinsic operator, service or recorded manager inspection |
| `SshServices` | network, after key or null | Current network-scoped20; at most16 records per page |
| `SshGrantCreate` | session, service, native user key, proof, purpose, expiry | Current member20 for the exact service and native-key possession |
| `SshGrantAccept` | session | The exact service or operator; rechecks current member and management authority |
| `SshGrantRevoke` | session | Session member, exact service or operator; restrictive, including after expiry |
| `SshGrantGet` | session | Session member, exact service or operator |
| `SshAuthorise` | service, session | Intrinsic maintenance by that registered role8 service only |

Intrinsic maintenance grants no reader or governance capability to a service or
operator key. `SshAuthorise` requires the accepted current session, member20,
manager26, registrar13, exact registration, host consent and profile. Withdrawal,
revoked capabilities and expired consent refuse the operation.

A permit result is
`[201,1,"AuthorityDomain",versionRefs,[commandName,domainRecords,governanceRecords,nextKeyOrNull]]`.
Every returned reference must match its enclosed canonical record. The consumer
independently evaluates the finite operation and compares the complete result.
A refusal is `[201,1,"AuthorityDomain",[]]`. The recipient identity is the signed
requester for all of these SSH commands; it cannot be redirected to another key.

## Native key possession

`nativeProof` is unpadded base64url containing one detached OpenSSH SSHSIG object,
without textual armour. It requires version1, namespace `HyperNetSshKey1`, an
empty reserved field, SHA512 and an `ssh-ed25519` signature. Its public key must
match the request. Fields are bounded and trailing bytes are refused.

The signed message is ASCII `HyperNet/SshKeyProof/1` followed by a NUL byte,
network bytes, member-key bytes and native-public-key bytes. The normal SSHSIG
structure hashes this message and binds its namespace. The member's canonical
intent also signs the complete request, including its proof. The proof confirms
possession; operator acceptance and current authority remain separate checks.

## Lease consumption

The service signs a fresh recipient challenge for its own immutable request.
Its private requester store durably retains current consensus and generation
floors, stream sequencing and effect claims. Starting or extending the SSH child
uses `perform_once`: an uncertain claimed effect is not silently retried after a
restart. The owner must resolve or explicitly fence that requester generation
before starting new work. Neither ordinary opening nor a network response can
recreate a missing floor.

Each challenge lasts at most five seconds. The service also checks its exact
local profile, native user key, signed clock and live operator withdrawal before
and after the protected effect. A suspend-aware kernel timer invokes a dedicated signal handler that exits every
supervisor thread at the conservative lease deadline, including when the event
loop is blocked. The explicit handler is required because namespace PID1 ignores
default fatal timer signals. PID1 exit makes the kernel kill its descendants.
A renewal must complete within the previous deadline. An old result cannot
extend the timer. Loss of quorum, invalid proof, clock failure or withdrawal
ends the session and all descendants.
