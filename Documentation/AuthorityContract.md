# HyperNet 0.8.0 authority contract

This specifies the fixed-committee HyperNet 0.8.0 authority contract. The 0.7.5
executables do not implement it. It supplies no installed Byzantine qualification
or live reconfiguration proof. User signatures, local consent and client privacy
remain mandatory. The wire representation is defined in WireContract.md.

## Fixed-committee decision

Specify Basic HotStuff, without chaining or pipelining, for the first authority
integration. Exactly four equal-weight, independently enrolled voting keys form
one configuration; three distinct valid signatures form a quorum. The exact
initial tier/grant state is pinned through GenesisGovernance in WireContract.md;
voters do not create or inherit administrative grants. At most one
replica may behave arbitrarily. Crashes, compromised signers and lost signing
state consume the fault budget; four processes do not prove four independent
failure domains. A 2/2 partition cannot issue new authority. A Byzantine replica
withholding while another replica is unavailable can stop progress. No setting
reduces the quorum or installs a single-server fallback.

The ordered log contains bounded canonical commands and immutable object
references, not page/media/mail bodies. Every replica independently validates
client intent and deterministically executes commands. A broker cannot supply an
already-authorised opaque result for the quorum merely to endorse. Client and
recovery signing keys remain distinct from replica keys.

The specification follows the published Basic HotStuff phases and safety rule.
Its implementation still needs a fully specified pacemaker, persistence,
state transfer and integration. Explicit Ed25519 signer sets replace threshold
signature aggregation; this does not inherit the paper's constant-size
certificate or linear authenticator cost. The protocol source is
[HotStuff, algorithms 1-2 and section 4](https://arxiv.org/pdf/1803.05069).

## Replica state and messages

All integers are bounded unsigned values. Overflow refuses the operation. Wire
records use the common canonical encoding and signature domains in
[WireContract.md](WireContract.md); a parser never silently normalises an alternative encoding.

A configuration descriptor fixes the network identity, incarnation, protocol,
epoch, ordered four-member key set, key-to-replica mapping, quorum three, derived genesis
checkpoint and recovery policy digest. The sorted key itself identifies its
logical replica; there is no independently mutable key-to-replica table. Duplicate keys or identities are invalid.
Transport identity is bound to the enrolled replica identity but does not replace
message signatures. The initial configuration is fixed for this protocol model.

A node binds configuration, epoch, proposing view, height, parent digest,
canonical command digest, explicit evaluation time and justification digest.
The complete canonical kind-14 Node determines its digest. Verify the whole ancestry to
a trusted checkpoint before processing it. Height equals parent height plus one;
view strictly increases along a proposal edge. The justification is a verified
Prepare QC from an earlier view. Honest leaders propose a direct child of that
QC's node. A receiver checks ancestry, not an untrusted boolean extension claim.

Wire kind 11 Vote binds the signature domain, Scope, view,
phase and exact node digest. Its signature wrapper identifies the replica key.
Wire kind 12 QC embeds that exact Vote payload and three or four strictly ordered distinct
eligible signer/signature pairs. Its duplicate Scope must match the Vote Scope.
Each signature uses the common preimage binding the payload and its signer key. Prepare,
PreCommit and Commit domains/phases are distinct. Duplicate signers, unknown
members, mixed nodes/phases/views, wrong network/epoch and malformed signatures
are invalid. Genesis is deterministically derived from the pinned descriptor: Node view and
height zero, null parent/command/justification, and descriptor bootstrap time.
Only that pinned genesis has a null-vote, empty-signature QC; it never authorises
a non-genesis decision or result.

Durable state contains at least:

- Highest entered view, one signed vote record per phase/view still needed for
  recovery, highest learned Prepare QC and highest locked PreCommit QC.
- Verified node ancestry and certificates needed to justify those records.
- Highest committed node, applied position, canonical policy state and digest,
  deterministic request receipts and tombstones, and the checkpoint floor.
- Configuration and network identity, integrity/version metadata, and any
  terminal configuration boundary once a qualified transition exists.

A durable vote record retains the complete signed statement, so exact retries
return the same vote. Signing a different statement in the same phase/view is
refused. A single exclusive signer owns the key and durable history. Cloning a
key plus an old database into two concurrently running replicas is not recovery.

## One view, precisely

Let `v` be the current view, `p` a proposal, `j` its preceding Prepare QC and `L`
the replica's locked PreCommit QC. Genesis behaves as a zero-view ancestor.
The safety predicate is:

```text
safe(p, j, L) = extends(p, L.node) OR (j.view > L.view)
```

Before any signature, verify its message, configuration, phase, ancestry and
bounded input. Time admission and deterministic command validation are additional
application checks; they never weaken the safety predicate.

| Step | Required evidence and transition | Durable-before-send requirement |
| --- | --- | --- |
| New view | Send the highest persisted Prepare QC to the designated next leader. An honest leader obtains three distinct current NewView reports and chooses the highest valid Prepare QC. | Persist entry into the target view; preserve previous locks/votes. |
| Prepare | Receive this view's designated leader proposal; verify its ancestry extends `j.node`, `j.view < v`, and `safe(p,j,L)`. Vote Prepare at most once. | Atomically retain proposal ancestry, view floor and exact Prepare vote before releasing the signature. |
| PreCommit | Verify a Prepare QC for this view/node. Retain the highest Prepare QC and vote PreCommit once. | Persist Prepare QC and exact PreCommit vote before releasing the signature. |
| Commit | Verify a PreCommit QC for this view/node. Lock that QC and vote Commit once. | Persist the lock and exact Commit vote atomically before releasing the signature. |
| Decide | Verify a Commit QC. Its branch is decided; retain missing ancestry and apply committed commands in order. | Persist commit evidence, then atomically apply state/receipts/results before signing an executed result. |

The leader forms each successive QC only from the preceding phase's valid
matching votes. Three Prepare votes do not commit; three PreCommit votes do not
commit; a Commit QC does not prove a supplied application response. Phase
messages received early wait in bounded storage until their prerequisites are
verified. Identical duplicates are idempotent; conflicting duplicates are
rejected and retained as bounded public incident evidence. A stale-view message
cannot generate a new stale-view vote. A verified older Commit QC can still
repair missing committed state if it extends the accepted committed prefix.

Ordinary phase reception follows the view's ordered state machine. No later
phase message can create a Prepare vote without its safety/ancestry check.
A valid current Prepare QC justifies PreCommit; its recipient does not require
its own Prepare vote to occur in that certificate or repeat safeNode as an
extra PreCommit rule. Certificate repair is distinct: it can learn a decision and ancestry
without issuing a new vote. A replica learns a stronger QC without lowering any
lock, view, applied position or trust floor. An unexpected conflicting valid
Commit QC stops serving and records the evidence; it is never resolved by a
hash, timestamp, arrival order or local preference.

## View change, progress and withheld decisions

Views increase monotonically; the leader is the deterministic round-robin member
for that view. A timeout advances the local view and produces a signed NewView
report. An honest next leader chooses the highest verified Prepare QC from its
three distinct reports and extends it. It does not select whichever application
command is most popular. Timeouts never clear a lock or authorise a lower quorum.

Basic HotStuff abstracts the synchroniser as `nextView`. This contract fixes its
required interface, not a new supposedly proved synchronisation algorithm:
monotone durable view entry, authenticated bounded reports, no single-peer
forced jump, eventual overlapping correct views with a correct leader after
synchrony, and no change to the voting safety rule. Timeout retransmission,
catch-up, backoff and the exact evidence required for a view jump belong to the
implementation-selection gate. A bound on timeout duration is not a liveness
proof. The implementation must select and test a complete synchroniser; it cannot claim progress
from the local timer alone.

Correct replicas retain and exchange votes and certificates through bounded
repair requests independently of a leader or edge broker. A collector withholding
Decide cannot erase a Commit QC or make a committed request run twice. A client
retries the same signed operation through another authorised ingress; result
collection does not depend on one original leader. Repair verifies individual
signatures and ancestry before persisting data. Unbounded history requests,
unknown configurations and unverifiable suffixes are refused or rate limited.

## Restart, checkpoints and executed results

Write and synchronise persistent security state before exposing its signature.
The atomic persistence boundary must cover a lock together with its Commit vote.
The storage implementation must specify torn-write handling, file/directory sync,
transaction recovery and error propagation. Failed sync means no signature.

Restart loads and verifies the last complete durable state. It does not infer
that a vote was absent because a reply was lost. A replica with intact exclusive
state may retransmit an identical stored vote, repair certified ancestry and
resume. Uncertain, corrupted, missing or rolled-back signing state quarantines
the signer. A checksum detects corruption; it does not detect an adversary
restoring an internally consistent older snapshot. Do not represent ordinary
backup restoration as rollback-proof storage.

A checkpoint binds its configuration, committed position/node, complete state
digest, deterministic receipts, revoked generations, consumed invitations and
required ancestry boundary. Keep enough evidence to preserve outstanding locks,
anti-replay state and descendant validation. State transfer verifies the certified
checkpoint and every required suffix; catching-up replicas cannot serve permits
or vote from an incomplete state. Exact checkpoint retention/compaction and
physical crash behaviour remain implementation qualification work.

Wire kind 23 ExecutedResult binds the exact canonical result, OrderedRequest digest, signed intent and
identity, requester, recipient, operation/resource/version, policy digest and
causal floor, committed position/node, evaluation time, expiry, recipient
challenge/session, and relevant consent/placement/route digests. Every result
signer first verifies commitment and durably applies the deterministic transition.
The state update and request receipt are one transaction. A duplicate request
returns its original logical result; it does not repeat an effect or extend a
permit's challenge deadline. A new challenge is a new ordered authorisation,
not a changed encoding of an old result.

The broker gathers three matching executed-result signatures. Each consumer
checks this certificate independently before using the exact typed response.
A merely authenticated connection, one replica's assertion or a valid Commit QC
without execution evidence is insufficient. All page, media, mail, transfer,
SSH, federation, route and search consumers use this rule. No obsolete signer
path remains alongside it.

## Time and freshness profile

The following are explicit proposed constants for implementation qualification, not measured
WAN performance or evidence that the operating system has a trustworthy clock:

| Parameter | Initial bound |
| --- | --- |
| Honest wall-clock absolute error `Delta` | At most 250 ms against the common time scale |
| Voter proposal time admission `A` | `abs(evaluatedAt - localWallNow) <= 1000 ms` |
| Conservative evaluation uncertainty `U` | `Delta + A = 1250 ms` |
| Recipient challenge lifetime | At most 5000 ms, end to end, strict expiry |
| Clock health | Required at proposal admission and every sensitive recipient use |

Time is integer Unix milliseconds; use checked arithmetic. The time service and
leap/smear convention must be consistent across the deployment. A signed leader
timestamp is not independent evidence of clock correctness. Clock synchronisation
status alone is not proof of the stated error bound. Deployment diagnostics must
state how the bound is established; absent that evidence, clock health is unknown
and sensitive authorisation stops. This is a specific integration gate.

Proposals carry an explicit evaluation time `t`, no earlier than the verified
parent evaluation time or the previous committed evaluation time. Every honest Prepare voter requires its health bound
and `abs(t - localWallNow) <= A`. Given that voter's error bound, actual time at
that admission lies in `[t-U,t+U]`. Deterministic grant evaluation therefore
requires `notBefore <= t-U` and `t+U < notAfter` for all relevant credentials and
consents. Known generations and revocations are evaluated in the same committed
state. Clock reads never occur inside deterministic execution.

The admission allowance is deliberately greater than pairwise skew. An honest
leader proposing its local time and delivering within 500 ms fits the 1000 ms
allowance even with 500 ms pairwise error. This is arithmetic, not a guarantee
of Internet delivery, fsync latency, total decision time or synchroniser progress.
A slower request times out and obtains a fresh authorisation; it cannot widen
the bound automatically. Delayed commitment is harmless to time enforcement only
because recipients check their own current time and original challenge deadline.

The recipient that releases bytes or exercises a permission creates an
unpredictable 32-byte challenge and records `(boot/session identity, nonce,
request digest, issueBootTime, deadlineBootTime)`. A client cannot assert when a
service-owned challenge was issued. Where both parties need independent
freshness, bind both challenges and obey the earlier effective deadline.

Use Linux `CLOCK_BOOTTIME` for local elapsed deadlines. It includes suspension;
`CLOCK_MONOTONIC` does not. No external party supplies a trusted local clock value.
The clock API distinction is documented by the
[Linux clock_gettime manual](https://man7.org/linux/man-pages/man2/clock_gettime.2.html).

Acceptance requires all of the following, immediately before the protected effect:

1. The exact challenge belongs to the current local boot/session and original
   signed request, has not been consumed where one-use is required, and
   `nowBootTime < deadlineBootTime <= issueBootTime + 5000 ms`.
2. A valid executed-result certificate matches all identities, route, operation,
   exact resource/version and local consent. Signature work, fetching, queuing,
   rendering and redirects do not create additional five-second windows.
3. The local clock remains healthy, `localWallNow - Delta >= notBefore`, and
   `localWallNow + Delta < absoluteExpiry`. At a boundary equality is expired.
4. The certificate satisfies the caller's signed causal policy floor and the
   recipient's durable trust/policy floors, including relevant resource and
   membership generations. Known revocation defeats an otherwise unexpired
   result immediately.
5. Any newer accepted floor is durably recorded before the effect. Restart
   invalidates all live challenges; wall-clock rollback, unsupported clock APIs,
   boot mismatch or uncertain persistent floors cause refusal.

A floor is not just the largest integer observed from a server. Persist the
network/configuration anchor and certified committed prefix. A causal policy
floor additionally names relevant namespace/recipient/placement generations.
A new request includes the maximum floor already known by its caller. Replicas
must execute at or beyond that prefix and against the requested generations;
consumers refuse stale results rather than letting an old but correctly signed
permit override a later removal. A restored client with lost floors must repeat
independently authenticated bootstrap, not trust its old backup as current.

Long streams revalidate before another protected chunk is released and close or
pause at the earlier deadline. Bytes already released cannot be recalled.
Committed revocation stops new permits; a permit already issued before an
unknown revocation can survive only its original remaining bound. Local host
withdrawal stops immediately without waiting for consensus. No global
instantaneous revocation or erasure of retained plaintext is promised.

## Replacement and recovery boundary

This fixed-committee specification cannot justify hot key rotation or membership
change by three signatures alone. The Basic HotStuff source assumes a fixed
replica set. The proposal's terminal old-epoch checkpoint followed by a new-epoch
activation is a requirement to prove and implement, not an established protocol
obtained by combining two certificates.

For an ordinary lost process whose complete current durable state and key remain
intact, the safe initial path is to restore that one exclusive logical replica
on replacement hardware, verify that no old signer can run, retain its vote/lock
history, synchronise certified state, then resume. If the old machine may be
compromised, fencing is uncertain, the key is lost, or the durable record is
missing, this path is prohibited. Three healthy remaining replicas can continue
at degraded availability but cannot appoint a new fourth key under this model.

The implementation must deliver and qualify a complete established epoch-transition mechanism
for a genuinely lost member, including old/new failure assumptions, key history,
terminal-boundary crashes, checkpoint uniqueness and consumer activation. Until
then normal key replacement returns an explicit unsupported/unavailable result.
This refusal defines a security boundary; it does not complete the 0.8.0
replacement workflow.

When healthy replacement cannot be established, the already selected exceptional
recovery procedure creates a new network identity. Independently authenticated
client acceptance is mandatory. Recovery signatures authorise a proposal, not
unique global succession. Conflicting declarations stop automatic recovery.
Historical snapshots are reviewed imports; they cannot revive old grants,
mailbox membership, placement consent or reader keys. The detailed owner/shared
custody rules remain in [PolicyContract.md](PolicyContract.md).

