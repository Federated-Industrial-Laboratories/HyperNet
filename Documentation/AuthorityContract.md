# HyperNet 0.8.0 authority contract

This specifies the HyperNet 0.8.0 authority contract for replicas, independently
verifying clients and domain services. Certified checkpoint compaction and
existing-signer catch-up use the bounded WireContract profile. Certified committee
replacement is described in [AuthorityEpochs.md](AuthorityEpochs.md). This contract
does not establish independent physical failure domains or production Byzantine
qualification. User signatures, local consent and client privacy remain mandatory.
The wire representation is defined in WireContract.md.

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
Its runtime uses the published SMR synchroniser in Figure 3 of Bravo, Chockler
and Gotsman (DISC 2022), durable signer state and bounded dependency repair.
Certified checkpoints bound retained history and authenticate state transfer.
Explicit Ed25519 signer sets replace threshold
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
for that view. A timeout asks the SMR synchroniser to advance; authenticated
quorum entry durably records the new view before emitting its signed NewView
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

Each entered view v arms one timer: F(0)=0 and, for v>0,
F(v)=1000ms+250ms*floor(log2(v)). Expiry consumes that timer; periodic WISH
retransmission continues until another view is entered. A restart derives the
duration from the durable entered view, without a private failure counter or a
success-based duration reset. Committed progress may request the next view early.
The mathematical function is unbounded on natural view numbers; this finite-u64
profile has a maximum duration of16750ms and refuses counter overflow. It does
not guarantee progress for arbitrary unknown network/processing delays or
completion within the separate operation-specific recipient challenge.

View entry also atomically retires signatures through max(previousFloor,v-2)
before allocating the new report. Reclamation works from genesis before the
first checkpoint and preserves the complete highest Prepare/lock, current and
previous-view certificate, committed/applied and outstanding execution closures.
The signature floor does not prohibit verified late QCs or Decide. Collected
Prepare QCs raise the durable Prepare floor before deferred local delivery.
When a newly collected or received QC has complete local dependencies, its
publication also retains the eligible next phase vote and lock, or committed
position, in the same atomic journal transaction. No certificate or vote is
released before that transaction succeeds. Missing inputs or phase prerequisites
defer voting while the learned QC and its stronger Prepare floor remain durable.
Application discovery and executed-result publication retain their separate
bounded durable transitions.
Advance publishes its own signed WISH and synchroniser transition together;
loopback delivery cannot require a second publication of that evidence.
Already queued authenticated votes for one exact view, phase and node may share
a publication. The same applies to WISH evidence for one target or NewView reports
for the current entered view with already durable Prepare dependencies and
available immutable inputs. Collection never waits for another message and stops
at the first unrelated, invalid, conflicting or dependency-missing event within
the existing ingress bound. Every distinct signer's evidence is retained,
including a fourth signer. Successful transport acknowledgements and broadcasts
follow durable publication; a rejected
later event does not discard the accepted prefix. Uncertain publication stops the
signer without acknowledgements, broadcasts or an in-process persistence retry.

Correct replicas retain and exchange votes and certificates through bounded
repair requests independently of a leader or edge broker. A collector withholding
Decide cannot erase a Commit QC or make a committed request run twice. A client
retries the same signed operation through another authorised ingress; result
collection does not depend on one original leader. Repair persists only complete
dependency closures rooted in verified quorum certificates. Raw votes and executed
shares cannot authorise persistent dependencies. A proposal retains its own node
and command only when the ordinary Prepare checks permit a durable vote.
Unbounded history requests, unknown configurations, unrelated records and
unverifiable suffixes are refused. Equivalent proofs of one quorum statement use
one certificate identity and retain the first verified proof.

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

Application, certified-checkpoint and candidate state bodies are immutable
objects referenced by their exact existing state digests. Shared roots retain
one body and allocation charge. New objects reach durable storage before archive
visibility and the atomic journal reference; collection follows that journal
publication. Reopen resolves and verifies every state root before collection,
including checkpoint, applied-result and execution-cursor bindings. Missing,
altered or incompatible state objects refuse restart. Internal signer format3
requires this representation and does not accept earlier inline-state layouts.
Consensus records, state digests and checkpoint transfer formats are unchanged.

A checkpoint binds its configuration, committed position/node, complete state
digest, deterministic receipts, revoked generations, consumed invitations and
required ancestry boundary. Three distinct eligible signers certify the exact
applied state. Each signer verifies actual commitment and complete ancestry,
then durably records that state, archive commitment and checkpoint statement
before releasing its share. The public proof contains the quorum statement and
its exact applied anchor; it is not a phase QC and carries no deciding attachment.
Keep enough evidence to preserve outstanding locks,
anti-replay state and descendant validation. State transfer verifies the certified
checkpoint and every required suffix; catching-up replicas cannot serve permits
or vote from an incomplete state. The bounded profile retains an append-only
archive, local safety obligations and a durable retired-view floor. Imported
state cannot initialise a missing signer journal. A divergent local lock may
remain alongside the certified committed prefix only with its complete bounded
verified ancestry to an authenticated common prefix. Installation preserves the
exact lock, highest Prepare QC, own votes and retired-view floor. A checkpoint
never unlocks or produces a phase vote; ordinary current-view PreCommit
processing remains the lock transition. Physical storage-failure behaviour and
independent failure domains require deployment qualification.

Wire kind 23 ExecutedResult binds the exact canonical result, OrderedRequest digest, signed intent and
identity, requester, recipient, operation/resource/version, policy digest and
causal floor, committed position/node, evaluation time, expiry, recipient
challenge/session, and relevant consent/placement/route digests. Every result
signer first verifies commitment and durably applies the deterministic transition.
The state update, sequence retirement and original request receipt are one
transaction. An exact duplicate never repeats the mutation. Returning its
protected body requires fresh current disclosure authority. A refusal to
disclose does not change the retained original completion. A new challenge is a
new ordered authorisation; it preserves the immutable request and fence identity.
Own-stream metadata and explicit generation fencing follow WireContract.md.

The broker gathers three matching executed-result signatures for one exact
committed node. Repeated ordering of identical request bytes can create distinct
execution attestations; their signatures remain in separate bounded sets. For
one request, the broker returns the highest committed position with a complete
matching set. Each consumer checks that certificate independently, including its
retained floor and freshness bounds, before using the exact typed response.
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
| Ordinary recipient challenge lifetime | At most 5000 ms, end to end, strict expiry |
| Federation maintenance challenge lifetime | At most 15000 ms, with inherited end-to-end expiry |
| Clock health | Required at proposal admission and every sensitive recipient use |

Ordinary recipient challenges have a hard 5000-ms maximum. The finite
federation maintenance chain has a separate hard 15000-ms maximum: Admission,
Export, Import, grant-free MediaAuthorise and MediaReceipt. The allowance is
derived from the fully parsed signed operation, never from a caller-selected
profile or action-name prefix. MediaAuthorise still requires the exact admitted
Bridge and treaty; MediaReceipt also permits its exact storage host. Reader,
reviewer, administrative, stream-control and other operations retain 5000 ms.

The maintenance budget accommodates three serial authority decisions; it is not
a completion guarantee. It increases the maximum exposure to an unknown foreign
revocation to 15000 ms for those permissions. Known restrictive floors and local
withdrawal still take effect immediately. Each result inherits the earliest
applicable foreign expiry and credential deadline. A later step cannot restart
an earlier permission's lifetime. Existing signed 5000-ms challenges remain
bounded to their original interval. No retry or configuration widens a challenge.

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

Challenge creation is not a credential `notBefore`. For challenge duration `D`,
evaluation requires `createdAt <= t+U` and `t+U < requestedExpiry <= challengeExpiry`.
The executed permission expires no later than `min(requestedExpiry, t-U+D)`;
`t+U` must also be strictly below that effective expiry. All arithmetic is checked.
The signed request and challenge remain unchanged. Every Permit verifier checks
this cap, including stream controls; expired Refuse/Pending evidence cannot grant
an effect and remains observable.

For an honest Prepare voter at actual time `tau`, `tau >= t-U`. Thus the cap is
no later than `tau+D`, even if a malicious recipient future-dates its challenge.
An honest recipient additionally enforces its original local session deadline.
Credential activation dates, foreign expiry inheritance and known revocations
retain their conservative checks. No waiting period is added merely to age a
fresh unpredictable challenge. Recipient-side lower bounds come from independent
credentials; the original live BOOTTIME record establishes challenge issuance.
A historical completion signed by that same recipient must not precede its
recorded challenge creation. Its completion time plus `Delta` must remain strictly
below the certified expiry. Such a receipt never establishes fresh permission.

Use Linux `CLOCK_BOOTTIME` for local elapsed deadlines. It includes suspension;
`CLOCK_MONOTONIC` does not. No external party supplies a trusted local clock value.
The clock API distinction is documented by the
[Linux clock_gettime manual](https://man7.org/linux/man-pages/man2/clock_gettime.2.html).

Acceptance requires all of the following, immediately before the protected effect:

1. The exact challenge belongs to the current local boot/session and original
   signed request, has not been consumed where one-use is required, and
   `nowBootTime < deadlineBootTime <= issueBootTime + signedDuration`, with
   the signed duration within the exact operation's hard maximum.
2. A valid executed-result certificate matches all identities, route, operation,
   exact resource/version and local consent. Signature work, fetching, queuing,
   rendering and redirects do not create additional permission windows.
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

A fully verified newer Refuse or Pending result is still a learned committed
prefix. Persist that restrictive prefix before reporting its outcome, including
when its effect deadline has expired. This observation cannot produce a permit
or release a protected payload. An older pending permit must then fail its
prefix check. Generation floors advance only from exact versions established by
the typed certified result. Signed request expectations alone are not certified
current state, especially when the request was refused for stale expectations.

The private floor binds one requester key and keeps its exact signed ordinary
request before transmission. At most one ordinary workflow and one explicit
fence can be outstanding. A fresh response cannot substitute a different
request. Own-stream status retains original completion metadata separately from
later disclosure decisions. An unknown outcome, missing body or claimed local
effect prevents automatic acknowledgement and sequence reuse.

Floor, witness and request tracker use one private write-ahead transaction.
Recovery verifies its exact identity, consecutive local transaction witnesses,
canonical next floor and typed forward transition. Certified prefix changes
also require ancestry or checkpoint inclusion and consistency. Recovery only
completes the same forward update; inconsistent or missing files refuse.
A complete internally consistent local rollback still requires an independent
current anchor to detect. The journal does not provide that external anchor.

A live ordinary permit saves the exact original result body privately before
releasing its effect. Freshness and restrictions are checked again after disk
writes. The body cache cannot grant current permission. An irreversible handler
first records its durable claim; interruption thereafter remains MayHaveApplied.
Retrying that handler automatically is prohibited. Explicit generation fencing
can close prior requests while preserving bounded unresolved summaries. Neither
fencing nor a refusal proves that an earlier external effect did not happen.

Long streams revalidate before another protected chunk is released and close or
pause at the earlier deadline. Bytes already released cannot be recalled.
Private routes establish authenticated transport and current endpoint readiness
before an application challenge is issued. Submission, polling and history share
that finite channel. Transit and endpoint permission are revalidated with their
own fresh challenges; they do not replace or extend application freshness.
A renewal cannot restore an expired proof, a closed connection or spent budget.
Committed revocation stops new permits; a permit already issued before an
unknown revocation can survive only its original remaining bound. Local host
withdrawal stops immediately without waiting for consensus. No global
instantaneous revocation or erasure of retained plaintext is promised.

## Replacement and recovery boundary

Each epoch runs Basic HotStuff with a fixed committee. Healthy replacement uses
an authorised terminal declaration, durable old halt, exact state derivation and
durable new installation before its two quorum boundaries. Three signatures
alone do not authorise a configuration change or repair lost signing history.
The supported installed transition nominates four fresh identities with four
exact admitted deployments. It refuses overlap, retired keys and implicit
changes to117profiles or129registrations. See [Authority committee replacement](AuthorityEpochs.md).

For a lost process whose complete current durable state and key remain intact,
restore that one exclusive logical replica on replacement hardware, verify that
no old signer can run, retain its vote/lock history, synchronise certified state,
then resume. If the old machine may be compromised, fencing is uncertain, the
key is lost, or the durable record is missing, this path is prohibited. Three
healthy remaining replicas can authorise the fresh four-member replacement;
fewer than three cannot complete its old handoff. Missing new readiness keeps
the old committee halted rather than selecting a different successor.

Correct replicas sign only the unique successor of their durably terminal state.
The new committee cannot vote before the matching ready quorum is durable.
Consumers verify inclusion and consistency from their actual retained floors,
and preserve restrictive versions, pending requests and uncertain effects when
activating. Retired keys must remain protected or be destroyed under the accepted
operating model: an offline client cannot distinguish counterfeit old handoffs
if a historical quorum's private keys is later compromised.

When healthy replacement cannot be established, the already selected exceptional
recovery procedure creates a new network identity. Independently authenticated
client acceptance is mandatory. Recovery signatures authorise a proposal, not
unique global succession. Conflicting declarations stop automatic recovery.
Historical snapshots are reviewed imports; they cannot revive old grants,
mailbox membership, placement consent or reader keys. The detailed owner/shared
custody rules remain in [PolicyContract.md](PolicyContract.md).

## Bounded governance discovery

`AuthorityContext` uses the parameters
`[200,1,"AuthorityContext",grant,MinimumPoint,cursor]`, with an empty signed
expected-reference set. `MinimumPoint` is `[epoch,height,stateDigest]`.
The first cursor is null; a continuation is `[recordsRoot,totalCount,nextIndex]`.
Every request requires a current network-scoped InspectAudit grant.

A permitted value is `[201,1,"AuthorityContext",pageRefs,page]`, where
`page = [recordsRoot,totalCount,startIndex,nextIndexOrNull,recordByteStrings]`.
Records and references have matching, strictly increasing `(kind,id)` order.
A page contains at most 64 whole records, and its complete encoded kind-24
result is at most 32768 bytes. The authority selects the largest whole-record
prefix within both bounds. A record that cannot fit causes a capacity refusal.
The root is RecordDigest of canonical CBOR
`[200,1,"AuthorityRecordsView",[network,incarnation,epoch],allSortedVersionRefs]`.
Record digests bind their exact canonical bytes.

Each continuation recomputes the current root/count, checks the minimum point,
and rechecks current permission before disclosure. A changed root/count refuses
with code 12. It does not expose an old snapshot under revoked permission.
The root excludes receipt state, which advances when pages are requested.
The client requires contiguous indices, the same root/count on all pages, and
null only at the exact total. It validates the completed root and all retained
version minima before publishing a complete context. The latest independently
verified certified point supplies a subsequent mutation's Snapshot. Delegation,
member admission, application/deployment registration and withdrawal, and grant
revocation use that point as a same-epoch causal floor. They require the complete
exact relevant dependency set and current authority at execution; an equal-height
point must still match the state digest. Creation results retain their original
certified creation height on exact replay. Reconfiguration retains its own
explicitly defined snapshot requirements.

The client retains bounded private pages and resumes immutable requests after
interruption. An explicit discovery restart cannot clear an unresolved request,
version floor or accepted authority. Partial pages are never an authorisation
context. Scoped application delegation discovery remains a separate contract.
