# Authority operation

Authority state is ordered by four independently appointed Basic HotStuff
replicas. Three matching signatures alone are insufficient: clients validate
canonical statements, ordered ancestry, committed state, current permissions and
the retained epoch and generation floors. Ordinary storage hosts have no vote.
See [AuthorityContract](AuthorityContract.md) for exact voting and result rules.

## Establish independent trust

Prepare a network bootstrap using HyperNetSuite's offline network commands.
Authenticate the complete bootstrap SHA256 through a separate trusted channel.
The bootstrap fixes network/incarnation identity, ordered voter and transport
keys, clock monitor reservations, initial policy and accepted recovery keys.
Recovery acceptance must be complete before a voter can be initialised.

Keep administrator, voter, transport, service, operator, application and recovery
identities separate. Never copy administrator or offline recovery private keys
into an authority or storage container. A capability is explicit authority for
its stated actions and scope; a tier label or broader membership is not a grant.

Configure each voter according to [AuthorityReplica](AuthorityReplica.md).
Install it using [Runtime](Runtime.md), inspect the exact preview, sign local
consent and start its foreground supervisor. Peer addresses and certificate pins
must match the independently accepted bootstrap. Each machine needs a trustworthy
signed clock source. Ordinary wall-clock time is not a substitute for its witness.

Four containers on one host exercise protocol integration but share scheduling,
storage and power failures. Independent operation requires separately protected
replicas and failure domains. Losing the required quorum stops new authority
results; it cannot select a unilateral authority or cached-permission fallback.

## Membership and effects

HyperNetSuite's `authority-inspection` commands prepare invitations, obtain the
member's signed acceptance and submit admission under an explicit current grant.
Delegation can only reduce its parent's authority. Revocation is durable and
cannot be undone by replaying an earlier acceptance or restoring a local cache.
See [PolicyContract](PolicyContract.md) for actions, scope and restrictive state.

Applications require both owner and application consent and an exact admitted
registration. Page review defaults to a manual decision. Automatic review needs
a current policy explicitly permitting that mode. Hosting additionally requires
an exact admitted manifest and local hardware operator consent.

Every mutating requester retains its signed request before transmission. An
interrupted operation resumes those exact bytes and its original operation ID.
A receipt proves a past disposition; it cannot authorise another effect. Clients
retain result floors before exposing success and reconstruct interrupted caches
from the exact authenticated result. Service recipients durably record remote
claims before serving. See [Protocol](Protocol.md) and the domain manuals.

## Persistence and recovery

Use private persistent storage for journals, immutable objects, requester floors,
recipient claims and operator receipts. Keep independently authenticated backups
and external generation floors. A complete disk rollback cannot be detected by
a floor stored only on that same disk. A missing or contradictory journal is a
recovery condition, never permission to generate a fresh journal for the same key.

Healthy committee replacement requires the old terminal certificate and the new
Ready certificate. Readers and service journals explicitly accept the same
successor while retaining verified history. See [AuthorityEpochs](AuthorityEpochs.md).
After total authority loss, [NetworkRecovery](NetworkRecovery.md) establishes a
new identity requiring independent acceptance; it does not silently restore
revoked grants or claim a unique successor from threshold signatures alone.

The local authority control socket is private operator infrastructure. It is not
a public reader endpoint, a confidential-content route or an anonymity guarantee.
