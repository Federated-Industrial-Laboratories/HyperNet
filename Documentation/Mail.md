# Private mail

HyperNet 0.4.0 provides public mailbox discovery and opaque, persistent mail on
explicitly selected hosts. HyperNetSuite is a separate client implementing the
`HyperNetMailMls1` end-to-end encryption profile. The infrastructure does not
parse MLS plaintext or hold mailbox decryption keys. File transfer, SSH and
cross-network mail routing are not part of this profile.

## Identities and authority

An admitted ordinary member registers an owner-signed mailbox manifest. Its
address is derived from the network and a separate Ed25519 owner key. Each
address has distinct child request keys and MLS signature keys; those children
are not network members. The registering member's current admission remains a
prerequisite for every child operation. Device scopes are `Read`, `Send` and
`Delete`; the owner manages the device list, selected stores, retention and
address deletion. An owner may delete letters but cannot read them through the
owner key. Applications receive their own scoped child device, not an owner key.

A manifest update compares the current generation and previous signed-manifest
digest. Removed child keys cannot be enrolled again, even with another device
name. Renewal is an explicit owner update; device expiry must also be renewed
when needed. An admitted owner may retrieve its own expired or deleted manifest
to resolve an uncertain update or deletion result. Revoking the registering
member disables all its mailboxes. Administrators cannot expand owner-selected
placement through a network default.

The authority requires a separate `mailSigningKey`. It must differ from its
federation signer and all member, host, owner and child keys. A store verifies
fresh authority permissions under the exact signer pinned in its consent.
Historical delivery admission is retained with the ciphertext so a recipient
can verify an original accepted letter after subsequent manifest changes.

Public authority state contains signed manifests, selected-host descriptors,
public one-use key packages and their claims, plus the private association to the
registering member. It contains no ciphertext, subject, body, inbox index or
store receipt. `MailAuthorise` and `MailPolicySync` perform linearizable reads
without creating authority request receipts or transactions. Their signed
permissions expire within five seconds. Authority loss denies new operations.

## Delivery and storage

Before encryption, a sender claims one unexpired public key package for every
current receiving device in the recipient manifest. The complete set is removed
atomically; a missing device prevents the whole claim. The client verifies the
actual MLS package, lifetime, reference, signature key and mailbox binding.
Each letter uses a fresh MLS group; this is not a continuously joined group
conversation. Public claims do not prove delivery or reveal a store inbox.

A sender selects only stores in the recipient's signed manifest, verifies their
consented certificate/root and obtains a durable signed receipt from each
required copy. A store requires a fresh authority permission for each exact
operation and ciphertext digest. An acknowledgement records receipt by a
reading device; deletion clears the local payload and retains a bounded signed
tombstone until the route expires. Repeating the same message ID, route and
ciphertext is idempotent. A different ciphertext for an accepted ID is rejected,
even when its replacement counter increases. Uncertain multi-store delivery
must be resolved through receipts before the client constructs any replacement.
There is no atomic commit across several selected hosts.

Each store runs with one preallocated 8--64 MiB state file. Two banks hold
checksummed generations; the usable serialized state is less than half of the
file size. A commit fsyncs the new bank before returning a receipt, then clears
the old bank. Restart selects the newest valid committed bank and clears an
incomplete alternate bank. A damaged file with no recoverable bank fails closed;
it never silently becomes an empty mailbox. A failed write requires process
restart and recovery before another commit. Capacity also has explicit per-store
and per-address limits, so delivery can fail before the byte bound is reached.

Current signed policy removes expired mail and removes copies from a store no
longer selected by the recipient. Narrowed retention applies from the original
local acceptance time, including retained deletion metadata. Fresh policy is
checked at startup and normally every two seconds while the service runs.
An authority outage denies fresh operations. An already running worker and relay
continue running, retain encrypted state and retry policy synchronisation; they
do not terminate merely because quorum is unavailable. Startup still requires a
fresh policy. Host consent expiry terminates both processes, including suspended
processes, and retains their encrypted state. Neither condition destroys valid
retained mail merely because a network is down. Cleanup resumes once a valid
fresh policy is available. An offline or malicious
former store cannot be forced to erase a copy, and filesystem deletion cannot
prove erasure from snapshots, flash media or backups. End-to-end encryption
limits the content exposed by such copies.

## Privacy and recovery limits

TLS protects transport. Selected stores and the authority can observe routing,
public mailbox identities, device relationships, size and timing. A selected
store sees encrypted letters and local receipts. This profile does not provide
traffic-analysis resistance or hide public directory data from admitted clients.
Mail attachment execution and terminal escape interpretation are not supported.

Keep identity and private client-vault backups under the owner's control.
Removing a device blocks new permission but cannot revoke keys or plaintext it
already obtained. Lost consumed private MLS key packages cannot be recreated by
republishing their public package. The client must retain private packages until
all admitted letters using them have been processed or deliberately abandoned.

Store revision, epoch, host generation and time floors are durable in the state
file. Restoring an old copy of the entire file also restores those local floors;
this is not an external anti-rollback witness. Do not resume an uncertain backup
under the old live service identity. Register a fresh dedicated host identity,
obtain new host consent and explicit mailbox placement, and treat old ciphertext
as an offline recovery archive. This avoids claiming that an old deletion or
receipt history remains current. Recovery archives are not automatically copied
into a live store. The network itself retains the authority disaster-recovery
rules described in [Authority operation](Authority.md).

See [Mail store operation](MailStore.md) for deployment and
[Mail protocol](MailProtocol.md) for independent client integration.
