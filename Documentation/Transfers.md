# Encrypted file transfers

A transfer is an immutable, expiring offer between two admitted client identities.
The recipient explicitly accepts its ciphertext digest, size, encryption key and
selected storage host before upload. The destination is an opaque local label;
remote participants cannot choose a recipient filesystem path. The store never
executes or extracts files. This initial profile operates inside one network.
It does not inherit Federation membership or route through another network.

An independently implemented client can use the [transfer protocol](TransferProtocol.md).
HyperNetSuite supplies file encryption, offer acceptance, resumable upload and
verified local delivery. It encrypts the file and private metadata to an explicit
native age X25519 recipient. The authority stores public routing, consent and
size metadata; neither the authority nor storage host receives plaintext file
bytes or a clear-content digest. Static recipient encryption keys do not provide
forward secrecy: protect and rotate them according to recipient policy.

An offer binds its sender, recipient, encryption recipient, encrypted size and
SHA-256, clear size, opaque label and expiry. The signed recipient acceptance
binds the exact offer digest, selected host and local destination label. The
host reserves the whole encrypted size atomically at acceptance. No default host
or fallback can override that choice. Host resources and retained reservations
must permit the offer. The encrypted payload is limited to 8 MiB. Each request
carries at most 64 KiB. Total accepted reservations are at most one quarter of
the host's signed state size, leaving space for two durable journal banks and
encoding overhead. Capacity is bounded to 16 hosts, 32 unexpired offers per sender and 256 unexpired
offers per network. Cancelled records remain until their original signed expiry.
Expired records are removed only at guarded monotonic authority time; their old
signed offers and acceptances cannot become valid again. Use new random IDs for
new transfers. Permanent service identity histories remain reserved.

Upload is contiguous. An interrupted sender queries the signed durable offset
and resumes the same encrypted bytes. Repeating an already stored chunk succeeds
only if those bytes match; changed bytes or skipped offsets fail. Completion
requires the entire encrypted size and SHA-256 to match. Recipients can fetch
only completed objects, verify the encrypted digest, decrypt and check private
file metadata before publishing a local file. Local clients must reject symlinks,
device files, traversal and replacement of existing outputs. A cryptographically
valid file remains untrusted content; opening it is a separate recipient action.

Every store operation needs a fresh quorum-backed permission, bound to the exact
signed operation and current host generation. Permissions last at most five
seconds. Member revocation, cancellation, expiry, placement or host withdrawal
therefore deny new work. Cancellation is terminal for an offer. Authority host
withdrawal also cancels its accepted offers; renewed host consent does not revive
those offers. Local emergency withdrawal stops the service immediately without
waiting for authority access. Unavailable quorum denies work but does not erase
ciphertext. Only a fresh authoritative policy can prune cancelled, expired or
otherwise unauthorised records.

A selected store writes its journal and fsyncs before acknowledging changed data.
Repeated status, fetch and policy checks reuse durable receipts without rewriting
unchanged ciphertext. Higher authority revision and epoch floors remain durable. Two
checksummed banks permit recovery from an interrupted write; the superseded
bank is cleared after commit. Deleted objects leave a tombstone until authority
no longer permits the offer. A logical deletion receipt does not prove erasure
from SSD internals, filesystem snapshots or operator backups. The rollback floor
protects against older policy observed by an intact store; restoring all trusted
state and storage together is outside this guarantee. End-to-end integrity
protects the recipient even when an untrusted storage host lies or loses data.
