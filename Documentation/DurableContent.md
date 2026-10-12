# Durable Page content

A role1 Page host can reserve a durable content partition in its signed host
profile. The partition stores exact source or opaque ciphertext objects on the
operator's designated volume. Authority replicas retain placement, permission,
approval and receipt metadata. They do not retain the Page body.

The normal [hosting consent](Hosting.md) and [service activation](ServiceRuntime.md)
requirements apply. A network manager cannot add a path, increase a partition,
permit opaque content or replace the operator's selected reviewer keys.

## Capacity and consent

The optional content policy has these fields, in wire order:

| Field | Meaning |
| --- | --- |
| metadataBytes | Physical size of the two-bank object catalogue |
| dataBytes | Maximum combined reserved object extent |
| stagingBytes | Maximum unfinished or repairing object extent |
| quarantineBytes | Maximum quarantined object extent |
| maximumObjects | Maximum retained object entries |
| opaque | Whether encrypted Page objects are accepted |
| failureDomain | Operator-declared failure-domain identity |
| reviewerKeys | Exact reviewer keys accepted for opaque objects |

Metadata has two equal banks and requires at least8192bytes. Data and staging
must be nonzero; staging and quarantine cannot exceed dataBytes. Staging and
quarantine are subsets of the data allocation. Admission reserves dataBytes,
metadataBytes and8192bytes per possible object for file allocation overhead.
The remaining Page metadata partition must fit its own two-bank storage.
The signed maximum object size and retention bound apply separately.

Opaque hosting also requires the deployment manifest's explicit opaque consent
and a matching permitted reviewer key. Failure-domain identifiers are operator
claims, not proof of independent hardware, power, ownership or connectivity.

## Upload and serving

A placement names an exact revision, SHA256, length, permitted host versions,
required copy count, failure domains and expiry. Each upload chunk names that
placement, one selected host, offset, length and chunk digest. Each exchange is
at most32768bytes and requires a fresh certified finite permission.

The host reserves the complete object extent before accepting the first chunk.
An exact retry can reuse stored bytes; changed bytes, skipped offsets and another
placement refuse. Completion checks the full digest and host-readable source
format, synchronises the file and catalogue, and then signs the durable receipt.
Opaque content is hash-checked but its plaintext is available only to authorised
reviewers and readers.

A complete object alone does not grant publication. Publication requires exact
review and the selected current copy and failure-domain conditions. Reads recheck
current publication, requester authority, consent, placement and full object hash.
A missing host can reduce availability without giving another host permission
to store a copy. Signed receipts and successful recent reads are distinct facts.

## Restart, repair and withdrawal

The content directory contains `Store.bin` and digest-derived immutable object
files. Network input never supplies a filesystem path. Open files must be owned,
private, regular, single-link files; symbolic links and unaccounted entries refuse.
The exclusive catalogue lock prevents concurrent writers. Torn catalogue updates
recover the last complete bank; unrecoverable damage never becomes an empty store.

Opening an existing store makes all retained content non-serving. A fresh exact
authorisation and complete hash check reconcile a selected object before read.
Staging progress survives restart. Repair reserves staging capacity before
replacing a corrupt object; interruption retains the exact repair progress.

Withdrawal records the placement tombstone before physical deletion. Purge is
an explicit finite owner or selected-host operation. Interrupted deletion remains
charged and can be retried. Expired, withdrawn or quarantined bytes cannot regain
permission merely because their file or old receipt still exists.

Keep the complete private state directory, profile and journals on persistent
storage. Restore never replaces the current authority floor with an older copy.
An explicitly restored object must reconcile against current authority and
withdrawal state before serving. Copying a directory to another host or volume
does not transfer its consent or placement identity. There is no automatic backup
replication; declared sealed backup destinations currently refuse admission.
Logical withdrawal, file deletion and physical-media sanitisation are distinct.
An unreachable or malicious host cannot be forced to erase previously copied data.
