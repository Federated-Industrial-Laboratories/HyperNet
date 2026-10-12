# Private mail

HyperNet certifies mailbox metadata and stores opaque encrypted letters on
explicitly selected, consenting Mail services. HyperNetSuite implements the
`HyperNetMailMls1` encryption profile using a fresh MLS group for each letter.
Storage services never receive mailbox decryption keys or message plaintext.

## Identity and placement

An admitted manager publishes an independently owner-signed mailbox manifest.
Its address is derived from the network identity and the separate owner key.
The owner signs the exact device roster, store list, copy count, retention and
expiry. Updates require the consecutive generation and exact predecessor digest.
An administrator cannot replace that owner or silently add storage locations.

A private mailbox selects exactly one store and one required copy. Other
mailboxes may explicitly select up to four stores. Network defaults cannot
expand either policy. The mailbox manager must retain the current SendMail and
ReadMail capabilities. Revoking these grants prevents dependent operations.

Each device has separate request and MLS signing keys. Its owner grants `Read`,
`Send` or `Delete` individually. Publication atomically admits request streams
for these devices without granting membership, hosting or governance authority.
Their identities remain reserved after removal; removal does not make a key
available for a different role. Keep application devices in separate vaults.
Sharing an owner's vault also shares the private keys in that vault.

## Claims and delivery

A sender obtains a certified claim naming one unexpired package for every current
Read device. The complete set is consumed atomically. A missing device package
prevents the claim; expired or abandoned claims never return packages to use.
Clients independently verify each actual MLS package, reference, signature,
credential and lifetime before encryption.

The claim then binds one exact ciphertext digest and size. This binding cannot be
replaced. Every Put names the claim as its message identity and rechecks the
current sender, recipient revision, selected service and operator consent.
Recipient removal or another manifest update before binding or delivery refuses
that operation. A client must preserve its pending state after a timeout and
resume the exact request; a timeout is not evidence that delivery failed.

Each selected service provides a signed effect receipt with the exact quorum
result and committed history. The client independently verifies it and retains
it before acknowledging completion. Delivery to several stores consists of
separate operations; there is no atomic transaction across stores. `delivered`
means the manifest's required number of stores supplied verified receipts. It
never means a recipient read the letter.

Fetch and Delete require current recipient device rights. Historical ciphertext
is authenticated against its original signed manifests and certified claim time.
A reader commits the plaintext archive and destruction of its consumed private
package in one age-encrypted snapshot before displaying the letter. An exact
repeat uses that archive instead of consuming another package. Delete removes
one remote copy; local archives and other selected copies remain separate.

## Storage and transport

Mail uses the installed role3 service described in [MailStore](MailStore.md).
Each service has separate retained requester and recipient journals, a bounded
preallocated ciphertext file, and a private local control socket. The recipient
journal retains the exact effect claim before storage changes. Two checksummed
banks preserve committed ciphertext and deletion tombstones across interruption.
A corrupted file with no recoverable bank fails closed. Successful reads also
persist the clock floor; restart cannot reopen expired data by rolling back time.

The fixed file size and signed resource admission determine usable storage.
Claims reserve space for their exact selected placements, including deleted
entries until their claim expiry. Expired storage entries are removed during a
subsequent authorized storage operation. Placement changes do not migrate old
letters or promise immediate deletion from a former store.

There is no direct TCP reader route or public Mail proxy. Clients explicitly
choose an existing private local service socket or the installed service's
bounded exchange command. An unavailable compatible route fails closed. Network
relay routing requires a separately qualified implementation.

## Privacy and recovery limits

The authority sees public mailbox, device, package and claim metadata, including
the ciphertext digest and size. A storage service sees ciphertext, local inbox
identifiers and timing. This profile does not hide recipients or protect against
traffic analysis. Page scripts, mail attachment execution and terminal escape
interpretation are not supported. CLI output serializes message text as JSON.

Removing a device or store restricts future authorized operations. It cannot
erase plaintext, keys or ciphertext already retained by that party. Preserve the
current encrypted vault and its separate age identity. Replacing a live vault or
service journal with an old backup can roll back consumption or effect history;
no local check can detect replacement of every local witness and private file.
Do not resume uncertain backups under an existing live identity. Recovery of a
lost authority committee follows [AuthorityEpochs](AuthorityEpochs.md), and does
not automatically transfer confidential keys or trust to a successor network.

See [MailProtocol](MailProtocol.md) for wire contracts and HyperNetSuite's
`Documentation/PrivateMail.md` for client commands.

Serving verification combines the sparse certified governance closure with the
independently accepted bootstrap records. Returned records must match their exact
certified references and cannot roll back retained generations. Bootstrap data
does not replace missing live consent, delegated grants or withdrawal records.
