# Encrypted file transfers

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

A transfer is an immutable, expiring offer between two explicitly authorized
participants. The sender encrypts the file to the recipient's independently
verified native age X25519 key. The recipient accepts that exact key, ciphertext
digest and size, then selects one consenting role 4 store and a destination label.
No automatic host selection or placement fallback overrides that decision.

The authority retains public routing, consent and size metadata. The store holds
opaque ciphertext. The filename and plaintext digest remain inside the encrypted
file header. The maximum ciphertext is 8 MiB and each upload or download chunk is
at most 64 KiB. Static encryption keys do not provide forward secrecy; protect
recipient keys and backups according to the recipient's policy.

Every store effect needs a fresh certified authority result and the exact
selected service's local acceptance. Both participants' current permissions,
cancellation, expiry, deployment consent and withdrawal are checked. Durable
requester and recipient journals distinguish a new effect from reconciliation
of an already claimed operation. A historical receipt can confirm that operation
but cannot grant future access.

HyperNetSuite supplies encrypted local vaults, explicit offer acceptance,
resumable upload and download, packet/receipt exchange, complete ciphertext and
plaintext integrity checks, and atomic output publication without replacement.
The sender's filename never chooses a local path. Files are neither executed
nor extracted. Received copies remain readable by their authorized owner; later
revocation cannot erase previously disclosed content.

Either participant may cancel an agreement. Only the recipient may delete the
selected store's ciphertext. Service operators can immediately withdraw local
consent and publish the corresponding restrictive authority transition. These
actions do not erase backups, local vaults, recipient copies or media remnants.

The installed exchange currently uses private local service control. Internet
reader access requires the approved relay integration; no temporary direct
reader endpoint is provided. Federation does not imply transfer permissions.
See [Transfer protocol](TransferProtocol.md), [Transfer store](TransferStore.md)
and the independent HyperNetSuite client documentation for the exact contracts.

Serving verification combines the sparse certified governance closure with the
independently accepted bootstrap records. Returned records must match their exact
certified references and cannot roll back retained generations. Bootstrap data
does not replace missing live consent, delegated grants or withdrawal records.
