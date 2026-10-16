# Cold content archive custody

`HyperNet backup destination` provides native initialise, import, list, export and
purge commands for encrypted Page archives. The independent Suite creates and
restores archives through the certified authority protocol; see its
`Documentation/Backups.md` for the complete workflow.

A cold destination is bound to one installed host and volume. The native command
validates its current signed consent and prepared backing filesystem. It allocates
only explicitly consented volume surplus above the service's existing state
allocation. Destination quotas are charged together, and private device/inode
bindings prevent a copied catalogue from silently selecting another directory.

Import accepts only the exact destination's signed profile, a permitted owner's
signed archive manifest, and matching encrypted bytes. It checks immutable IDs,
retention, logical and physical capacity before durable acknowledgement. An
interrupted import remains charged until resumed or purged. Exact retries do not
create additional copies. Export does not decrypt content. Expired packages are
removed on import, export, list and explicit purge; deployments may schedule the
native purge command for an otherwise idle online destination.

Storage consent is separate from publication authority. A native offline import
is explicit operator custody; it does not confer serving permission. The Suite
commits the exact archive through current authority and requires it again on
restore. Decrypted restore staging remains non-serving until current publication,
placement, capabilities, recipient state and tombstones reconcile. Each source or
media repair obtains fresh authority. No old approval, request journal or index is
restored.

Archives contain one Page and its canonical bitmap/vector assets, or the original
sealed Page ciphertext and encrypted assets. They exclude mail/transfer queues,
identity vaults, authority journals, daemon snapshots and search indexes. Local
indexes must be rebuilt through the currently authorised search workflow.

Destination consent and archive placement use shared domain records169,170 and171.
A sealed backup requires the named destination in both exact author and approved
outer placement. The destination must separately consent to opaque content and
its reviewer. An owning publisher may read or repair its exact published
ciphertext with current Submit authority; this grants no plaintext keys, new
recipient or permission to change the ciphertext digest or approved revision.
