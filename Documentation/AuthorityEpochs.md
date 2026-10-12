# Authority committee replacement

Committee replacement preserves the network identity, policy, admitted identities,
revocations, request streams and domain state. It requires an authorised terminal
command from the old committee and durable installation by the new committee.
Three old signatures and three new readiness signatures are required. A timeout
never appoints an alternative committee.

The installed workflow currently requires four fresh authority identities and
four distinct admitted deployments. Each operator must approve the same ordered
peer identities, addresses, ports, transport keys and certificates. Reusing an
old voter or changing an admitted deployment's immutable consent is refused.
Other admitted services and their consent remain historical records; replacement
does not rewrite or renew them.

## Prepare and nominate

Create each successor installation with `HyperNet runtime setup --future-epoch`
and the next epoch number. This explicitly creates a non-serving installation.
Use the existing consent, possession and deployment registration commands to
admit its exact manifest. Offline setup alone does not grant voting authority.
Keep the operator consent valid throughout installation and activation.

Refresh the administrator's certified governance context, then use
`HyperNetSuite authority-inspection epoch draft` to select the NetworkAdmin grant and the
four deployments. Drafting binds the current state and every required grant,
profile and consent reference. `authority-inspection epoch propose` submits that exact
file. Any intervening committed state change requires a new draft after the
prior request is resolved. A refused proposal leaves the old committee active.

An accepted proposal stops old-epoch execution at its terminal command. Normal
commands cannot pass an unresolved proposal; only finite targeted consensus
no-ops can complete its commit. A committed refusal releases that restriction.

## Export and install

Stop the old runtime workloads before offline export. Retain each installation's
independent signer generation and pass it through `--minimum-signer-generation`.
`HyperNet runtime epoch terminal` exports a terminal signature share, the exact
terminal application state and any prior epoch archive. Keep the full application
state private; it may contain protected network information.

When the terminal state retains Pages, pass `--objects-output` with a new private
absolute directory. The export contains an exact index and the immutable source
and bundle objects needed by pending and published revisions. Each indexed body
has a verified class, byte count and SHA-256 digest. Bitmap and vector payloads
remain on their consented media hosts; this export carries their approved
metadata and receipts through the application state.

Collect three terminal shares with `authority-inspection epoch checkpoint`. Give the exact
result to three old installations through `HyperNet runtime epoch handoff`.
Combine their handoff shares with `authority-inspection epoch handoff`. The resulting
transition is bound to one terminal state, one successor state and one committee.
Old installations remain halted across restart and can only resend this same
handoff.

On each fresh installation run `HyperNet runtime epoch prepare`, supplying the
transition, genesis-to-terminal history, terminal state and prior epoch archive.
The complete state is checked before durable preparation. Preparation exports a
readiness share but cannot vote. It refuses an existing incomplete or conflicting
signer journal; deleting that journal is not a recovery procedure.

Supply that exported directory through `--objects` when preparing each successor.
Preparation derives the required object set from the verified terminal state and
refuses missing, extra or changed objects before issuing readiness. There is no
URL fetch or automatic substitute. An empty object set can omit both options.
Installed helpers receive only fixed input and output mounts; they do not receive
access to the original export path. Existing output is accepted only when it
matches exactly and is never overwritten.

Collect three readiness shares with `authority-inspection epoch ready`. Install the ready
quorum with `HyperNet runtime epoch activate` on every prepared successor, then
start the runtime normally. Voting begins only after the matching quorum is
stored durably. Keep all four installations available for fault tolerance.

## Advance requesters and installed services

Each consumer verifies history from its actual retained floor and tree head.
`authority-inspection epoch retained` exports that consumer's public proof requirements;
pass the file to an old installation's `runtime epoch handoff --retained` to
obtain its exact history. A genesis-only history is insufficient for a consumer
that already retained a later floor.

`authority-inspection epoch seal` durably records the terminal transition and immediately
stops old-epoch effects. `authority-inspection epoch activate` accepts the new readiness
quorum and derives the successor descriptor from the original independent pin.
These operations preserve privacy requirements, restrictive versions, signed
pending requests, unresolved effects and request-stream metadata. Fetch fresh
current-epoch stream status before starting another request. Historical receipts
can confirm a known completion; they cannot authorise an old effect.

An installed service keeps separate requester and serving-recipient journals.
Stop its foreground supervisor, then run `HyperNet runtime services epoch retained`
with separate `--requester-output` and `--recipient-output` files. Obtain a history
for each floor from an old halted authority. Use `runtime services epoch seal`
with `--transition`, `--requester-history` and `--recipient-history` to stop both
old journals durably. `runtime services epoch activate` also requires `--ready`
and an explicit `--authority-directory` for a running new committee member.

Both journals must select the same handoff. Activation checks the new local control
route against their exact successor configuration and preserves the immutable
service manifest, keys and consent. A crash after only one journal advances remains
non-serving; retry the same inputs to finish both journals and retain the route.
The command never restarts a listener. Start the service with a fresh current-epoch
manager activation request after this step. A newly prepared service starts at its
independent initial bootstrap and must adopt retained transitions in order.

Epoch archives have a 2 MiB byte budget and are never silently evicted. A full
archive refuses further activation. Protect retired signing keys: this protocol
cannot distinguish a forged historical quorum after enough old keys are stolen.

If either required quorum is unavailable, the network remains safely stopped.
[Exceptional recovery](NetworkRecovery.md) creates a new network identity that
requires explicit independently authenticated acceptance. It does not restore
revoked grants or silently resume the previous identity.
