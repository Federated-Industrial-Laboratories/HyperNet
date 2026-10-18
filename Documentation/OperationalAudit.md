# Operational event history

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

Each installed authority or service deployment has a private `Audit` directory.
Setup creates a separate signing identity. Lifecycle events bind the deployment,
network, incarnation, exact profile, software digest, consent generation, event
sequence, previous event digest, time, operation and outcome. Only fixed operation
and outcome names are accepted. Bodies, invitations, form values, search terms,
credentials and navigation histories are not recorded.

The event key grants no network authority. Its signatures identify the emitter;
they cannot prove that a compromised emitter reported every event truthfully.
Identifiers and times remain private metadata. Export them only to an approved
witness. The diagnostic preview does not automatically export this history.

An expanding lifecycle operation first records its prepared event durably.
If that write fails, the operation cannot proceed. Its committed event follows
the durable effect. An interruption between these points leaves a prepared event
with an uncertain outcome; inspect the current runtime state before recovery.
Failure to complete the startup audit stops the owned workload. Stop, withdrawal
and their cleanup remain available if event storage fails, with an explicit
audit-loss warning. Committed authority permission and publication decisions
retain their separate consensus evidence.

## Inspect and configure

```sh
HyperNet runtime audit inspect --directory /Private/AuthorityOne
HyperNet runtime audit configure --directory /Private/AuthorityOne \
  --maximum-bytes 67108864 --retention-seconds 7776000
```

The default event budget is 16 MiB with 90 days minimum local retention. The byte
budget is configurable from64 KiB to16 GiB; it is a bounded local metadata budget,
not a traffic rate. An additional1 MiB allocation reserves failure-reporting space.
Exports are paginated in batches of at most 1 MiB. Fixed event schemas are bounded
to8 KiB each. Choose storage and retention for the expected lifecycle activity.
Increasing the budget does not allocate that entire amount immediately. A lower
budget must still fit retained history and the configuration outcome; it cannot
remove events or bypass their retention interval.

Events are not silently overwritten when full. Export to a witness and prune
expired events, or explicitly increase the budget. Capacity is reserved for
restrictive outcomes and changing the audit budget. Changing the retention policy
does not itself delete events. Event files and heads are private owner files.
Do not delete the key, retained head or anchor to make a full log appear empty.

## Independently witness a head

Obtain the emitter key from `audit inspect` and authenticate it through a separate
channel. Initialise a witness on an independently controlled system:

```sh
HyperNet runtime audit witness-init --directory /Private/Witness \
  --emitter-key <authenticated-emitter-key>
```

Retain and independently authenticate the returned witness key. Distinct keys or
directories alone do not establish independent operation. A witness controlled
by the same compromised operator cannot provide that independence.

The first export starts at sequence zero:

```sh
HyperNet runtime audit export --directory /Private/AuthorityOne \
  --after-sequence 0 --output /Private/Export/Batch.json
```

Transfer the batch through an authorised confidential channel, then run on the
witness system:

```sh
HyperNet runtime audit witness-accept --directory /Private/Witness \
  --batch /Private/Import/Batch.json --output /Private/Export/Receipt.json
```

The witness checks signatures and every intervening sequence and digest. It
retains its new head before producing the signed receipt. A repeated exact batch
can produce the same retained receipt after an interrupted export. A conflicting
head, old prefix or missing intervening events is refused. Subsequent exports
start at the witness's retained sequence. Repeat until `throughSequence` reaches
`currentSequence`. No network request or external upload occurs automatically.

An external retained head can reveal a conflicting or missing previously
witnessed tail. It cannot reveal events never sent to that witness. Retain the
private witness state independently; restoring both systems to old snapshots
would remove this protection.

## Prune expired local history

Return the signed receipt to the emitter and use the authenticated witness key:

```sh
HyperNet runtime audit prune --directory /Private/AuthorityOne \
  --receipt /Private/Import/Receipt.json \
  --witness-key <authenticated-witness-key>
```

Pruning requires a receipt on the exact retained event chain. Only events at or
before that head whose minimum retention has elapsed are removed. The signed
anchor is durably advanced before removal; interruption can leave extra expired
files but cannot expose a missing live prefix. Retain exported batches separately
if their full contents are needed after local pruning: the witness retains a
head and receipt, not an archive of every event. File deletion is not a claim of
physical media erasure.
