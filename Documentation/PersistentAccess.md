# Persistent access and hosting

[Documentation](ReadMe.md)

An operator may choose access **until removed** and hosting consent **until
withdrawn**. This is an explicit opt-in lifetime. Existing timestamp intervals,
manual invitations and finite hosting consent retain their meaning.

## Compatibility and representation

Run `HyperNet protocol-features` and `HyperNetSuite protocol-features` before
configuring a persistent network. Require `UntilWithdrawn/1` on every authority
voter, authoring tool and client. Persistent managed services additionally require
`PersistentActivation/2`; early route replacement requires `RouteHandover/1`.
Retained root adoption requires `PersistentRootPolicy/2`; discovery certificates
require `DiscoveryPolicy/1`.
Upgrade the complete voting committee before publishing persistent records. Old
implementations reject the new field rather than reinterpret it as a timestamp.
Shared admission descriptors must require these features before choosing this mode.

JSON validity keeps its finite form `[startMs, endMs]`. The persistent form is
`[startMs, {"untilWithdrawn": 1}]`. Canonical CBOR keeps a numeric finite end;
the persistent end is the versioned array `[1]`. Null, zero, omitted expiry and
large numeric timestamps do not mean persistent access. Unknown variants fail.
Bootstrap route discovery uses the same end type in `route.expiresMs`; its root
grant inherits that lifetime. New persistent networks select that mode at creation.
Existing networks use the explicit policy migration below without changing the
accepted bootstrap, network, incarnation, keys or retained rollback floors.

Use `--until-withdrawn` instead of `--expires-ms` in member delegation/invitation,
application delegation/offer/renewal and stream service offer commands. It cannot
be combined with a numeric expiry. Grant JSON accepts the tagged end in
`expiresMs`. Every parent grant and membership/application dependency must allow
that lifetime. A finite parent cannot issue a persistent child. Existing finite
records remain finite until their normal explicit successor or admission flow
changes them.

Invitation acceptance windows, deployment possession proofs, route vouchers,
clock observations, challenges and execution permits remain finite. Sealed encryption
device bindings and device admission retain their separate finite consent mode. An invitation
expiring does not remove already admitted persistent membership. Membership
removal, grant/application revocation, current policy and service withdrawal
continue to deny access. A persistent permission is not an immortal connection.

## Adopt an existing finite network

Complete the upgrade while the original administration grants remain current.
Stop services for a consistent private backup, retain all independent rollback
floors, and apply reviewed local software/consent successors. Do not initialise
new network state or replace the accepted bootstrap to extend its dates.

Use `HyperNetSuite authority-inspection policy get` to obtain the current typed
`spec`. Preserve its settings and add `untilWithdrawnRoots: ["ROOT_GRANT_ID"]`,
listing only the exact roots selected for extension, sorted by identifier. Use
`policy prepare --spec Policy.json --output Proposal.cbor`, inspect the proposal,
and submit it with `policy apply --proposal Proposal.cbor --proposal-digest DIGEST`.
These commands use the usual bootstrap, private requester directory, key, socket,
grant and clock arguments. Accept the resulting inspected trust digest with
`policy accept`. Other clients explicitly accept the changed root contract too.

Version2 policy entries bind each selected root's exact original version and the
`UntilWithdrawn/1` end. They cannot alter its key, actions, scope, tier, depth or
budgets. An expired or revoked root cannot be revived by this operation. Original
grant bytes and descendant parent references remain valid. Existing child grants,
memberships and application consents keep their own finite bounds. New child grants
and application renewals can explicitly select persistent validity. This root-only
procedure does not replace create-only member admissions or change their keys.
Revocation remains effective. Removing an extension in a later policy restores the original root
interval and can immediately stop descendants whose authority then expires.

Existing joined profiles keep their original bootstrap and keys. For a new
profile after the original bootstrap discovery interval ends, a server can export
a fresh quorum policy read using `authority-inspection policy export --output
CurrentPolicy.json`, with its usual location, requester, socket and clock arguments.
Every root retained in the current policy must be persistent for this discovery
certificate. Partial root adoption remains usable by existing joined profiles,
but cannot override expired discovery while a retained root remains finite.
Pass that file to `networks prepare --current-policy CurrentPolicy.json` alongside
the original bootstrap and independently pinned fingerprint. The certificate
binds the bootstrap digest, epoch succession, exact persistent roots and permitted
route. It expires with its short native read window, normally five seconds;
fetch it immediately before preparation. Manual preparation without this option
continues to enforce the original bootstrap expiry. This evidence permits offline
profile preparation only. Joining and all operations still require fresh owned
proofs and current native authority. A saved certificate is not an access token.

## Host consent and lifecycle

For an authority profile use `HyperNet runtime setup --until-withdrawn` in place
of `--lifetime-seconds`. Service manifest JSON uses the persistent validity form
above. Preview and sign the exact manifest through the existing operator consent
workflow. Existing installations use the stopped transition `prepare
--until-withdrawn`, followed by preview and explicit apply. Omission retains the
existing lifetime; it never converts an old finite approval automatically.

Persistent consent still binds exact software/image, roles, keys, paths,
endpoints, storage and resource limits. Changes use the ordinary reviewed
successor workflow. Withdrawal remains a local durable veto without a quorum.
Clock validation and rollback detection continue; only the consent expiry timer
is absent. Packet exchanges, helpers and connection proofs retain bounded
operation deadlines. There is no Podman workload timeout for persistent consent.

Select managed session policy and the `CurrentHost` clock binding when automatic
boot is wanted. Managed units verify the exact retained consent before starting,
restart after failures with a five-second delay, and obtain fresh signed clock
and authority evidence. An explicit stop does not request a restart. Disable the
managed unit to retain offline intent across boot. Withdrawal or a changed
profile prevents restart. Status must be accompanied by a real authenticated
operation before reporting functional readiness.

## Dedicated persistent service activation

Persistent managed services use a separate activation manager identity and
private requester profile for each deployment. It must differ from the operator,
registrar and serving keys. Admit that identity through the normal application
workflow with a persistent non-delegating grant: action `26` only, scope
`5:DEPLOYMENT_ID` only. Its entire authority chain, registered deployment and
local consent must be persistent. Admission registrars and ordinary user activity
use their own profiles.

Obtain the current deployment context for this manager. Its first ordinary
request is prepared with:

```sh
HyperNetSuite authority-inspection deployments activation-request \
  --bootstrap Bootstrap.cbor --bootstrap-digest BOOTSTRAP_DIGEST \
  --directory ActivationManager/Floor --key ActivationManager/Identity.json \
  --clock-witness ClockWitness.cbor --clock-monitor-key MONITOR_KEY \
  --host-kernel-boot CurrentHost --deployment DEPLOYMENT_ID \
  --grant ACTIVATION_GRANT_ID --role ROLE --generation LOCAL_GENERATION \
  --persistent --output ActivationRequest.cbor
```

Use `ActivationRequest.cbor` as `--activation-request` in Core's ordinary
`runtime services managed preview` and `enable` commands. The version2 request
reserves the dedicated manager's first sequence. Keep that request pending;
`activation-complete` deliberately refuses to retire a persistent request.
Do not advance or fence this manager profile while its persistent installation
is in use. Software/profile successors require a newly reviewed activation and
dedicated profile. No manager private key enters the serving container.

Every restart creates a new short-lived service challenge and reevaluates the
manager grant, registrar authority, exact deployment and operator consent.
Retaining the manager request does not cache a permit. Other requester profiles
can advance and retire their own sequences without retiring this activation.

## Route handover

A sponsor may replace a voucher in its final 60 seconds with an increasing finite
expiry, identical identities, grant, action, scope and limits. Early replacement
preserves the cumulative usage baseline; it cannot reset a spent budget. The new
generation is required for new admissions. Existing admitted sessions can fetch
current authority across that replacement while retaining their original total
expiry, idle limit and byte budget. Old credentials cannot open new sessions.
After expiry, the original renewal workflow may establish a new budget baseline.
An exhausted early replacement needs that normal expired-voucher renewal or a
separately authorised new voucher; it does not silently replenish capacity.

## Private authority routing and one clock owner

A host supervisor may share one pinned clock monitor across its native services.
For an authority with exact unwithdrawn `Managed`/`CurrentHost` consent, run
`runtime serve --directory PRIVATE --managed-minimum-signer-generation N`.
This starts through the normal managed lifecycle and checks the admitted executable,
consent, signer generation and current clock. It never creates a clock monitor.
The independent minimum is combined with the retained local signer generation;
it cannot lower that generation. Omitting the option keeps foreground behaviour.
Require `ManagedAuthoritySession/1` before selecting this setup.

Normal hosts can confine authority publication to loopback using
`runtime setup --private-peer-routing --bind 127.0.0.1`. Each authority's signed
peer origin must name its actual private bridge address ending in `.20`, and its
own origin must match its declared subnet. This explicit `PrivateAuthorityRouting/1`
consent permits communication between those committee bridges (`isolate=false`).
Other runtime networks retain their previous isolation settings. The service
TLS identities and endpoint certificates remain exact. Only the relay and
chosen public joining endpoint need external publication.

Management sockets support long private storage paths through retained directory
file descriptors. Directory ownership, non-writable ancestry, socket identity
and peer-credential validation still apply.

## Persistent static Pages

Require `PersistentPages/1` on every authority, host and client. A static,
host-readable Page can use `pages author --until-withdrawn`, a Page host profile
with `--retention-until-withdrawn`, and `pages content place --until-withdrawn`.
These flags replace the respective finite `--expires-ms` or `--retention-ms`
option. Persistent author, reviewer, manager and registrar permissions require
persistent current membership and every grant ancestor. The admitted deployment
and exact signed hosting consent must also be persistent.

The versioned end is retained in signed author provenance, host retention,
placement, copy acknowledgement and durable storage metadata. Numeric host
retention still means a duration in milliseconds; `{"untilWithdrawn":1}` means
explicit retention until withdrawal. A persistent record does not use a numeric
expiry ceiling. Finite formats and bounds retain their meaning.

This mode supports ordinary author/reviewer identities and static source without
media assets or forms. Application authoring, media retention, federation treaties
and sealed publication keep their existing finite contracts. Upload authorisation,
review statements, requester challenges and execution proofs remain finite.
An approved Page may be read after the original review statement's acceptance
window, but every read rechecks current publication, permissions and hosting.
Content withdrawal, grant revocation, member removal and local host withdrawal
still deny access. Reconciliation is required before a retained copy serves after
restart, even when its explicit storage lifetime is permanent.
