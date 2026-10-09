# HyperNet 0.8.0 contracts

These documents define the replacement network contract. They do not add runtime
features to the current 0.7.5 executables. In particular, the current authority
still uses its documented trusted crash-fault model. No Byzantine, relay-privacy,
sealed-publication or runtime qualification follows from these specifications.

| Contract | Defines |
| --- | --- |
| [Wire](WireContract.md) | Canonical bytes, signature purpose, exact requests, recipient challenges and executed-result proofs |
| [Authority](AuthorityContract.md) | Four-replica Basic HotStuff phases, durable votes/locks, time/freshness and recovery boundaries |
| [Policy](PolicyContract.md) | Independent policies, tiers, recipient continuity, sealed revisions, custody, consent and lifecycle |
| [Runtime](RuntimeContract.md) | Native management, readiness, complete relay coverage, diagnostics and software replacement |

[Wire vectors](WireVectors.json) contain exact canonical bytes and synthetic
certificate acceptance/refusal examples. Their keys are public test fixtures.
[Policy vectors](PolicyVectors.json) define semantic transition obligations;
they are not claims that all operational checks have run.

Four independent choices configure the same runtime:

| Policy | Default | Supported alternative |
| --- | --- | --- |
| Participation | Invitation-only, explicit reader grant | Approved applications or explicitly public host-readable publications |
| Reader privacy | Approved independent relay | Approved organisational relay under its narrower declared guarantee |
| Hosted Pages | Exact approved host-readable content | Bounded sealed publications for authenticated recipient devices |
| Recovery | Offline owner custody, preferably two of three keys | Two of three distinct custodians, without an owner-only bypass |

Explicit capabilities determine authority. Tier numbers, admission, storage
contribution and computational work confer no additional privilege. Configuration
cannot disable signature verification, quorum rules, local consent, user placement
vetoes, exact approval, bounded parsing or client privacy minima.

Basic HotStuff remains the fixed-committee specification. Complete synchroniser,
crash-safe integration, certified state transfer, actual clock-health assurance
and safe lost-key committee replacement require implementation qualification.
The fixed-committee model does not supply a dynamic-membership protocol. Unknown
or unsafe replacement paths must refuse rather than reconstruct authority from
a convenient set of three signatures.

Online client joining requires the same approved relay connector used for all
other reader requests. Offline provisioning alone does not grant membership.
No temporary direct-reader fallback is permitted while a runtime is incomplete.

Policy changes protect future authorised operations. They cannot erase plaintext
already retained by a reader or host. Recovery proposes a new identity requiring
independently authenticated acceptance; threshold signatures do not establish a
globally unique successor. Missing or conflicting authority causes refusal.

Core and Suite carry identical common contract documents and vectors while
remaining independently built products. New implementations must exercise these
contracts through their normal installed interfaces. Unchanged earlier evidence
retains its original software and configuration identity.
