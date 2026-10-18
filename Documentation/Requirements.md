# Requirements

[Documentation](ReadMe.md) | [Project](../ReadMe.md)

These requirements describe intended behaviour. They are not implementation or
security certification claims.

## Membership and hosting

- Membership requires an invitation and authenticated enrolment.
- Network membership, publication, storage and service access have separate grants.
- Each host administrator explicitly consents to the roles and resources offered.
- A host can withdraw consent. Remote policy cannot expand local resource grants.
- Administration is replicated across explicitly trusted authorities.
- Internet deployment is part of the threat model.
- Nodes run in confined environments with restricted storage and system access.

## Pages and publication

- HyperNet Pages contain declarative text, links and optional media references.
- Pages cannot contain scripts, executable extensions or automatic commands.
- Publication requires approval of the exact content and its media dependencies.
- Manual review is the default. Restricted adapters can support other review methods.
- Unapproved submissions remain separate from published replication.
- Terminal control sequences from content cannot pass directly to a terminal.
- Images require bounded decoding and safe text alternatives.

## Communication and services

- Users can manage multiple mailbox addresses.
- Private correspondence uses end-to-end encryption and explicit storage policies.
- User privacy restrictions cannot be weakened by administrator defaults.
- Private mailboxes default to persistent storage only on user-selected systems.
- Applications receive scoped, revocable access through documented interfaces.
- File transfers require sender authority, recipient consent and verified content.
- SSH access requires a separate host grant and maintained OpenSSH protection.
- Hosting pages does not grant access to the host shell, private files or devices.

## Portability and client independence

- Linux is the initial platform family, across several distributions.
- The design keeps alternative architectures and future platform ports possible.
- The infrastructure has no dependency on a graphical or terminal frontend.
- FICC and other applications integrate through ordinary application interfaces.
