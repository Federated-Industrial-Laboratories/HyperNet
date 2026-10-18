// SPDX-License-Identifier: MIT
// Every finite content effect selects current publication, exact placement and operator consent.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Upload,
    Read,
    Inspect,
    Repair,
    Purge,
    Search,
}
impl Effect {
    pub fn code(self) -> u64 {
        match self {
            Self::Upload => 0,
            Self::Read => 1,
            Self::Inspect => 2,
            Self::Repair => 3,
            Self::Purge => 4,
            Self::Search => 5,
        }
    }
    pub fn parse(value: &V) -> Result<Self> {
        Ok(match value.uint()? {
            0 => Self::Upload,
            1 => Self::Read,
            2 => Self::Inspect,
            3 => Self::Repair,
            4 => Self::Purge,
            5 => Self::Search,
            _ => anyhow::bail!("unknown content effect"),
        })
    }
}
pub(super) fn evaluate(
    c: &mut Evaluation<'_>,
    operation: &Operation,
    command: &Command,
    intent: &Intent,
) -> Result<()> {
    use super::super::evaluation::grant;
    let Command::Authorise {
        placement,
        host,
        effect,
        offset,
        bytes,
        ..
    } = command
    else {
        unreachable!()
    };
    let record = c.exact(placement)?;
    let p = Placement::parse(&record.payload)?;
    ensure!(
        p.hosts.contains(host),
        "content effect names an unconsented destination"
    );
    let configured = c.host(host, Some(&p.namespace), true)?;
    let policy = configured
        .profile
        .content
        .as_ref()
        .context("host lacks durable content consent")?;
    ensure!(
        p.bytes <= configured.profile.maximum_asset_bytes && (!p.opaque || policy.opaque),
        "content object exceeds host consent"
    );
    if *effect == Effect::Purge {
        let tombstone = c.select(TOMBSTONE_KIND, placement.id)?;
        ensure!(
            Tombstone::parse(&tombstone.payload)?.placement == *placement,
            "content purge names another tombstone"
        );
        if intent.requester == host.id {
            ensure!(
                operation.grant.is_none(),
                "host purge uses intrinsic authority"
            );
        } else {
            ensure!(
                intent.requester == p.owner,
                "content purge requires owner or selected host"
            );
            owner_scope(c, &p, intent.requester, grant(operation)?)?;
        }
        return Ok(());
    }
    let p = live(c, placement)?;
    ensure!(
        offset.checked_add(*bytes).is_some_and(|end| end <= p.bytes),
        "content effect exceeds its exact immutable range"
    );
    if *effect == Effect::Search {
        ensure!(
            !p.opaque && policy.search && *offset == 0 && *bytes == p.bytes,
            "search requires exact host-readable bytes and explicit indexing consent"
        );
        c.capability(
            &configured.grant,
            configured.manager,
            &[7],
            (1, namespace_id(&p.namespace)?),
            Some(&p.namespace),
            p.bytes,
        )?;
    }
    if p.opaque {
        let (outer, _, _) = sealed::live(c, &p.revision)?;
        ensure!(
            policy.reviewers.contains(&outer.reviewer)
                && outer.placement.hosts.contains(&host.id)
                && outer.placement.volumes.contains(&configured.profile.volume)
                && outer
                    .opaque_consents
                    .contains(&wire::digest(&configured.profile.envelope)),
            "selected opaque host no longer consents to this reviewer or placement"
        );
        sealed::content_access(c, &p, *effect, intent.requester, grant(operation)?)?;
        return Ok(());
    }
    let body = c.revision(&p.revision, true)?;
    let (_, ledger) = c.ledger(body.author.raw_page)?;
    let action = match effect {
        Effect::Upload => {
            ensure!(
                intent.requester == p.owner && ledger.pending.as_ref() == Some(&p.revision),
                "content upload requires the current pending author"
            );
            "PagesSubmit"
        }
        Effect::Read | Effect::Search => {
            c.publication(body.author.raw_page)?;
            ensure!(
                ledger
                    .published
                    .as_ref()
                    .is_some_and(|r| r.id == p.revision.id),
                "content read requires the exact current publication"
            );
            "PagesRead"
        }
        Effect::Inspect => {
            ensure!(
                ledger.pending.as_ref() == Some(&p.revision),
                "content inspection requires the current pending revision"
            );
            if intent.requester == p.owner {
                "PagesSubmit"
            } else {
                "ReviewInspect"
            }
        }
        Effect::Repair => {
            c.publication(body.author.raw_page)?;
            ensure!(
                intent.requester == p.owner
                    && ledger
                        .published
                        .as_ref()
                        .is_some_and(|r| r.id == p.revision.id),
                "content repair requires the exact published author placement"
            );
            "PagesSubmit"
        }
        Effect::Purge => unreachable!(),
    };
    if *effect == Effect::Search {
        c.read_capability(
            grant(operation)?,
            intent.requester,
            &[0, 1],
            (2, body.author.intent.resource),
            Some(&p.namespace),
            *bytes,
        )?;
        c.application(
            intent.requester,
            grant(operation)?,
            None,
            "PagesSearch",
            &p.namespace,
            Some(body.author.raw_page),
        )?;
    }
    c.principal(
        intent.requester,
        grant(operation)?,
        None,
        action,
        &p.namespace,
        Some(body.author.raw_page),
        *bytes,
    )?;
    Ok(())
}
