// SPDX-License-Identifier: MIT
// Only certified finite Page results select immutable objects for local delivery.
use super::*;

pub fn response_inputs(intent: &Intent, value: &V) -> Result<Vec<Reference>> {
    let operation = Operation::parse(intent)?;
    let super::super::Command::Page(command) = operation.command else {
        return Ok(vec![]);
    };
    let f = value.array(5)?;
    ensure!(
        f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == "AuthorityDomain",
        "Page result schema differs"
    );
    let body = f[4].array(4)?;
    ensure!(
        body[0].text()? == command.name(),
        "Page result action differs"
    );
    let mut records = BTreeMap::new();
    for v in body[1].list(MAXIMUM_CONTEXT_RECORDS)? {
        let record = Record::parse(v.bytes()?, intent.network, intent.incarnation)?;
        ensure!(
            records.insert(record.reference.index(), record).is_none(),
            "repeated Page result record"
        );
    }
    let exact = |r: &VersionRef| -> Result<&Record> {
        let record = records
            .get(&r.index())
            .context("Page result dependency absent")?;
        ensure!(
            record.reference == *r,
            "Page result dependency version differs"
        );
        Ok(record)
    };
    let ledger = |page: [u8; 16]| -> Result<Ledger> {
        let record = records
            .get(&(140, page_id(&page)?))
            .context("Page result head absent")?;
        let ledger = Ledger::parse(&record.payload)?;
        ensure!(
            ledger.raw_page == page,
            "Page result native identity differs"
        );
        Ok(ledger)
    };
    let published = |head: &Ledger| -> Result<(Review, Revision)> {
        let reference = head
            .published
            .as_ref()
            .context("Page result has no publication")?;
        let review = Review::parse(
            &exact(reference)?.payload,
            intent.network,
            intent.incarnation,
        )?;
        let revision = Revision::parse(
            &exact(&review.statement.revision)?.payload,
            intent.network,
            intent.incarnation,
        )?;
        ensure!(
            review.statement.approve
                && revision.author.raw_page == head.raw_page
                && revision.author.namespace == head.namespace
                && revision.author.intent.requester == head.author,
            "Page result publication differs from exact head"
        );
        Ok((review, revision))
    };
    match command {
        Command::Inspect { page } => {
            let head = ledger(page)?;
            let pending = head
                .pending
                .context("Page result has no pending revision")?;
            let revision = Revision::parse(
                &exact(&pending)?.payload,
                intent.network,
                intent.incarnation,
            )?;
            ensure!(
                revision.author.raw_page == page
                    && revision.author.intent.requester == head.author
                    && revision.author.intent.revision == head.last_revision,
                "Page inspection source differs"
            );
        }
        Command::Read { page } => {
            published(&ledger(page)?)?;
        }
        Command::Sync {
            host,
            namespace,
            fetch: Some(page),
            ..
        } => {
            ensure!(
                intent.requester == host,
                "Page inventory result requester differs"
            );
            let head = ledger(page)?;
            ensure!(
                head.namespace == namespace,
                "Page inventory namespace differs"
            );
            published(&head)?;
        }
        Command::ReplicaResult { ticket } => {
            let current = records
                .get(&ticket.index())
                .context("Page ticket result absent")?;
            ensure!(
                current.reference == ticket
                    || ticket.generation.checked_add(1) == Some(current.reference.generation)
                        && current.predecessor == Some(ticket.digest),
                "Page replica result no longer names the requested ticket"
            );
            let ticket = Ticket::parse(&current.payload)?;
            ensure!(
                ticket.reader == intent.requester,
                "Page replica result belongs to another reader"
            );
            let review = Review::parse(
                &exact(&ticket.publication)?.payload,
                intent.network,
                intent.incarnation,
            )?;
            if let Some(delivered) = ticket.delivered {
                ensure!(
                    Some(&delivered) == review.bundle.as_ref(),
                    "Page replica result bundle differs"
                );
            }
        }
        _ => {}
    }
    Ok(vec![])
}
