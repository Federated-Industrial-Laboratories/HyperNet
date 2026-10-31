// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
fn prefix(
    value: &V,
    kind: u64,
    length: usize,
    network: Digest,
    incarnation: Digest,
) -> Result<&[V]> {
    let f = value.array(length)?;
    ensure!(
        f[0].uint()? == kind
            && f[1].uint()? == 1
            && f[2].fixed::<32>()? == network
            && f[3].fixed::<32>()? == incarnation
            && f[4].uint()? == 1
            && f[5] == V::Null,
        "application record context differs"
    );
    Ok(f)
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub struct Withdrawal {
    pub admission: VersionRef,
    pub withdrawer: Key,
    pub reference: VersionRef,
}

#[cfg(test)]
impl Withdrawal {
    pub fn parse(bytes: &[u8], network: Digest, incarnation: Digest) -> Result<Self> {
        let value = wire::decode(bytes)?;
        let f = prefix(&value, 128, 9, network, incarnation)?;
        let admission = version(&f[6])?;
        let withdrawer = f[7].fixed()?;
        wire::valid_key(&withdrawer)?;
        ensure!(
            admission.kind == 127,
            "withdrawal target is not an application"
        );
        Snapshot::parse(&f[8])?;
        Ok(Self {
            admission,
            withdrawer,
            reference: record_reference(bytes)?,
        })
    }
}

/// The quorum certifies ownership/completeness; this checks the exact bounded lifecycle schema.
#[cfg(test)]
pub fn validate_lifecycle_result(intent: &Intent, value: &V) -> Result<Vec<VersionRef>> {
    let operation = Operation::parse(intent)?;
    let f = value.list(7)?;
    ensure!(
        f.len() >= 4 && f[0].uint()? == 201 && f[1].uint()? == 1 && f[2].text()? == intent.action,
        "application result context differs"
    );
    let declared = refs(
        &f[3],
        if matches!(operation, Operation::List { .. }) {
            192
        } else {
            64
        },
    )?;
    let mut derived = Vec::new();
    match operation {
        Operation::Get {
            application,
            minimum,
        } => {
            let f = value.array(7)?;
            let admission = Registration::parse(f[4].bytes()?, intent.network, intent.incarnation)?;
            ensure!(
                admission.application == application
                    && (intent.requester == application || intent.requester == admission.owner),
                "application metadata is not owned by requester"
            );
            let grant_bytes = f[5].bytes()?;
            let grant = record_reference(grant_bytes)?;
            let value = wire::decode(grant_bytes)?;
            let g = prefix(&value, 102, 17, intent.network, intent.incarnation)?;
            let child = membership::ChildSpec::parse(
                &a(vec![
                    g[6].clone(),
                    g[8].clone(),
                    g[9].clone(),
                    g[10].clone(),
                    g[11].clone(),
                    g[12].clone(),
                    g[14].clone(),
                    g[15].clone(),
                ]),
                intent.network,
            )?;
            ensure!(
                grant == admission.grant
                    && g[7].fixed::<32>()? == admission.owner
                    && child.subject == application
                    && version(&g[13])?.kind == 102
                    && child.depth == 0
                    && !child.actions.contains(&11)
                    && (admission.renewable
                        || admission.validity.0 >= child.validity.0
                            && admission.validity.1 <= child.validity.1),
                "application metadata grant differs"
            );
            Snapshot::parse(&g[16])?;
            derived.extend([admission.reference.clone(), grant]);
            if f[6] != V::Null {
                let withdrawal =
                    Withdrawal::parse(f[6].bytes()?, intent.network, intent.incarnation)?;
                ensure!(
                    withdrawal.admission == admission.reference
                        && (withdrawal.withdrawer == application
                            || withdrawal.withdrawer == admission.owner),
                    "application withdrawal differs"
                );
                derived.push(withdrawal.reference);
            } else {
                ensure!(
                    !minimum.iter().any(|v| v.kind == 128 && v.id == application),
                    "application withdrawal omitted"
                );
            }
            ensure!(
                relevant_minima(&derived, &minimum),
                "application metadata is below retained generations"
            );
        }
        Operation::List { minimum, .. } => {
            let f = value.array(5)?;
            let mut prior = None;
            for row in f[4].list(63)? {
                let r = row.array(4)?;
                let application = r[0].fixed()?;
                wire::valid_key(&application)?;
                ensure!(
                    prior.is_none_or(|p| p < application) && application != intent.requester,
                    "application list is duplicate, unsorted or self-owned"
                );
                prior = Some(application);
                let admission = version(&r[1])?;
                let grant = version(&r[2])?;
                ensure!(
                    admission.kind == 127 && admission.id == application && grant.kind == 102,
                    "application list row references differ"
                );
                derived.extend([admission, grant]);
                if r[3] != V::Null {
                    let withdrawal = version(&r[3])?;
                    ensure!(
                        withdrawal.kind == 128 && withdrawal.id == application,
                        "application list withdrawal differs"
                    );
                    derived.push(withdrawal);
                } else {
                    ensure!(
                        !minimum.iter().any(|v| v.kind == 128 && v.id == application),
                        "application list withdrawal omitted"
                    );
                }
            }
            ensure!(
                relevant_minima(&derived, &minimum),
                "application list is below retained generations"
            );
        }
        _ => anyhow::bail!("not an application metadata result"),
    }
    derived.sort_by_key(VersionRef::index);
    derived.dedup();
    ensure!(
        declared == derived && wire::encode(value)?.len() <= MAX_CONTEXT_BYTES,
        "application result versions or size differ"
    );
    Ok(declared)
}

impl Operation {
    #[cfg(test)]
    pub fn prepare(
        &self,
        records: &[Vec<u8>],
        reservations: &Reservations,
        intent: &Intent,
        at: u64,
        replay: bool,
    ) -> Result<Decision> {
        self.evaluate(records, reservations, intent, at, replay, false)
    }
}
