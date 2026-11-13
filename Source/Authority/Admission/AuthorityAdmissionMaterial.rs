// SPDX-License-Identifier: MIT
// Slot-owned records use ordinary capabilities while retaining exact assignment provenance.
use super::*;

fn header(kind: u64, id: Digest, n: Digest, i: Digest, old: &[Vec<u8>]) -> Result<Vec<V>> {
    let previous = old.iter().find(|bytes| {
        wire::decode(bytes).is_ok_and(|v| {
            v.list(32).is_ok_and(|f| {
                f[0].uint().ok() == Some(kind) && f[6].fixed::<32>().ok() == Some(id)
            })
        })
    });
    let generation = previous.map_or(Ok(1), |x| {
        wire::decode(x)?.list(32)?[4]
            .uint()?
            .checked_add(1)
            .context("slot material generation exhausted")
    })?;
    Ok(vec![
        V::Uint(kind),
        V::Uint(1),
        b(&n),
        b(&i),
        V::Uint(generation),
        previous.map_or(V::Null, |x| b(&wire::digest(x))),
        b(&id),
    ])
}
fn scopes(p: &Policy, t: &Template, n: Digest, purpose: u64) -> V {
    match purpose {
        1 => a(vec![a(vec![V::Uint(0), b(&n)])]),
        2 => {
            let mut targets = vec![p.authority, t.destination];
            targets.sort();
            a(targets
                .into_iter()
                .map(|id| a(vec![V::Uint(3), b(&id)]))
                .collect())
        }
        3 => a(vec![a(vec![
            V::Uint(3),
            b(&t.application.expect("chat template")),
        ])]),
        _ => unreachable!(),
    }
}
pub fn enrol_material(
    p: &Policy,
    s: &Slot,
    tier: &VersionRef,
    snapshot: &Snapshot,
    n: Digest,
    i: Digest,
) -> Result<Vec<Vec<u8>>> {
    let mut material = s.material.clone();
    for role in &s.roles {
        let template = p.template(role.role)?;
        let mut reader = None;
        let owned = role.grants(p.reference.id, s.slot);
        let member = identifier(p.reference.id, s.slot, role.role, 0)?;
        for purpose in 1..=if role.role == 1 { 3 } else { 2 } {
            let id = identifier(p.reference.id, s.slot, role.role, purpose)?;
            let mut fields = header(102, id, n, i, &s.material)?;
            fields.extend([
                b(&p.owner),
                b(&role.member),
                reference(tier),
                a(vec![V::Uint(match purpose {
                    1 | 2 => 0,
                    _ => 30,
                })]),
                scopes(p, template, n, purpose),
                p.validity.value(),
                reference(&p.parent),
                V::Uint(0),
                a(template.limits.iter().map(|x| V::Uint(*x)).collect()),
                snapshot.value.clone(),
            ]);
            let bytes = wire::encode(&a(fields))?;
            if purpose == 1 {
                reader = Some(VersionRef {
                    kind: 102,
                    id,
                    generation: wire::decode(&bytes)?.array(17)?[4].uint()?,
                    digest: wire::digest(&bytes),
                });
            }
            material.retain(|x| {
                !wire::decode(x).is_ok_and(|v| {
                    v.list(32).is_ok_and(|f| {
                        f[0].uint().ok() == Some(102) && f[6].fixed::<32>().ok() == Some(id)
                    })
                })
            });
            material.push(bytes);
        }
        let mut fields = header(125, member, n, i, &s.material)?;
        fields.extend([
            b(&role.member),
            p.validity.value(),
            V::Bool(false),
            reference(&reader.context("reader material missing")?),
            snapshot.value.clone(),
        ]);
        material.retain(|x| {
            !wire::decode(x).is_ok_and(|v| {
                v.list(32).is_ok_and(|f| {
                    f[0].uint().ok() == Some(125) && f[6].fixed::<32>().ok() == Some(member)
                })
            })
        });
        material.push(wire::encode(&a(fields))?);
        ensure!(
            owned.len() == if role.role == 1 { 3 } else { 2 },
            "invalid role material"
        );
    }
    material.sort_by_key(|x| {
        let v = wire::decode(x).expect("encoded material");
        let f = v.list(32).expect("encoded array");
        (f[0].uint().expect("kind"), f[6].fixed::<32>().expect("id"))
    });
    Ok(material)
}
pub fn validate_material(p: &Policy, s: &Slot, records: &[Vec<u8>], n: Digest) -> Result<()> {
    let parent = records
        .iter()
        .find(|x| {
            wire::decode(x).is_ok_and(|v| {
                v.list(32).is_ok_and(|f| {
                    f[0].uint().ok() == Some(102) && f[6].fixed::<32>().ok() == Some(p.parent.id)
                })
            })
        })
        .context("admission parent absent")?;
    ensure!(
        wire::digest(parent) == p.parent.digest,
        "admission parent reference differs"
    );
    let parent = wire::decode(parent)?;
    let tier = parent.array(17)?[9].clone();
    let mut seen = BTreeSet::new();
    for bytes in &s.material {
        let v = wire::decode(bytes)?;
        let f = v.list(32)?;
        let kind = f[0].uint()?;
        let lookup = id(&f[6])?;
        ensure!(
            seen.insert((kind, lookup))
                && s.owned()?.contains(&(kind, lookup))
                && records.contains(bytes),
            "slot material is missing, repeated or foreign"
        );
        let (role, purpose) = (0..2)
            .flat_map(|r| (0..=if r == 1 { 3 } else { 2 }).map(move |p| (r, p)))
            .find(|(r, purpose)| {
                identifier(p.reference.id, s.slot, *r, *purpose).ok() == Some(lookup)
            })
            .context("slot material identifier differs")?;
        let template = p.template(role)?;
        if kind == 102 {
            ensure!(
                purpose > 0
                    && f.len() == 17
                    && f[7].fixed::<32>()? == p.owner
                    && f[9] == tier
                    && f[10]
                        == a(vec![V::Uint(match purpose {
                            1 | 2 => 0,
                            _ => 30,
                        })])
                    && f[11] == scopes(p, template, n, purpose)
                    && f[12] == p.validity.value()
                    && f[13] == reference(&p.parent)
                    && f[14].uint()? == 0
                    && limits(&f[15])? == template.limits,
                "slot grant exceeds fixed policy template"
            );
        } else {
            ensure!(
                kind == 125
                    && purpose == 0
                    && f.len() == 12
                    && f[8] == p.validity.value()
                    && !f[9].boolean()?,
                "slot membership differs from fixed template"
            );
        }
        if let Some(active) = s
            .roles
            .iter()
            .find(|r| r.role == role)
            .filter(|_| s.active())
        {
            ensure!(
                f[if kind == 125 { 7 } else { 8 }].fixed::<32>()? == active.member,
                "slot material is bound to another candidate"
            );
        }
    }
    if s.active() {
        for role in &s.roles {
            ensure!(
                seen.contains(&(125, identifier(p.reference.id, s.slot, role.role, 0)?))
                    && role
                        .grants(p.reference.id, s.slot)
                        .iter()
                        .all(|id| seen.contains(&(102, *id))),
                "active slot lacks fixed capability material"
            );
        }
    }
    Ok(())
}
