// SPDX-License-Identifier: MIT
//! Requested dependencies remain bounded and unauthoritative until engine validation.
use super::*;
use std::collections::BTreeSet;
// Discovery work is bounded independently of retained object capacity.
const MAX_PIVOTS: usize = 65_536;
pub(super) struct Repair {
    pub view: u64,
    goals: BTreeMap<Reference, Vec<u8>>,
    root: Option<Reference>,
    pivots: usize,
    wanted: BTreeSet<Reference>,
    staged: BTreeMap<Reference, Vec<u8>>,
    waiting: Vec<Message>,
    flight: Option<(Digest, Vec<Reference>)>,
}
impl Repair {
    pub(super) fn pending_message(&self) -> Option<Message> {
        self.flight
            .as_ref()
            .map(|(id, refs)| Message::RepairRequest(*id, refs.clone()))
    }
    #[cfg(test)]
    pub(super) fn retained_counts(&self) -> (usize, usize, usize, usize) {
        (
            self.wanted.len(),
            self.staged.len(),
            self.goals.len(),
            self.pivots,
        )
    }
    fn new(view: u64) -> Self {
        Self {
            view,
            goals: BTreeMap::new(),
            root: None,
            pivots: 0,
            wanted: BTreeSet::new(),
            staged: BTreeMap::new(),
            waiting: Vec::new(),
            flight: None,
        }
    }
    fn goal(&mut self, item: Item) -> Result<()> {
        ensure!(
            self.goals.contains_key(&item.reference) || self.goals.len() < 8,
            "Dependency goal capacity exhausted"
        );
        self.goals.entry(item.reference).or_insert(item.bytes);
        Ok(())
    }
    fn seed(&mut self, reference: Reference, bytes: Vec<u8>) {
        self.wanted = BTreeSet::from([reference.clone()]);
        self.staged = BTreeMap::from([(reference.clone(), bytes)]);
        self.root = Some(reference);
        self.flight = None;
    }
    fn add(&mut self, r: Reference) -> Result<()> {
        ensure!(
            self.wanted.contains(&r) || self.wanted.len() < super::super::repair::MAX_RECORDS,
            "Dependency repair capacity exhausted"
        );
        self.wanted.insert(r);
        Ok(())
    }
    fn wait(&mut self, message: Message) -> Result<()> {
        let digest = wire::digest(&message.payload()?);
        if !self
            .waiting
            .iter()
            .any(|m| m.payload().is_ok_and(|p| wire::digest(&p) == digest))
        {
            ensure!(self.waiting.len() < 8, "Dependency wait capacity exhausted");
            self.waiting.push(message);
        }
        Ok(())
    }
}
impl Driver {
    fn available(&self, r: &Reference) -> Result<bool> {
        Ok(!self
            .engine
            .repair_export(std::slice::from_ref(r))?
            .is_empty())
    }
    pub(super) fn dependencies(
        &mut self,
        sender: Key,
        message: Message,
        items: Vec<Item>,
    ) -> Result<bool> {
        let mut pending = Vec::new();
        for item in items {
            ensure!(
                item.reference.kind == 12,
                "Durable dependencies require a quorum certificate"
            );
            peer::validate_item(self.config(), &item)?;
            if !self.available(&item.reference)? {
                pending.push(item);
            }
        }
        if pending.is_empty() {
            return Ok(true);
        }
        let refs: Vec<_> = pending.iter().map(|i| i.reference.clone()).collect();
        if let Ok(certificates) = self
            .engine
            .repair_import_with_inputs(&refs, &pending, |bytes| {
                self.application.command_inputs(bytes)
            })
        {
            for qc in certificates {
                self.broadcast(Message::Certificate(qc))?;
            }
            return Ok(true);
        }
        let view = self.engine.view();
        let repair = self
            .repairs
            .entry(sender)
            .or_insert_with(|| Repair::new(view));
        for item in pending {
            repair.goal(item)?;
        }
        repair.wait(message)?;
        self.repair_progress(sender)?;
        Ok(false)
    }
    pub(super) fn repair_response(
        &mut self,
        sender: Key,
        id: Digest,
        items: Vec<Item>,
    ) -> Result<()> {
        let mut seen = BTreeSet::new();
        for item in &items {
            peer::validate_item(self.config(), item)?;
            ensure!(seen.insert(item.reference.clone()), "Repeated repair item");
        }
        let repair = self
            .repairs
            .get_mut(&sender)
            .context("Unsolicited repair response")?;
        let (flight_id, requested) = repair
            .flight
            .as_ref()
            .context("No repair request is pending")?;
        ensure!(*flight_id == id, "Repair response identity differs");
        for item in &items {
            ensure!(
                requested.contains(&item.reference),
                "Unrequested dependency"
            );
        }
        let mut total: usize = repair.staged.values().map(Vec::len).sum();
        for item in &items {
            total -= repair.staged.get(&item.reference).map_or(0, Vec::len);
            total = total
                .checked_add(item.bytes.len())
                .context("Repair size overflow")?;
        }
        ensure!(
            total <= super::super::repair::MAX_BYTES,
            "Repair staging exceeds byte bound"
        );
        for item in items {
            repair.staged.insert(item.reference, item.bytes);
        }
        repair.flight = None;
        self.repair_progress(sender)
    }
    pub(super) fn repair_progress(&mut self, sender: Key) -> Result<()> {
        let Some(mut repair) = self.repairs.remove(&sender) else {
            return Ok(());
        };
        let result = self.progress_inner(sender, &mut repair);
        if result.is_ok() && (!repair.wanted.is_empty() || !repair.waiting.is_empty()) {
            self.repairs.insert(sender, repair);
        }
        result
    }
    fn progress_inner(&mut self, sender: Key, repair: &mut Repair) -> Result<()> {
        for _ in 0..super::super::repair::MAX_RECORDS {
            if repair.wanted.is_empty() {
                let mut goal = None;
                for (reference, bytes) in &repair.goals {
                    if !self.available(reference)? {
                        goal = Some((reference.clone(), bytes.clone()));
                        break;
                    }
                }
                if let Some((reference, bytes)) = goal {
                    repair.seed(reference, bytes);
                } else {
                    break;
                }
            }
            let known = repair
                .wanted
                .iter()
                .map(|r| Ok((r.clone(), self.available(r)?)))
                .collect::<Result<Vec<_>>>()?;
            for (r, available) in known {
                if available {
                    repair.wanted.remove(&r);
                    repair.staged.remove(&r);
                }
            }
            let staged = repair
                .staged
                .iter()
                .map(|(r, bytes)| Item {
                    reference: r.clone(),
                    bytes: bytes.clone(),
                })
                .collect::<Vec<_>>();
            let mut needed = repair.wanted.clone();
            for item in &staged {
                peer::validate_item(self.config(), item)?;
                for dependency in dependencies(self.config(), item)? {
                    if !self.available(&dependency)? {
                        needed.insert(dependency);
                    }
                }
            }
            let total: usize = repair.staged.values().map(Vec::len).sum();
            if needed.len() > super::super::repair::MAX_RECORDS
                || total > super::super::repair::MAX_BYTES - peer::MAX_PAYLOAD
            {
                let (reference, bytes) = self.repair_pivot(repair)?;
                ensure!(
                    repair.pivots < MAX_PIVOTS,
                    "Dependency discovery work bound exhausted"
                );
                repair.pivots += 1;
                // Keep original certified goals and waiting messages. Upper
                // transient bodies are re-fetched after a lower QC is imported.
                repair.seed(reference, bytes);
                continue;
            }
            for dependency in needed {
                repair.add(dependency)?;
            }
            let mut progress = false;
            for root in staged.iter().filter(|item| item.reference.kind == 12) {
                // A lower certified subclosure may be complete while a higher
                // certificate still awaits its branch. Never publish raw fragments.
                if let Some(items) = self.certified_closure(&root.reference, repair)? {
                    let refs: Vec<_> = items.iter().map(|item| item.reference.clone()).collect();
                    self.engine
                        .repair_import_with_inputs(&refs, &items, |bytes| {
                            self.application.command_inputs(bytes)
                        })?;
                    for item in items {
                        repair.wanted.remove(&item.reference);
                        repair.staged.remove(&item.reference);
                    }
                    progress = true;
                }
            }
            let total: usize = repair.staged.values().map(Vec::len).sum();
            ensure!(
                total <= super::super::repair::MAX_BYTES,
                "Repair staging exceeds byte bound"
            );
            if !progress && !repair.wanted.is_empty() {
                break;
            }
        }
        if repair.wanted.is_empty() {
            for (reference, bytes) in &repair.goals {
                if !self.available(reference)? {
                    let reference = reference.clone();
                    let bytes = bytes.clone();
                    repair.seed(reference, bytes);
                    return Ok(());
                }
            }
            let waiting = std::mem::take(&mut repair.waiting);
            self.apply()?;
            for message in waiting {
                let _ = self.receive(sender, message);
            }
            return Ok(());
        }
        if repair.flight.is_none() {
            let refs: Vec<_> = repair
                .wanted
                .iter()
                .filter(|r| !repair.staged.contains_key(*r))
                .take(peer::MAX_REPAIR_RECORDS)
                .cloned()
                .collect();
            ensure!(
                !refs.is_empty(),
                "Repair dependencies could not be verified"
            );
            repair.flight = Some((rand::random(), refs));
        }
        let (id, refs) = repair.flight.as_ref().unwrap();
        self.send(sender, &Message::RepairRequest(*id, refs.clone()))
    }
    fn repair_pivot(&self, repair: &Repair) -> Result<(Reference, Vec<u8>)> {
        let root = repair.root.as_ref().context("Dependency root is missing")?;
        let mut cursor = root.clone();
        let mut selected = None;
        let mut seen = BTreeSet::new();
        for _ in 0..super::super::repair::MAX_RECORDS {
            ensure!(seen.insert(cursor.clone()), "Dependency ancestry repeats");
            let Some(bytes) = repair.staged.get(&cursor) else {
                break;
            };
            let qc = Certificate::parse(self.config(), bytes)?;
            let node_ref = reference(14, qc.node);
            if self.available(&node_ref)? {
                break;
            }
            let Some(node_bytes) = repair.staged.get(&node_ref) else {
                break;
            };
            let node = Node::parse(self.config(), node_bytes)?;
            ensure!(qc.view == node.view, "Dependency QC view differs");
            let Some(justify) = node.justify else { break };
            let next_ref = reference(12, justify);
            if self.available(&next_ref)? {
                break;
            }
            let Some(next_bytes) = repair.staged.get(&next_ref) else {
                break;
            };
            let next = Certificate::parse(self.config(), next_bytes)?;
            ensure!(
                next.phase == Phase::Prepare
                    && Some(next.node) == node.parent
                    && next.view < node.view,
                "Dependency pivot is not its certified parent"
            );
            selected = Some((next_ref.clone(), next_bytes.clone()));
            cursor = next_ref;
        }
        selected.context("Dependency discovery cannot reach a certified subclosure")
    }
    fn certified_closure(&self, root: &Reference, repair: &Repair) -> Result<Option<Vec<Item>>> {
        let mut seen = BTreeSet::new();
        let mut pending = vec![root.clone()];
        let mut items = Vec::new();
        while let Some(reference) = pending.pop() {
            if !seen.insert(reference.clone()) || self.available(&reference)? {
                continue;
            }
            let Some(bytes) = repair.staged.get(&reference) else {
                return Ok(None);
            };
            let item = Item {
                reference,
                bytes: bytes.clone(),
            };
            peer::validate_item(self.config(), &item)?;
            pending.extend(dependencies(self.config(), &item)?);
            items.push(item);
            ensure!(
                items.len() <= super::super::repair::MAX_RECORDS,
                "Certified repair closure exceeds bound"
            );
        }
        Ok((!items.is_empty()).then_some(items))
    }
}
fn dependencies(config: &Configuration, item: &Item) -> Result<Vec<Reference>> {
    Ok(match item.reference.kind {
        12 => vec![reference(14, Certificate::parse(config, &item.bytes)?.node)],
        14 => {
            let node = Node::parse(config, &item.bytes)?;
            let mut result = Vec::new();
            if let Some(parent) = node.parent {
                result.push(reference(14, parent));
            }
            if let Some(justify) = node.justify {
                result.push(reference(12, justify));
            }
            if let Some(command) = node.command {
                result.push(reference(22, command));
            }
            result
        }
        22 => Vec::new(),
        _ => anyhow::bail!("Unsupported dependency kind"),
    })
}
