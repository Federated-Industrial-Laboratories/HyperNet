// SPDX-License-Identifier: MIT
//! Two transport lanes share one finite mailbox; recovery cannot queue behind stale gossip.
use super::peer;
use crate::trust_wire;
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
    time::Instant,
};

pub(super) const MAX_COUNT: usize = 128;
pub(super) const MAX_BYTES: usize = 4 * 1024 * 1024;
const GENERAL_COUNT: usize = MAX_COUNT - 16;
const GENERAL_BYTES: usize = MAX_BYTES - 2 * 1024 * 1024;
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Lane {
    General,
    Recovery,
}
impl Lane {
    fn index(self) -> usize {
        match self {
            Self::General => 0,
            Self::Recovery => 1,
        }
    }
}
#[derive(Clone, Copy)]
pub(super) enum Class {
    Broadcast { recovery: bool },
    Submission([u8; 32]),
    Request { family: u8, token: [u8; 32] },
    Response { family: u8 },
    Transient,
    Fresh,
}
impl Class {
    fn lane(self) -> Lane {
        match self {
            Self::Broadcast { recovery: true } | Self::Request { .. } | Self::Response { .. } => {
                Lane::Recovery
            }
            _ => Lane::General,
        }
    }
    fn slot(self) -> Option<(u8, u8)> {
        match self {
            Self::Request { family, .. } => Some((0, family)),
            Self::Response { family } => Some((1, family)),
            _ => None,
        }
    }
    fn expiry(self, now: Instant) -> Option<Instant> {
        match self {
            Self::Request { .. } | Self::Response { .. } | Self::Fresh => {
                now.checked_add(peer::HTTP_TIMEOUT)
            }
            _ => None,
        }
    }
}
struct Entry {
    body: Vec<u8>,
    class: Class,
    expires: Option<Instant>,
}
#[derive(Default)]
struct Queue {
    order: [VecDeque<[u8; 32]>; 2],
    messages: BTreeMap<[u8; 32], Entry>,
    bytes: usize,
    general_bytes: usize,
}
impl Queue {
    fn remove(&mut self, id: &[u8; 32]) -> Option<Vec<u8>> {
        let entry = self.messages.remove(id)?;
        let lane = entry.class.lane();
        self.order[lane.index()].retain(|old| old != id);
        self.bytes -= entry.body.len();
        if lane == Lane::General {
            self.general_bytes -= entry.body.len();
        }
        Some(entry.body)
    }
    fn expire(&mut self, now: Instant) {
        let ids: Vec<_> = self
            .messages
            .iter()
            .filter(|(_, e)| e.expires.is_some_and(|t| t <= now))
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.remove(&id);
        }
    }
    fn pop(&mut self, lane: Lane, now: Instant) -> Option<Vec<u8>> {
        self.expire(now);
        let id = *self.order[lane.index()].front()?;
        self.remove(&id)
    }
}
#[derive(Clone)]
pub(super) struct Mailbox {
    queue: Arc<Mutex<Queue>>,
    notify: Arc<[tokio::sync::Notify; 2]>,
}
impl Mailbox {
    pub(super) fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(Queue::default())),
            notify: Arc::new(std::array::from_fn(|_| tokio::sync::Notify::new())),
        }
    }
    #[cfg(test)]
    pub(super) fn push(&self, body: Vec<u8>) -> Result<()> {
        self.push_class(body, Class::Transient)
    }
    pub(super) fn push_class(&self, body: Vec<u8>, class: Class) -> Result<()> {
        self.push_at(body, class, Instant::now())
    }
    fn push_at(&self, body: Vec<u8>, class: Class, now: Instant) -> Result<()> {
        ensure!(
            body.len() <= trust_wire::MAXIMUM,
            "Outbound message exceeds bound"
        );
        let id = trust_wire::digest(&body);
        let lane = class.lane();
        let mut q = self
            .queue
            .lock()
            .map_err(|_| anyhow::anyhow!("Peer mailbox failed"))?;
        q.expire(now);
        if let Some(old) = q.messages.get_mut(&id) {
            old.expires = old.class.expiry(now);
            return Ok(());
        }
        if let Some(slot) = class.slot() {
            let replace: Vec<_> = q
                .messages
                .iter()
                .filter(|(_, e)| e.class.slot() == Some(slot))
                .map(|(id, _)| *id)
                .collect();
            for id in replace {
                q.remove(&id);
            }
        }
        ensure!(
            q.messages.len() < MAX_COUNT && q.bytes + body.len() <= MAX_BYTES,
            "Peer mailbox aggregate capacity exhausted"
        );
        if lane == Lane::General {
            ensure!(
                q.order[0].len() < GENERAL_COUNT && q.general_bytes + body.len() <= GENERAL_BYTES,
                "Peer gossip allocation exhausted"
            );
            q.general_bytes += body.len();
        }
        q.bytes += body.len();
        q.order[lane.index()].push_back(id);
        q.messages.insert(
            id,
            Entry {
                body,
                class,
                expires: class.expiry(now),
            },
        );
        drop(q);
        self.notify[lane.index()].notify_one();
        Ok(())
    }
    pub(super) fn retain_live(
        &self,
        broadcasts: &BTreeSet<[u8; 32]>,
        submissions: &BTreeSet<[u8; 32]>,
        requests: &BTreeSet<[u8; 32]>,
    ) -> Result<()> {
        let mut q = self
            .queue
            .lock()
            .map_err(|_| anyhow::anyhow!("Peer mailbox failed"))?;
        q.expire(Instant::now());
        let remove: Vec<_> = q
            .messages
            .iter()
            .filter(|(id, e)| match e.class {
                Class::Broadcast { .. } => !broadcasts.contains(*id),
                Class::Submission(digest) => !submissions.contains(&digest),
                Class::Request { token, .. } => !requests.contains(&token),
                Class::Response { .. } | Class::Transient | Class::Fresh => false,
            })
            .map(|(id, _)| *id)
            .collect();
        for id in remove {
            q.remove(&id);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn try_pop(&self) -> Result<Option<Vec<u8>>> {
        let mut q = self
            .queue
            .lock()
            .map_err(|_| anyhow::anyhow!("Peer mailbox failed"))?;
        let now = Instant::now();
        Ok(q.pop(Lane::Recovery, now)
            .or_else(|| q.pop(Lane::General, now)))
    }
    pub(super) async fn pop(&self, lane: Lane) -> Result<Vec<u8>> {
        loop {
            let notified = self.notify[lane.index()].notified();
            let body = self
                .queue
                .lock()
                .map_err(|_| anyhow::anyhow!("Peer mailbox failed"))?
                .pop(lane, Instant::now());
            if let Some(body) = body {
                return Ok(body);
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[tokio::test]
    async fn offline_backlog_is_pruned_and_recovery_uses_its_own_wakeup() {
        let q = Mailbox::new();
        for serial in 0..GENERAL_COUNT {
            q.push_class(
                (serial as u64).to_be_bytes().to_vec(),
                Class::Broadcast { recovery: false },
            )
            .unwrap();
        }
        assert!(q.push(vec![200; 16]).is_err());
        // A stalled general request does not hold the recovery sender's queue.
        let general = q.pop(Lane::General).await.unwrap();
        assert_eq!(general, 0u64.to_be_bytes());
        let recovery_wait = q.pop(Lane::Recovery);
        tokio::pin!(recovery_wait);
        assert!(
            tokio::time::timeout(Duration::from_millis(5), &mut recovery_wait)
                .await
                .is_err()
        );
        let proof = vec![250; 64];
        q.push_class(proof.clone(), Class::Broadcast { recovery: true })
            .unwrap();
        let live = BTreeSet::from([trust_wire::digest(&proof)]);
        q.retain_live(&live, &BTreeSet::new(), &BTreeSet::new())
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), recovery_wait)
                .await
                .unwrap()
                .unwrap(),
            proof
        );
        assert!(q.try_pop().unwrap().is_none());
    }
    #[test]
    fn slots_and_expiry_preserve_distinct_requested_response_families() {
        let q = Mailbox::new();
        let now = Instant::now();
        for family in [6, 14, 16] {
            q.push_at(vec![family; 16], Class::Response { family }, now)
                .unwrap();
        }
        q.push_at(vec![17; 16], Class::Response { family: 16 }, now)
            .unwrap();
        let mut inner = q.queue.lock().unwrap();
        assert_eq!(inner.messages.len(), 3);
        assert_eq!(inner.pop(Lane::Recovery, now).unwrap(), vec![6; 16]);
        assert_eq!(inner.pop(Lane::Recovery, now).unwrap(), vec![14; 16]);
        assert!(
            inner
                .pop(Lane::Recovery, now + peer::HTTP_TIMEOUT)
                .is_none()
        );
        drop(inner);
        // Repeating the exact request regenerates the same response after expiry.
        q.push_at(
            vec![17; 16],
            Class::Response { family: 16 },
            now + peer::HTTP_TIMEOUT,
        )
        .unwrap();
        assert_eq!(q.try_pop().unwrap().unwrap(), vec![17; 16]);
        let token = [3; 32];
        q.push_class(vec![4; 16], Class::Request { family: 13, token })
            .unwrap();
        q.retain_live(&BTreeSet::new(), &BTreeSet::new(), &BTreeSet::new())
            .unwrap();
        assert!(q.try_pop().unwrap().is_none());
    }
    #[test]
    fn aggregate_byte_reservation_is_shared_across_lanes() {
        let q = Mailbox::new();
        for serial in 0..8 {
            q.push_class(vec![serial; trust_wire::MAXIMUM], Class::Transient)
                .unwrap();
        }
        assert!(q.push(vec![9; 1]).is_err());
        for serial in 8..16 {
            q.push_class(
                vec![serial; trust_wire::MAXIMUM],
                Class::Broadcast { recovery: true },
            )
            .unwrap();
        }
        assert!(
            q.push_class(vec![17; 1], Class::Broadcast { recovery: true })
                .is_err()
        );
        let inner = q.queue.lock().unwrap();
        assert_eq!(inner.bytes, MAX_BYTES);
        assert_eq!(inner.messages.len(), 16);
    }
}
