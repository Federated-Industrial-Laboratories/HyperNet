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
#[path = "../../Tests/Unit/Consensus/ConsensusQueueUnitTests.rs"]
mod tests;

#[cfg(test)]
include!("../../Tests/Support/Consensus/ConsensusQueue.rs");
