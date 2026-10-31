// SPDX-License-Identifier: MIT
// Duplex streams share activity, retain bounded backpressure and drain the opposite half after EOF.
use super::*;
use std::pin::Pin;
use tokio::sync::watch;
struct ActivityClock(watch::Sender<u64>);
impl ActivityClock {
    fn touch(&self) -> Result<()> {
        self.0
            .send_replace(crate::authority_challenge::boot_time_ms()?);
        Ok(())
    }
    fn deadline(&self, absolute: u64, idle_ms: u64) -> u64 {
        absolute.min(self.0.borrow().saturating_add(idle_ms))
    }
}
async fn direction<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    bytes: &AtomicU64,
    gate: &Gate,
    deadline: u64,
    idle_ms: u64,
    activity: &ActivityClock,
) -> Result<()> {
    let mut buffer = [0; 8192];
    let mut changes = activity.0.subscribe();
    loop {
        changes.borrow_and_update();
        let wait =
            crate::authority_local_transport::remaining(activity.deadline(deadline, idle_ms))?;
        let count = tokio::select! {
            count = tokio::time::timeout(Duration::from_millis(wait), reader.read(&mut buffer)) => count??,
            changed = changes.changed() => { changed?; continue; },
        };
        if count == 0 {
            // TLS close-notify and Unix SHUT_WR preserve the receiver's remaining response.
            let _demand = gate.activity()?;
            return permitted(gate, activity.deadline(deadline, idle_ms), |cx| {
                Pin::new(&mut *writer).poll_shutdown(cx)
            })
            .await;
        }
        ensure!(
            bytes
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n
                    .checked_sub(count as u64))
                .is_ok(),
            "route byte admission exhausted"
        );
        // Buffered bytes retain renewal demand through partial writes and flush.
        // End it before the next read so idle streams do not renew permission.
        let _demand = gate.activity()?;
        activity.touch()?;
        let mut pending = &buffer[..count];
        while !pending.is_empty() {
            changes.borrow_and_update();
            let write = permitted(gate, activity.deadline(deadline, idle_ms), |cx| {
                Pin::new(&mut *writer).poll_write(cx, pending)
            });
            let written = tokio::select! {
                result = write => result?,
                changed = changes.changed() => { changed?; continue; },
            };
            ensure!(written > 0, "route write closed");
            pending = &pending[written..];
            activity.touch()?;
        }
        permitted(gate, activity.deadline(deadline, idle_ms), |cx| {
            Pin::new(&mut *writer).poll_flush(cx)
        })
        .await?;
    }
}
pub(super) async fn forward<
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
>(
    left: A,
    right: B,
    limits: Limits,
    gate: Gate,
    deadline: u64,
) -> Result<()> {
    ensure!(
        limits.bytes > 0
            && limits.bytes <= 1024 * 1024 * 1024
            && limits.duration_ms > 0
            && limits.duration_ms <= 3600000
            && limits.idle_ms > 0
            && limits.idle_ms <= 3600000,
        "remaining stream allowance exceeds admitted bounds"
    );
    let bytes = AtomicU64::new(limits.bytes);
    let activity = ActivityClock(watch::channel(crate::authority_challenge::boot_time_ms()?).0);
    let (mut lr, mut lw) = tokio::io::split(left);
    let (mut rr, mut rw) = tokio::io::split(right);
    let remaining = crate::authority_local_transport::remaining(deadline)?;
    tokio::time::timeout(Duration::from_millis(remaining),async {
        tokio::select! {
            result=async {tokio::try_join!(direction(&mut lr,&mut rw,&bytes,&gate,deadline,limits.idle_ms,&activity),direction(&mut rr,&mut lw,&bytes,&gate,deadline,limits.idle_ms,&activity))?;Ok(())}=>result,
            _=gate.closed()=>anyhow::bail!("route permission closed"),
        }
    }).await?
}
#[cfg(test)]
#[path = "../../Tests/Unit/Routing/RouteDuplexUnitTests.rs"]
mod tests;
