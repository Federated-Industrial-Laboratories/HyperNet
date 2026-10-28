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
mod tests {
    use super::*;
    #[tokio::test]
    async fn quiet_request_half_survives_response_activity_and_half_close() {
        let (mut caller, left) = tokio::io::duplex(128);
        let (right, mut service) = tokio::io::duplex(128);
        let limits = Limits {
            bytes: 16384,
            duration_ms: 3000,
            idle_ms: 200,
        };
        let deadline = crate::authority_challenge::boot_time_ms().unwrap() + 3000;
        let task = tokio::spawn(forward(left, right, limits, Gate::new(deadline), deadline));
        caller.write_all(b"request").await.unwrap();
        let mut request = [0; 7];
        service.read_exact(&mut request).await.unwrap();
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(80)).await;
            service.write_all(b"a").await.unwrap();
            let mut b = [0];
            caller.read_exact(&mut b).await.unwrap();
        }
        caller.shutdown().await.unwrap();
        let mut end = [0];
        assert_eq!(service.read(&mut end).await.unwrap(), 0);
        service.write_all(b"tail").await.unwrap();
        service.shutdown().await.unwrap();
        let mut tail = Vec::new();
        caller.read_to_end(&mut tail).await.unwrap();
        assert_eq!(tail, b"tail");
        task.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn revoked_stream_ends_a_blocked_reader_and_writer() {
        let (mut caller, left) = tokio::io::duplex(16);
        let (right, _service) = tokio::io::duplex(16);
        let deadline = crate::authority_challenge::boot_time_ms().unwrap() + 3000;
        let gate = Gate::new(deadline);
        let task = tokio::spawn(forward(
            left,
            right,
            Limits {
                bytes: 16384,
                duration_ms: 3000,
                idle_ms: 1000,
            },
            gate.clone(),
            deadline,
        ));
        let producer = tokio::spawn(async move { caller.write_all(&[1; 16384]).await });
        tokio::task::yield_now().await;
        gate.close();
        assert!(
            tokio::time::timeout(Duration::from_millis(500), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(producer.await.unwrap().is_err());
    }
}
