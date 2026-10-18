// SPDX-License-Identifier: MIT
// Clock suspension drains ingress and resumes only after a fresh check within unchanged consent.
use super::*;
use crate::consensus_clock::{Moment, ObservationExpired, Witness};
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn private_route_clock_shutdown_drains_nested_parser_and_queued_sockets() {
    struct Running(Arc<AtomicUsize>);
    impl Drop for Running {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let running = Arc::new(AtomicUsize::new(0));
    let observed = running.clone();
    let (entered, mut arrivals) = mpsc::channel(2);
    let mut queue = listen(listener, 2, 30000, None, move |mut socket| {
        let observed = observed.clone();
        let entered = entered.clone();
        async move {
            observed.fetch_add(1, Ordering::SeqCst);
            let _running = Running(observed);
            let byte = socket.read_u8().await?;
            entered.send(()).await.unwrap();
            if byte == 0 {
                return Ok(socket);
            }
            std::future::pending::<()>().await;
            Ok(socket)
        }
    });
    let mut queued = TcpStream::connect(address).await.unwrap();
    queued.write_u8(0).await.unwrap();
    arrivals.recv().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while queue.requests.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut parsing = TcpStream::connect(address).await.unwrap();
    parsing.write_u8(1).await.unwrap();
    arrivals.recv().await.unwrap();
    assert_eq!(running.load(Ordering::SeqCst), 1);
    tokio::time::timeout(Duration::from_secs(1), queue.shutdown())
        .await
        .unwrap();
    assert_eq!(running.load(Ordering::SeqCst), 0);
    assert!(queue.tasks.is_empty() && queue.requests.is_empty() && queue.attachments.is_empty());
    assert_eq!(
        queued.read_u8().await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    assert_eq!(
        parsing.read_u8().await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    let replacement = TcpListener::bind(address).await.unwrap();
    drop(replacement);
}

#[tokio::test]
async fn private_route_clock_recovers_only_after_fresh_observation() {
    let boot = "12345678-1234-1234-1234-123456789abc";
    let old = Witness {
        version: 1,
        kernel_boot: boot.into(),
        sample_wall_ms: 10000,
        sample_boot_ms: 2000,
        valid_until_boot_ms: 3000,
        maximum_error_ms: 20,
        source: "162.159.200.1".parse().unwrap(),
    };
    let fresh = Witness {
        sample_wall_ms: 11000,
        sample_boot_ms: 3000,
        valid_until_boot_ms: 4000,
        ..old.clone()
    };
    let mut checks = 0;
    assert!(
        wait_for_clock(
            || {
                checks += 1;
                let selected = if checks == 1 { &old } else { &fresh };
                selected.health(
                    boot,
                    Moment {
                        wall_ms: 11000,
                        boot_ms: 3000,
                    },
                )?;
                Ok(())
            },
            std::future::pending()
        )
        .await
        .unwrap()
    );
    assert_eq!(checks, 2);
}

#[tokio::test]
async fn private_route_clock_suspension_preserves_terminal_checks_and_shutdown() {
    for reason in [
        "original consent expired",
        "withdrawn",
        "generation changed",
        "activation changed",
        "configuration changed",
        "invalid journal",
    ] {
        let mut checks = 0;
        let error = wait_for_clock(
            || {
                checks += 1;
                if checks == 1 {
                    return Err(ObservationExpired.into());
                }
                anyhow::bail!(reason);
            },
            std::future::pending(),
        )
        .await
        .unwrap_err();
        assert_eq!(checks, 2);
        assert_eq!(error.to_string(), reason);
    }
    assert!(
        !wait_for_clock(|| Err(ObservationExpired.into()), std::future::ready(()))
            .await
            .unwrap()
    );
    assert!(clock_checked::<()>(Err(ObservationExpired.into())).is_err());
    assert!(
        clock_checked::<()>(Err(anyhow::anyhow!("connection refused")))
            .unwrap()
            .is_err()
    );
}

#[test]
fn private_route_fresh_read_retry_requires_typed_read_transport_failure() {
    use crate::authority_local_transport::{FreshReadUnavailable, HistoryOvertaken};
    for (error, reason) in [
        (
            anyhow::Error::new(FreshReadUnavailable),
            ReadRetry::FreshQuorumUnavailable,
        ),
        (
            anyhow::Error::new(HistoryOvertaken),
            ReadRetry::HistoryOvertaken,
        ),
    ] {
        let error = Client::retry_read(error.context("read transport"));
        assert_eq!(error.downcast_ref::<ReadRetry>(), Some(&reason));
        let propagated = clock_checked::<()>(Err(error)).unwrap_err();
        assert!(propagated.is::<ReadRetry>());
        assert!(propagated.is::<FreshReadUnavailable>() || propagated.is::<HistoryOvertaken>());
    }
    // An ordinary effect with the same underlying failure cannot acquire read retry authority.
    for error in [
        anyhow::Error::new(FreshReadUnavailable),
        anyhow::Error::new(HistoryOvertaken),
    ] {
        assert!(clock_checked::<()>(Err(error)).unwrap().is_err());
    }
    for error in [
        anyhow::anyhow!("fresh authority quorum is unavailable within the original challenge"),
        anyhow::anyhow!("malformed authority response"),
        anyhow::anyhow!("invalid quorum proof"),
        anyhow::anyhow!("Route maintenance refused with code 1"),
        std::io::Error::from(std::io::ErrorKind::TimedOut).into(),
        std::io::Error::from(std::io::ErrorKind::PermissionDenied).into(),
    ] {
        let error = Client::retry_read(error);
        assert!(!error.is::<ReadRetry>());
        assert!(clock_checked::<()>(Err(error)).unwrap().is_err());
    }
}

#[test]
fn private_route_terminal_diagnostics_exclude_private_error_text() {
    for (message, expected) in [
        ("private control read closed", FailureCode::LocalReadClosed),
        (
            "private control write closed",
            FailureCode::LocalWriteClosed,
        ),
        (
            "private control readiness failed or timed out",
            FailureCode::LocalReadiness,
        ),
        (
            "original inspection deadline expired",
            FailureCode::InspectionDeadline,
        ),
        (
            "unknown private field: confidential-page",
            FailureCode::Other,
        ),
    ] {
        let error = anyhow::anyhow!(message).context("obtain fresh Route context and history");
        assert_eq!(failure_code(&error), expected);
        assert!(!format!("{:?}", failure_code(&error)).contains(message));
        assert!(!Client::retry_read(error).is::<ReadRetry>());
    }
}

#[tokio::test]
async fn private_route_fresh_read_backoff_rechecks_consent_and_allows_shutdown() {
    let delay = Duration::from_millis(20);
    let started = tokio::time::Instant::now();
    let mut checks = 0;
    assert!(
        wait_for_retry(
            || {
                checks += 1;
                Ok(())
            },
            std::future::pending(),
            delay,
        )
        .await
        .unwrap()
    );
    assert!(started.elapsed() >= delay);
    assert!(checks >= 2);
    for reason in [
        "original consent expired",
        "withdrawn",
        "generation changed",
        "activation changed",
        "configuration changed",
        "invalid journal",
    ] {
        let mut checks = 0;
        let error = wait_for_retry(
            || {
                checks += 1;
                if checks == 1 {
                    return Ok(());
                }
                anyhow::bail!(reason);
            },
            std::future::pending(),
            Duration::from_millis(READ_RETRY_MS),
        )
        .await
        .unwrap_err();
        assert_eq!(checks, 2);
        assert_eq!(error.to_string(), reason);
    }
    assert!(
        !wait_for_retry(
            || Ok(()),
            std::future::ready(()),
            Duration::from_millis(READ_RETRY_MS),
        )
        .await
        .unwrap()
    );
    let mut checks = 0;
    assert!(
        wait_for_retry(
            || {
                checks += 1;
                if checks == 1 {
                    return Err(ObservationExpired.into());
                }
                Ok(())
            },
            std::future::pending(),
            delay,
        )
        .await
        .unwrap()
    );
    assert_eq!(checks, 2);
}
