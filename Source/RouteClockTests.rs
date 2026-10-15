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
