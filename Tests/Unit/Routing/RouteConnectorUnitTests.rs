// SPDX-License-Identifier: MIT
// Unit tests for RouteConnector.
use super::*;
use std::{
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
#[test]
fn private_route_operation_deadline_never_resets_session_budget() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_peer, _) = listener.accept().unwrap();
    let now = boot_time_ms().unwrap();
    let mut stream = Socket {
        opportunistic: false,
        socket,
        deadline: now + 60000,
        operation_deadline: Some(now),
        idle_deadline: now + 30000,
        idle_ms: 30000,
        remaining_bytes: 12345,
        cancelled: &|| false,
    };
    assert!(stream.check().is_err());
    stream.operation_deadline = Some(now + 5000);
    assert!(stream.check().unwrap() <= 5000);
    stream.operation_deadline = None;
    assert!(stream.check().unwrap() > 5000);
    assert_eq!(stream.deadline, now + 60000);
    assert_eq!(stream.idle_deadline, now + 30000);
    assert_eq!(stream.remaining_bytes, 12345);
}
#[test]
fn private_route_readiness_cannot_extend_original_socket_limits() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_peer, _) = listener.accept().unwrap();
    let mut stream = Socket {
        opportunistic: false,
        socket,
        deadline: 5000,
        operation_deadline: None,
        idle_deadline: 4800,
        idle_ms: 1000,
        remaining_bytes: 12000,
        cancelled: &|| false,
    };
    let limits = crate::route_profile::Limits {
        bytes: 16384,
        duration_ms: 1000,
        idle_ms: 800,
    };
    stream.admitted(limits, 4500);
    assert_eq!(stream.deadline, 5000);
    assert_eq!(stream.idle_deadline, 4800);
    assert_eq!(stream.remaining_bytes, 12000);
    assert_eq!(stream.idle_ms, 800);
    // A stricter remaining allowance starts at readiness, not at the original connection start.
    stream.deadline = 9000;
    stream.idle_deadline = 9000;
    stream.remaining_bytes = 65536;
    stream.admitted(limits, 4500);
    assert_eq!(stream.deadline, 5500);
    assert_eq!(stream.idle_deadline, 5300);
    assert_eq!(stream.remaining_bytes, 16384);
}
#[test]
fn private_route_cancellation_does_not_retry_as_interrupted_io() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_peer, _) = listener.accept().unwrap();
    socket.set_nonblocking(true).unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    let task = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        signal.store(true, Ordering::Release);
    });
    let check = || cancelled.load(Ordering::Acquire);
    let start = boot_time_ms().unwrap();
    let mut stream = Socket {
        opportunistic: false,
        socket,
        deadline: start + 5000,
        operation_deadline: None,
        idle_deadline: start + 5000,
        idle_ms: 5000,
        remaining_bytes: 1024,
        cancelled: &check,
    };
    let error = stream.read_exact(&mut [0; 1]).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert!(boot_time_ms().unwrap() - start < 1000);
    task.join().unwrap();
}
#[test]
fn private_route_drip_traffic_cannot_extend_original_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut peer, _) = listener.accept().unwrap();
    socket.set_nonblocking(true).unwrap();
    let task = std::thread::spawn(move || {
        for _ in 0..20 {
            if peer.write_all(&[1]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    let start = boot_time_ms().unwrap();
    let mut stream = Socket {
        opportunistic: false,
        socket,
        deadline: start + 75,
        operation_deadline: None,
        idle_deadline: start + 1000,
        idle_ms: 1000,
        remaining_bytes: 1024,
        cancelled: &|| false,
    };
    let error = stream.read_exact(&mut [0; 20]).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(boot_time_ms().unwrap() - start < 1000);
    drop(stream);
    task.join().unwrap();
}
