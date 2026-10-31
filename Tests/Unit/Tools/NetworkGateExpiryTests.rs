// SPDX-License-Identifier: MIT
// Unit tests for NetworkGate.
use super::*;

#[tokio::test(flavor = "current_thread")]
async fn absolute_expiry_closes_listener_and_established_streams() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    let config = Configuration {
        listen: address,
        destination: upstream.local_addr().unwrap(),
        allowed_source: address.ip(),
        bytes_per_second: 1048576,
        maximum_connections: 1,
        maximum_connection_bytes: 16384,
        expires: Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 2,
        ),
    };
    let relay = tokio::spawn(serve(config));
    let mut client = timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(client) = TcpStream::connect(address).await {
                break client;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let (mut remote, _) = upstream.accept().await.unwrap();
    client.write_all(b"x").await.unwrap();
    let mut byte = [0];
    remote.read_exact(&mut byte).await.unwrap();
    assert_eq!(&byte, b"x");
    let result = timeout(Duration::from_secs(3), relay)
        .await
        .unwrap()
        .unwrap();
    assert!(result.unwrap_err().to_string().contains("ConsentExpired"));
    assert_eq!(
        timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(
        timeout(Duration::from_secs(1), remote.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(TcpStream::connect(address).await.is_err());
}
