// SPDX-License-Identifier: MIT
// Unit tests for ConsensusIngress.
use super::*;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::test]
async fn peer_connection_reuses_identity_without_extending_its_lifetime() {
    let (server, client) = tokio::io::duplex(4096);
    let (events, mut received) = mpsc::channel(2);
    let key = [7; 32];
    let serving =
        tokio::spawn(
            async move { timeout(peer::HTTP_TIMEOUT, serve_peer(server, key, events)).await },
        );
    let replies = tokio::spawn(async move {
        for expected in [b"ab", b"cd"] {
            let Event::Peer {
                sender,
                body,
                answer,
                ..
            } = received.recv().await.unwrap()
            else {
                panic!("Peer request required");
            };
            assert_eq!(sender, key);
            assert_eq!(body, expected);
            answer.send(body).unwrap();
        }
    });
    let mut client = BufReader::new(client);
    for body in [b"ab", b"cd"] {
        client.write_all(b"POST /V1/Peer HTTP/1.1\r\nHost: peer\r\nContent-Type: application/cbor\r\nContent-Length: 2\r\n\r\n").await.unwrap();
        client.write_all(body).await.unwrap();
        let mut line = String::new();
        client.read_line(&mut line).await.unwrap();
        assert!(line.starts_with("HTTP/1.1 200 "));
        loop {
            line.clear();
            assert!(client.read_line(&mut line).await.unwrap() > 0);
            if line == "\r\n" {
                break;
            }
            assert!(!line.to_ascii_lowercase().starts_with("connection: close"));
        }
        let mut response = [0; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, body);
    }
    replies.await.unwrap();
    assert!(serving.await.unwrap().is_err());
    assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
}
