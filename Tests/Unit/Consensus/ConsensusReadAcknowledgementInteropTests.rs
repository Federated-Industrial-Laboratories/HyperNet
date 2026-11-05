// SPDX-License-Identifier: MIT
// A bounded external Suite test consumes a real quorum result and releases its exact collection.
use super::*;
use std::io::{Read, Write};
use std::os::{fd::AsRawFd, unix::net::UnixListener};

#[test]
#[ignore = "requires the paired Suite acknowledgement integration fixture"]
fn consumed_read_collector_for_suite_interop() {
    let root = PathBuf::from(std::env::var_os("HYPERNET_READ_ACK_FIXTURE").unwrap());
    let parent = crate::authority_files::private_directory(&root).unwrap();
    let path = Path::new("/proc/self/fd")
        .join(parent.as_raw_fd().to_string())
        .join("Control.sock");
    let listener = UnixListener::bind(path).unwrap();
    std::fs::set_permissions(
        root.join("Control.sock"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    listener.set_nonblocking(true).unwrap();
    let now = crate::consensus_clock::moment().unwrap();
    let fixture = crate::authority_application::tests::Fixture::at(now.wall_ms - 1000);
    let configuration = fixture.configuration().clone();
    let (_, keys) = crate::consensus::records::tests::fixture();
    let directories = (0..4).map(|_| Directory::new()).collect::<Vec<_>>();
    let mailboxes = (0..4).map(|_| ingress::Mailbox::new()).collect::<Vec<_>>();
    let mut drivers = directories
        .iter()
        .zip(&keys)
        .map(|(directory, key)| {
            let engine = Engine::create(
                &directory.0,
                configuration.clone(),
                key.clone(),
                fixture.initial.clone(),
            )
            .unwrap();
            let mut driver = repair_driver(
                engine,
                &directory.0,
                &keys,
                configuration.voters[0],
                mailboxes[0].clone(),
            );
            driver.application = Arc::new(crate::authority_application::PolicyApplication::new(
                configuration.clone(),
            ));
            driver.config.clock = crate::authority_clock_handoff::Source::Private {
                path: runtime_clock(&directory.0).0,
            };
            driver
        })
        .collect::<Vec<_>>();
    drivers[0].senders = (1..4)
        .map(|index| (configuration.voters[index], mailboxes[index].clone()))
        .collect();
    std::fs::write(root.join("Bootstrap.cbor"), &fixture.bootstrap).unwrap();
    std::fs::write(root.join("Ready"), b"Ready").unwrap();
    let end = Instant::now() + Duration::from_secs(30);
    let mut completed = None;
    let mut released = false;
    for _ in 0..16 {
        let mut stream = loop {
            assert!(
                Instant::now() < end,
                "Suite integration did not finish within its bound"
            );
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(error) => panic!("collector accept failed: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut length = [0; 4];
        stream.read_exact(&mut length).unwrap();
        let length = u32::from_be_bytes(length) as usize;
        assert!((1..=wire::MAXIMUM).contains(&length));
        let mut packet = vec![0; length];
        stream.read_exact(&mut packet).unwrap();
        for directory in &directories {
            runtime_clock(&directory.0);
        }
        let value = wire::decode(&packet).unwrap();
        let fields = value.array(5).unwrap();
        let operation = fields[3].uint().unwrap();
        let mut reply = drivers[0].local_checked(&packet).unwrap();
        if operation == 6 {
            assert!(completed.is_none());
            let submitted = wire::decode(fields[4].bytes().unwrap()).unwrap();
            let submitted = submitted.array(2).unwrap();
            let id = read::read_id(submitted[0].bytes().unwrap(), submitted[1].bytes().unwrap())
                .unwrap();
            for index in 1..4 {
                let probe = mailboxes[index].try_pop().unwrap().unwrap();
                if index < 3 {
                    let message =
                        peer::decode(&configuration, configuration.voters[0], &probe).unwrap();
                    drivers[index]
                        .receive(configuration.voters[0], message)
                        .unwrap();
                    let share = mailboxes[0].try_pop().unwrap().unwrap();
                    let message =
                        peer::decode(&configuration, configuration.voters[index], &share).unwrap();
                    drivers[0]
                        .receive(configuration.voters[index], message)
                        .unwrap();
                }
            }
            reply = drivers[0].read_poll(id).unwrap();
            assert_eq!(
                wire::decode(&reply).unwrap().array(10).unwrap()[3],
                V::Uint(1)
            );
            assert_eq!(drivers[0].reads.len(), 1);
            completed = Some(id);
        } else if operation == 8 {
            assert!(!released);
            let id = completed.unwrap();
            let receipt = wire::decode(&reply).unwrap();
            let receipt = receipt.array(7).unwrap();
            assert_eq!(receipt[3].fixed::<32>().unwrap(), id);
            assert!(receipt[6].boolean().unwrap());
            assert!(!drivers[0].reads.contains_key(&id));
            assert!(drivers[0].reads.is_empty());
            released = true;
        }
        stream
            .write_all(&(reply.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&reply).unwrap();
        if operation == 7 && released {
            assert_eq!(fields[4].fixed::<32>().unwrap(), completed.unwrap());
            let reply = wire::decode(&reply).unwrap();
            let fields = reply.array(10).unwrap();
            assert_eq!(
                (fields[3].uint().unwrap(), fields[4].uint().unwrap()),
                (2, 1)
            );
            std::fs::write(
                root.join("Released"),
                b"exact completed collection removed; subsequent poll absent",
            )
            .unwrap();
            return;
        }
    }
    panic!("Suite integration exceeded its finite control frame count");
}
