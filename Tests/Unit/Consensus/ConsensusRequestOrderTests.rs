// SPDX-License-Identifier: MIT
// Pending proposal selection preserves admission order under duplicate and lower-digest traffic.
use super::*;

fn submission(command: Vec<u8>) -> Submission {
    Submission {
        command,
        inputs: Resolved::default(),
    }
}

#[test]
fn oldest_eligible_request_precedes_later_lower_digests_and_duplicate_submissions() {
    let (configuration, keys) = fixture();
    let (_directories, mut engines) = fixtures::engines(&configuration, &keys);
    fixtures::enter(&configuration, &keys, &mut engines, 1);
    let directory = Directory::new();
    let (_, now) = runtime_clock(&directory.0);
    let mut driver = repair_driver(
        engines.remove(0),
        &directory.0,
        &keys,
        configuration.voters[1],
        ingress::Mailbox::new(),
    );
    let future = current_request(&configuration, 70, now + 60000);
    let future_digest = driver.remember_request(submission(future)).unwrap();
    let mut commands = (71..=78)
        .map(|n| current_request(&configuration, n, now))
        .collect::<Vec<_>>();
    commands.sort_by_key(|command| wire::digest(command));
    let oldest = commands.pop().unwrap();
    let oldest_digest = driver.remember_request(submission(oldest.clone())).unwrap();
    for later in commands {
        assert!(wire::digest(&later) < oldest_digest);
        driver.remember_request(submission(later)).unwrap();
    }
    let admitted = driver.request_order.clone();
    // The real submit path deduplicates before performing another clock or input lookup.
    assert_eq!(driver.submit(submission(oldest)).unwrap(), oldest_digest);
    assert_eq!(driver.request_order, admitted);
    assert_eq!(driver.request_order[0], future_digest);
    assert_eq!(driver.request_order[1], oldest_digest);
    let (clock, _) = runtime_clock(&directory.0);
    driver.config.clock = crate::authority_clock_handoff::Source::Private { path: clock };
    driver.try_propose().unwrap();
    let (body, _) = wire::envelope(driver.engine.current_proposal().unwrap(), 1).unwrap();
    assert_eq!(
        Node::parse(&configuration, &body).unwrap().command,
        Some(oldest_digest)
    );
}

#[test]
fn pending_order_capacity_and_expiry_remove_every_queue_entry() {
    let (configuration, keys) = fixture();
    let (_directories, mut engines) = fixtures::engines(&configuration, &keys);
    let directory = Directory::new();
    let (_, now) = runtime_clock(&directory.0);
    let mut driver = repair_driver(
        engines.remove(0),
        &directory.0,
        &keys,
        configuration.voters[1],
        ingress::Mailbox::new(),
    );
    let expired = (1..=MAX_PENDING as u8)
        .map(|n| current_request(&configuration, n, now - 11000))
        .collect::<Vec<_>>();
    for command in &expired {
        driver
            .remember_request(submission(command.clone()))
            .unwrap();
    }
    let extra = current_request(&configuration, 100, now - 11000);
    assert!(driver.remember_request(submission(extra.clone())).is_err());
    let original = driver.request_order.clone();
    driver
        .remember_request(submission(expired[0].clone()))
        .unwrap();
    assert_eq!(driver.request_order, original);
    driver.remove_request(&wire::digest(&expired[0]));
    assert_eq!(driver.request_order.len(), MAX_PENDING - 1);
    driver.remember_request(submission(extra)).unwrap();
    assert_eq!(driver.request_order.len(), MAX_PENDING);
    let (clock, _) = runtime_clock(&directory.0);
    driver.config.clock = crate::authority_clock_handoff::Source::Private { path: clock };
    driver.tick().unwrap();
    assert!(driver.requests.is_empty());
    assert!(driver.request_order.is_empty());
    let fresh = driver
        .remember_request(submission(current_request(&configuration, 101, now)))
        .unwrap();
    assert_eq!(driver.request_order, VecDeque::from([fresh]));
}
