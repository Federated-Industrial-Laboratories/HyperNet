// SPDX-License-Identifier: MIT
// Unit tests for RouteAuthority.
use super::*;

#[test]
fn private_route_recurring_cost_replaces_outliers_and_excludes_other_actions() {
    let own = [3; 32];
    let lookup = DomainCommand::Route(routes::Command::Lookup { service: own });
    let voucher = DomainCommand::Route(routes::Command::VoucherContext {
        voucher: VersionRef {
            kind: 166,
            id: [4; 32],
            generation: 1,
            digest: [5; 32],
        },
    });
    let unrelated = DomainCommand::Route(routes::Command::Lookup { service: [6; 32] });
    let mut costs = OperationCosts::default();
    costs.observe(&lookup, own, 1800);
    costs.observe(&voucher, own, 1700);
    costs.observe(&unrelated, own, 4500);
    assert_eq!(costs.own_ms, Some(1800));
    assert_eq!(costs.voucher_ms(), 1700);
    assert_eq!(costs.action_ms, 4500);
    costs.observe(&lookup, own, 650);
    costs.observe(&voucher, own, 700);
    assert_eq!(costs.own_ms, Some(650));
    assert_eq!(costs.voucher_ms(), 700);
    assert_eq!(costs.action_ms, 700);
}
