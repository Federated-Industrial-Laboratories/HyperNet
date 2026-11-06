// SPDX-License-Identifier: MIT
use super::*;

#[test]
fn preview_returns_only_complete_bounded_ipv4_reservations() {
    let inventory = vec![
        json!({"name":"not disclosed","labels":{"operator":"not disclosed"},"subnets":[
            {"subnet":"10.89.220.0/24"},{"subnet":"fd00::/64"},{"subnet":"10.88.0.0/16"},{"subnet":"10.89.220.0/24"}
        ]}),
    ];
    assert_eq!(
        ranges(&inventory).unwrap(),
        json!({"version":1,"complete":true,"ipv4Subnets":["10.88.0.0/16","10.89.220.0/24"]})
    );
    assert_eq!(
        ranges(&[]).unwrap(),
        json!({"version":1,"complete":true,"ipv4Subnets":[]})
    );
    assert_eq!(
        ranges(&[json!({"subnets":[{"subnet":"0.0.0.0/0"},{"subnet":"127.0.0.1/32"}]})]).unwrap()["ipv4Subnets"],
        json!(["0.0.0.0/0", "127.0.0.1/32"])
    );
}

#[test]
fn incomplete_or_invalid_inventory_never_reports_free_subnets() {
    for invalid in [
        json!({}),
        json!({"subnets":null}),
        json!({"subnets":{}}),
        json!({"subnets":[{}]}),
    ] {
        assert!(ranges(&[invalid]).is_err());
    }
    for cidr in [
        "garbage",
        "10.0.0.0",
        "10.0.0.0/33",
        "10.0.0.1/24",
        "fd00::/129",
        "fd00::1/64",
        "10.0.0.0/24/1",
    ] {
        assert!(
            ranges(&[json!({"subnets":[{"subnet":cidr}]})]).is_err(),
            "{cidr}"
        );
    }
    assert!(ranges(&vec![json!({"subnets":[]}); MAXIMUM + 1]).is_err());
    assert!(ranges(&[json!({"subnets":vec![json!({"subnet":"10.0.0.0/8"});MAXIMUM+1]})]).is_err());
}
