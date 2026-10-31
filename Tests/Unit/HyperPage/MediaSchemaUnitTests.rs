// SPDX-License-Identifier: MIT
// Unit tests for MediaSchema.
use super::*;
fn sample() -> Vector {
    Vector {
        profile: VECTOR_PROFILE.into(),
        width: 32,
        height: 16,
        background: [255; 3],
        paths: vec![VectorPath {
            commands: vec![
                PathCommand::Move { x: 0, y: 0 },
                PathCommand::Line { x: 1024, y: 1024 },
                PathCommand::Close,
            ],
            fill: Some([255, 0, 0, 255]),
            stroke: None,
            fill_rule: FillRule::NonZero,
        }],
    }
}
#[test]
fn canonical_geometry_is_bounded_and_self_contained() {
    let value = sample();
    let bytes = serde_json::to_vec(&value).unwrap();
    assert_eq!(vector(&bytes).unwrap(), value);
    let mut bad = value.clone();
    bad.paths[0].commands.push(PathCommand::Line { x: 0, y: 0 });
    assert!(validate_vector(&bad).is_err());
    bad = value.clone();
    bad.paths[0].commands[1] = PathCommand::Line { x: i32::MIN, y: 0 };
    assert!(validate_vector(&bad).is_err());
    bad = value.clone();
    bad.paths[0].commands = vec![PathCommand::Move { x: 0, y: 0 }; 2049];
    assert!(validate_vector(&bad).is_err());
    let source = String::from_utf8(bytes).unwrap();
    for source in [
        source.replace("\"width\":32", "\"width\":32,\"width\":32"),
        source.replace(
            "\"width\":32",
            "\"width\":32,\"href\":\"https://example.com/\"",
        ),
        format!(" {source}"),
    ] {
        assert!(vector(source.as_bytes()).is_err());
    }
    let svg = vector_svg(&value).unwrap();
    assert!(svg.contains("viewBox=\"0 0 32768 16384\""));
    assert!(!svg.contains("href="));
}
#[test]
fn media_manifest_binds_profile_dimensions_bytes_and_hosts() {
    let data = serde_json::to_vec(&sample()).unwrap();
    let mut asset = Asset {
        id: "Icon".into(),
        profile: VECTOR_PROFILE.into(),
        width: 32,
        height: 16,
        bytes: data.len() as u64,
        digest: hex::encode(Sha256::digest(&data)),
        hosts: vec!["01".repeat(32)],
        copies: 1,
    };
    validate_asset_bytes(&asset, &data).unwrap();
    asset.width = 33;
    assert!(validate_asset_bytes(&asset, &data).is_err());
    asset.width = 32;
    asset.hosts.push(asset.hosts[0].clone());
    assert!(validate_asset_bytes(&asset, &data).is_err());
    assert!(validate_assets(&vec![asset; 9]).is_err());
}
