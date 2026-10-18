// SPDX-License-Identifier: MIT
// Search metadata is bounded inert text included in exact-source review.
use super::*;

fn page(attributes: &str) -> String {
    format!("{PROFILE}\n# Catalogue\n@Tags {attributes}\n: Approved text.\n")
}

#[test]
fn tags_are_inert_reviewed_metadata_and_preserve_the_document_tree() {
    let source = page(r#"{"values":["Books","Tea, coffee","café"]}"#);
    let document = parse(&source).unwrap();
    assert_eq!(document.tags, ["Books", "Tea, coffee", "café"]);
    assert_eq!(document.nodes.len(), 1);
    assert!(document.links.is_empty() && document.forms.is_empty());
    assert_eq!(
        document.lines[1],
        r#"[ Tags: ["Books","Tea, coffee","café"] ]"#
    );
    assert_eq!(
        serde_json::to_value(&document).unwrap()["tags"],
        serde_json::json!(["Books", "Tea, coffee", "café"])
    );
    assert!(
        parse(&format!("{PROFILE}\n# Catalogue\n: Text.\n"))
            .unwrap()
            .tags
            .is_empty()
    );
}

#[test]
fn tags_refuse_ambiguous_structure_controls_and_excess_resources() {
    for attributes in [
        r#"{"values":[]}"#,
        r#"{"values":null}"#,
        r#"{"values":["Books"],"other":true}"#,
        r#"{"values":["Books"],"values":["Tea"]}"#,
        r#"{"values":["Books","Books"]}"#,
        r#"{"values":[""]}"#,
        r#"{"values":[" Books"]}"#,
        r#"{"values":["Books "]}"#,
        r#"{"values":["\u001b[31m"]}"#,
        r#"{"values":["\u202eBooks"]}"#,
        r#"{"values":["Books\nTea"]}"#,
    ] {
        assert!(parse(&page(attributes)).is_err(), "{attributes}");
    }
    for length in [64, 65] {
        let value = serde_json::json!({"values": ["x".repeat(length)]});
        assert_eq!(parse(&page(&value.to_string())).is_ok(), length == 64);
    }
    for count in [16, 17] {
        let values: Vec<_> = (0..count).map(|i| format!("Tag{i}")).collect();
        let value = serde_json::json!({"values": values});
        assert_eq!(parse(&page(&value.to_string())).is_ok(), count == 16);
    }
    for prefix in [
        ": Text.\n",
        "\n",
        "@Column {}\n",
        "@Tags {\"values\":[\"First\"]}\n",
    ] {
        let body = format!("{PROFILE}\n# Catalogue\n{prefix}@Tags {{\"values\":[\"Late\"]}}\n");
        assert!(parse(&body).is_err());
    }
}
