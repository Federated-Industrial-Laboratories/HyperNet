// SPDX-License-Identifier: MIT
// Unit tests for Markup.
use super::*;
#[test]
fn grammar_vectors() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/Tests/MarkupVectors.json"
    )))
    .unwrap();
    for case in corpus.as_array().unwrap() {
        assert_eq!(
            validate(case["body"].as_str().unwrap()).is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}
#[test]
fn border_styles_retain_explicit_selection_and_inheritance() {
    for (name, expected) in [
        ("Light", BorderStyle::Light),
        ("Heavy", BorderStyle::Heavy),
        ("Double", BorderStyle::Double),
        ("Rounded", BorderStyle::Rounded),
        ("Ascii", BorderStyle::Ascii),
    ] {
        let body = format!(
            "{PROFILE}\n# Borders\n@Panel {{\"label\":\"Outer\",\"border\":\"{name}\"}}\n@ScrollBox {{\"id\":\"Guide\",\"label\":\"Guide\",\"rows\":3,\"border\":\"{name}\"}}\n: Text\n@End\n@End\n"
        );
        let document = parse(&body).unwrap();
        let panel = &document.nodes[0];
        assert_eq!(panel.style.border, Some(expected));
        assert_eq!(panel.children[0].style.border, Some(expected));
        assert_eq!(panel.children[0].children[0].style.border, None);
        assert_eq!(
            serde_json::to_value(panel.style).unwrap(),
            serde_json::json!({"colour": null, "bold": false, "border": name})
        );
    }
    let document = parse(concat!(
        "HyperNetPage/2\n# Borders\n",
        "@Panel {\"label\":\"Outer\",\"border\":\"Double\"}\n",
        "@Panel {\"label\":\"Inherited\"}\n",
        "@ScrollBox {\"id\":\"Guide\",\"label\":\"Guide\",\"rows\":3,\"border\":null}\n",
        "@Separator {}\n@Text {\"value\":\"Text\"}\n@End\n@End\n@End\n"
    ))
    .unwrap();
    let inherited = &document.nodes[0].children[0];
    assert_eq!(inherited.style.border, None);
    assert_eq!(inherited.children[0].style.border, None);
    for node in &inherited.children[0].children {
        assert_eq!(node.style.border, None);
    }
    assert_eq!(
        serde_json::to_string(&Style::default()).unwrap(),
        "{\"colour\":null,\"bold\":false,\"border\":null}"
    );
}
#[test]
fn bounds_and_profile_are_enforced() {
    assert!(
        validate(&format!(
            "{PROFILE}\n# Title\n: x{}\n",
            "\u{0301}".repeat(16)
        ))
        .is_err()
    );
    assert!(validate(&format!("{PROFILE}\n# Title\n{}", ": text\n".repeat(257))).is_err());
    assert!(validate(&format!("{PROFILE}\n# Title\n: {}\n", "x".repeat(1023))).is_err());
    assert!(
        validate(&format!(
            "{PROFILE}\n# Title\n{}: Text\n{}",
            "@Column {}\n".repeat(8),
            "@End\n".repeat(8)
        ))
        .is_err()
    );
    assert!(validate_profile("HyperNetPage/1", &format!("{PROFILE}\n# Title\n")).is_err());
}
#[test]
fn form_span_and_plain_review_bind_every_declared_semantic() {
    let form = format!(
        "@Form {{\"id\":\"Feedback\",\"label\":\"Feedback\",\"profile\":\"HyperNetFormMail/1\",\"recipient\":\"{}\",\"owner\":\"{}\"}}\n@Field {{\"id\":\"Pick\",\"label\":\"Pick one\",\"required\":true,\"kind\":\"Choice\",\"options\":[\"Yes\",\"No\"]}}\n@Submit {{\"label\":\"Review answer\"}}\n@End\n",
        "01".repeat(32),
        "02".repeat(32)
    );
    let source = format!("{PROFILE}\n# Feedback\n{form}: After the form.\n");
    let document = parse(&source).unwrap();
    assert_eq!(document.forms.len(), 1);
    assert_eq!(
        document.forms[0].schema_digest,
        hex::encode(Sha256::digest(&form))
    );
    let outside = parse(&source.replace("After the form.", "Different outside text.")).unwrap();
    assert_eq!(
        document.forms[0].schema_digest,
        outside.forms[0].schema_digest
    );
    let inside = parse(&source.replace("Review answer", "Review response")).unwrap();
    assert_ne!(
        document.forms[0].schema_digest,
        inside.forms[0].schema_digest
    );
    let plain = document.lines.join("\n");
    for required in [
        "HyperNetFormMail/1",
        &"01".repeat(32),
        &"02".repeat(32),
        "Pick one [Pick]",
        "Choice",
        "Yes",
        "No",
        "required",
        "Review answer",
    ] {
        assert!(plain.contains(required), "{required}");
    }
}
