// SPDX-License-Identifier: MIT
// Unit tests for FormSchema.
use super::*;
use serde_json::json;

fn form() -> Form {
    Form { id: "Example".into(), label: "Example".into(), profile: PROFILE.into(), recipient: "01".repeat(32), owner: "02".repeat(32), schema_digest: "03".repeat(32), fields: vec![
        field(json!({"id":"Text","label":"Text","required":true,"kind":"Text","maxBytes":2048})).unwrap(),
        field(json!({"id":"Lines","label":"Lines","kind":"Multiline","maxBytes":2048})).unwrap(),
        field(json!({"id":"Count","label":"Count","required":true,"kind":"Integer","minimum":-2,"maximum":2})).unwrap(),
        field(json!({"id":"Flag","label":"Flag","required":true,"kind":"Boolean"})).unwrap(),
        field(json!({"id":"Choice","label":"Choice","required":true,"kind":"Choice","options":["One","Two"]})).unwrap(),
    ] }
}
#[test]
fn values_preserve_types_and_enforce_complete_schema() {
    let form = form();
    let values: BTreeMap<String, Value> = serde_json::from_value(json!({"Text":"x".repeat(2048),"Lines":"First\nSecond","Count":-2,"Flag":false,"Choice":"One"})).unwrap();
    validate_values(&form, &values).unwrap();
    for (id, invalid) in [
        ("Text", json!(" ")),
        ("Text", json!("x".repeat(2049))),
        ("Text", json!("Line\nBreak")),
        ("Text", json!("Escape\u{1b}")),
        ("Lines", json!("Return\r")),
        ("Count", json!(3)),
        ("Count", json!(1.0)),
        ("Count", json!("1")),
        ("Flag", json!(1)),
        ("Choice", json!("Three")),
        ("Extra", json!("Unknown")),
    ] {
        let mut changed = values.clone();
        changed.insert(id.into(), invalid);
        assert!(validate_values(&form, &changed).is_err(), "{id}");
    }
    let mut missing = values.clone();
    missing.remove("Lines");
    assert!(validate_values(&form, &missing).is_ok());
    missing.remove("Flag");
    assert_eq!(validate_values(&form, &missing), Err("RequiredFormValue"));
}
#[test]
fn serialized_values_limit_accounts_for_json_expansion() {
    let form = Form {
        fields: (0..4)
            .map(|n| Field {
                id: format!("Text{n}"),
                label: "Text".into(),
                required: false,
                kind: FieldKind::Text { max_bytes: 2048 },
            })
            .collect(),
        ..form()
    };
    let values = form
        .fields
        .iter()
        .map(|field| (field.id.clone(), json!("\\".repeat(1024))))
        .collect();
    assert_eq!(validate_values(&form, &values), Err("InvalidFormValues"));
}
