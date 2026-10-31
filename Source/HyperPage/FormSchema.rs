// SPDX-License-Identifier: MIT
// Bound declarative form schemas and typed values without executable validation rules.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use unicode_segmentation::UnicodeSegmentation;

pub const PROFILE: &str = "HyperNetFormMail/1";
pub const MAX_BUNDLE_BYTES: usize = 20 * 1024;
// Encrypted field values are validated by clients; infrastructure only admits schemas.
#[allow(dead_code)]
pub const MAX_VALUES_BYTES: usize = 8 * 1024;
pub const MAX_FORMS: usize = 4;
pub const MAX_FIELDS: usize = 16;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Form {
    pub id: String,
    pub label: String,
    pub profile: String,
    pub recipient: String,
    pub owner: String,
    pub schema_digest: String,
    pub fields: Vec<Field>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub id: String,
    pub label: String,
    pub required: bool,
    pub kind: FieldKind,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum FieldKind {
    Text { max_bytes: usize },
    Multiline { max_bytes: usize },
    Integer { minimum: i64, maximum: i64 },
    Boolean,
    Choice { options: Vec<String> },
}

pub(super) fn field(mut value: Value) -> Result<Field, &'static str> {
    let object = value.as_object_mut().ok_or("InvalidFieldAttributes")?;
    let id = object.remove("id").ok_or("InvalidFieldAttributes")?;
    let label = object.remove("label").ok_or("InvalidFieldAttributes")?;
    let required = object.remove("required").unwrap_or(Value::Bool(false));
    let field = Field {
        id: serde_json::from_value(id).map_err(|_| "InvalidFieldAttributes")?,
        label: serde_json::from_value(label).map_err(|_| "InvalidFieldAttributes")?,
        required: serde_json::from_value(required).map_err(|_| "InvalidFieldAttributes")?,
        kind: serde_json::from_value(value).map_err(|_| "InvalidFieldAttributes")?,
    };
    if !super::namespace(&field.id) {
        return Err("InvalidFieldId");
    }
    super::text(&field.label, 128, false)?;
    match &field.kind {
        FieldKind::Text { max_bytes } | FieldKind::Multiline { max_bytes } => {
            if !(1..=2048).contains(max_bytes) {
                return Err("InvalidFieldBound");
            }
        }
        FieldKind::Integer { minimum, maximum } if minimum > maximum => {
            return Err("InvalidFieldBound");
        }
        FieldKind::Choice { options } => {
            let mut seen = BTreeSet::new();
            if options.is_empty() || options.len() > 16 {
                return Err("InvalidFieldChoices");
            }
            for option in options {
                super::text(option, 128, false)?;
                if !seen.insert(option) {
                    return Err("InvalidFieldChoices");
                }
            }
        }
        _ => {}
    }
    Ok(field)
}

#[allow(dead_code)]
pub fn validate_values(form: &Form, values: &BTreeMap<String, Value>) -> Result<(), &'static str> {
    if serde_json::to_vec(values)
        .map_err(|_| "InvalidFormValues")?
        .len()
        > MAX_VALUES_BYTES
        || values
            .keys()
            .any(|id| !form.fields.iter().any(|field| &field.id == id))
    {
        return Err("InvalidFormValues");
    }
    for field in &form.fields {
        let Some(value) = values.get(&field.id) else {
            if field.required {
                return Err("RequiredFormValue");
            }
            continue;
        };
        validate_field(field, value)?;
    }
    Ok(())
}

#[allow(dead_code)]
fn value_text(value: &str) -> Result<(), &'static str> {
    if value.chars().any(super::forbidden) || value.graphemes(true).any(|g| g.chars().count() > 16)
    {
        return Err("InvalidFormText");
    }
    Ok(())
}

#[allow(dead_code)]
pub fn validate_field(field: &Field, value: &Value) -> Result<(), &'static str> {
    match &field.kind {
        FieldKind::Text { max_bytes } | FieldKind::Multiline { max_bytes } => {
            let value = value.as_str().ok_or("InvalidFormValueType")?;
            if value.len() > *max_bytes || (field.required && value.trim().is_empty()) {
                return Err("InvalidFormText");
            }
            if matches!(field.kind, FieldKind::Multiline { .. }) {
                for line in value.split('\n') {
                    value_text(line)?;
                }
            } else {
                value_text(value)?;
            }
        }
        FieldKind::Integer { minimum, maximum } => {
            let value = value.as_i64().ok_or("InvalidFormValueType")?;
            if value < *minimum || value > *maximum {
                return Err("InvalidFormInteger");
            }
        }
        FieldKind::Boolean if !value.is_boolean() => return Err("InvalidFormValueType"),
        FieldKind::Choice { options }
            if !value
                .as_str()
                .is_some_and(|value| options.iter().any(|option| option == value)) =>
        {
            return Err("InvalidFormChoice");
        }
        _ => {}
    }
    Ok(())
}

pub fn field_description(field: &Field) -> String {
    let kind = match &field.kind {
        FieldKind::Text { max_bytes } => format!("Text, at most {max_bytes} bytes"),
        FieldKind::Multiline { max_bytes } => format!("Multiline, at most {max_bytes} bytes"),
        FieldKind::Integer { minimum, maximum } => format!("Integer, {minimum} through {maximum}"),
        FieldKind::Boolean => "Boolean, true or false".into(),
        FieldKind::Choice { options } => format!(
            "Choice, {}",
            serde_json::to_string(options).unwrap_or_default()
        ),
    };
    format!(
        "{} [{}]: {kind}; {}",
        field.label,
        field.id,
        if field.required {
            "required"
        } else {
            "optional"
        }
    )
}

#[cfg(test)]
#[path = "../../Tests/Unit/HyperPage/FormSchemaUnitTests.rs"]
mod tests;
