// SPDX-License-Identifier: MIT
// Typed attributes for the finite terminal component grammar.
use super::media::{Effect, Fit};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Colour {
    #[default]
    Default,
    Black,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
    BrightBlack,
    BrightRed,
    BrightGreen,
    BrightYellow,
    BrightBlue,
    BrightMagenta,
    BrightCyan,
    BrightWhite,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum ScrollDirection {
    Up,
    Down,
    Start,
    End,
}
#[derive(Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Action {
    Navigate {
        target: String,
    },
    Focus {
        target: String,
    },
    Scroll {
        target: String,
        direction: ScrollDirection,
    },
    Reveal {
        target: String,
    },
    Motion {
        target: String,
        running: bool,
    },
}
fn one() -> u8 {
    1
}
fn columns() -> u16 {
    24
}
#[derive(Deserialize)]
#[serde(
    tag = "component",
    deny_unknown_fields,
    rename_all_fields = "camelCase"
)]
pub enum Directive {
    Form {
        id: String,
        label: String,
        profile: String,
        recipient: String,
        owner: String,
    },
    Submit {
        label: String,
    },
    Column {
        id: Option<String>,
        colour: Option<Colour>,
        #[serde(default = "one")]
        weight: u8,
        #[serde(default)]
        padding: u8,
        #[serde(default)]
        gap: u8,
    },
    Row {
        id: Option<String>,
        colour: Option<Colour>,
        #[serde(default = "columns")]
        min_child_columns: u16,
        #[serde(default = "one")]
        gap: u8,
    },
    Panel {
        motion: Option<Effect>,
        id: Option<String>,
        colour: Option<Colour>,
        label: String,
        #[serde(default = "one")]
        padding: u8,
    },
    ScrollBox {
        id: String,
        colour: Option<Colour>,
        label: String,
        rows: u16,
    },
    Text {
        id: Option<String>,
        motion: Option<Effect>,
        colour: Option<Colour>,
        value: String,
        #[serde(default)]
        bold: bool,
    },
    Separator {
        colour: Option<Colour>,
    },
    Spacer {
        rows: u16,
    },
    Progress {
        id: Option<String>,
        motion: Option<Effect>,
        colour: Option<Colour>,
        label: String,
        value: u32,
        maximum: u32,
    },
    Image {
        id: String,
        asset: String,
        alt: String,
        rows: u16,
        #[serde(default)]
        fit: Fit,
        motion: Option<Effect>,
    },
    Button {
        id: Option<String>,
        colour: Option<Colour>,
        label: String,
        action: Action,
    },
}

// Check nested maps before typed parsing, including repeated optional null fields.
pub fn strict_json(input: &str) -> Result<serde_json::Value, &'static str> {
    use serde::de::{self, MapAccess, SeqAccess, Visitor};
    use std::fmt;
    struct Unique(serde_json::Value);
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Check;
            impl<'de> Visitor<'de> for Check {
                type Value = Unique;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("bounded JSON")
                }
                fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<Unique, M::Error> {
                    let mut object = serde_json::Map::new();
                    while let Some(key) = m.next_key::<String>()? {
                        if object.contains_key(&key) {
                            return Err(de::Error::custom("duplicate key"));
                        }
                        object.insert(key, m.next_value::<Unique>()?.0);
                    }
                    Ok(Unique(serde_json::Value::Object(object)))
                }
                fn visit_seq<S: SeqAccess<'de>>(self, mut s: S) -> Result<Unique, S::Error> {
                    let mut values = Vec::new();
                    while let Some(value) = s.next_element::<Unique>()? {
                        values.push(value.0);
                    }
                    Ok(Unique(serde_json::Value::Array(values)))
                }
                fn visit_str<E: de::Error>(self, value: &str) -> Result<Unique, E> {
                    Ok(Unique(value.into()))
                }
                fn visit_bool<E: de::Error>(self, value: bool) -> Result<Unique, E> {
                    Ok(Unique(value.into()))
                }
                fn visit_u64<E: de::Error>(self, value: u64) -> Result<Unique, E> {
                    Ok(Unique(value.into()))
                }
                fn visit_i64<E: de::Error>(self, value: i64) -> Result<Unique, E> {
                    Ok(Unique(value.into()))
                }
                fn visit_f64<E: de::Error>(self, _: f64) -> Result<Unique, E> {
                    Err(de::Error::custom("integer required"))
                }
                fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                    Ok(Unique(serde_json::Value::Null))
                }
            }
            d.deserialize_any(Check)
        }
    }
    serde_json::from_str::<Unique>(input)
        .map(|value| value.0)
        .map_err(|_| "InvalidComponentJson")
}
