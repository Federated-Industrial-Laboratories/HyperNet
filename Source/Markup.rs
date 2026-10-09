// SPDX-License-Identifier: MIT
// Parse a bounded inert document; source bytes remain the publication identity.
#[path = "PageComponents.rs"]
mod components;
use components::{Action, Directive};
pub use components::{Colour, ScrollDirection};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use unicode_segmentation::UnicodeSegmentation;

pub const PROFILE: &str = "HyperNetPage/2";
pub const MAX_BYTES: usize = 16 * 1024;
pub const MAX_NODES: usize = 256;
pub const MAX_DEPTH: usize = 8;
#[derive(Clone, Debug, Serialize)]
pub struct Link {
    pub target: String,
    pub label: String,
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Style {
    pub colour: Option<Colour>,
    pub bold: bool,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum TextKind {
    Paragraph,
    Heading2,
    Heading3,
    Item,
    Quote,
    Literal,
}
#[derive(Clone, Debug, Serialize)]
pub enum PageAction {
    Navigate {
        link: usize,
    },
    Focus {
        target: String,
    },
    Scroll {
        target: String,
        direction: ScrollDirection,
    },
}
#[derive(Clone, Debug, Serialize)]
pub enum Kind {
    Text {
        text: String,
        kind: TextKind,
    },
    Column {
        weight: u8,
        padding: u8,
        gap: u8,
    },
    Row {
        min_child_columns: u16,
        gap: u8,
    },
    Panel {
        label: String,
        padding: u8,
    },
    ScrollBox {
        label: String,
        rows: u16,
    },
    Separator,
    Spacer {
        rows: u16,
    },
    Progress {
        label: String,
        value: u32,
        maximum: u32,
    },
    Button {
        label: String,
        action: PageAction,
    },
}
#[derive(Clone, Debug, Serialize)]
pub struct Node {
    pub key: usize,
    pub id: Option<String>,
    pub style: Style,
    pub kind: Kind,
    pub children: Vec<Node>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Document {
    pub title: String,
    pub lines: Vec<String>,
    pub links: Vec<Link>,
    pub nodes: Vec<Node>,
}

fn forbidden(ch: char) -> bool {
    let n = ch as u32;
    ch.is_control()
        || matches!(
            ch,
            '\u{00ad}' | '\u{061c}' | '\u{200b}' | '\u{200e}' | '\u{200f}' | '\u{feff}'
        )
        || ('\u{2028}'..='\u{202e}').contains(&ch)
        || ('\u{2060}'..='\u{206f}').contains(&ch)
        || (0xfdd0..=0xfdef).contains(&n)
        || (0xe0000..=0xe007f).contains(&n)
        || n & 0xffff >= 0xfffe
}
fn text(value: &str, maximum: usize, empty: bool) -> Result<(), &'static str> {
    if value.len() > maximum
        || (!empty && value.trim().is_empty())
        || value.chars().any(forbidden)
        || value.graphemes(true).count() > 512
        || value.graphemes(true).any(|g| g.chars().count() > 16)
    {
        return Err("InvalidPageText");
    }
    Ok(())
}
pub fn namespace(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value.bytes().all(|b| b.is_ascii_alphanumeric())
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn target(value: &str) -> bool {
    if value.len() > 512 || !value.is_ascii() || value.bytes().any(|b| b <= 32 || b >= 127) {
        return false;
    }
    if let Some(address) = value.strip_prefix("hypernet://") {
        let parts: Vec<_> = address.split('/').collect();
        return parts.len() == 4
            && hex(parts[0], 64)
            && hex(parts[1], 64)
            && namespace(parts[2])
            && hex(parts[3], 32);
    }
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.as_str() == value
}
fn navigation(
    address: String,
    label: &str,
    links: &mut Vec<Link>,
) -> Result<PageAction, &'static str> {
    if !target(&address) {
        return Err("InvalidPageLink");
    }
    let link = links.len();
    links.push(Link {
        target: address,
        label: label.into(),
    });
    Ok(PageAction::Navigate { link })
}
fn directive(line: &str, key: usize, links: &mut Vec<Link>) -> Result<Node, &'static str> {
    let (name, attributes) = line
        .strip_prefix('@')
        .ok_or("UnknownPageConstruct")?
        .split_once(' ')
        .ok_or("InvalidComponentJson")?;
    let mut value = components::strict_json(attributes)?;
    let object = value.as_object_mut().ok_or("InvalidComponentJson")?;
    if object.contains_key("component") {
        return Err("UnknownComponentAttribute");
    }
    object.insert("component".into(), name.into());
    let props: Directive =
        serde_json::from_value(value).map_err(|_| "InvalidComponentAttributes")?;
    let mut node = Node {
        key,
        id: None,
        style: Style::default(),
        kind: Kind::Separator,
        children: Vec::new(),
    };
    node.kind = match props {
        Directive::Column {
            id,
            colour,
            weight,
            padding,
            gap,
        } => {
            if !(1..=8).contains(&weight) || padding > 4 || gap > 4 {
                return Err("InvalidLayoutBound");
            }
            node.id = id;
            node.style.colour = colour;
            Kind::Column {
                weight,
                padding,
                gap,
            }
        }
        Directive::Row {
            id,
            colour,
            min_child_columns,
            gap,
        } => {
            if !(12..=120).contains(&min_child_columns) || gap > 4 {
                return Err("InvalidLayoutBound");
            }
            node.id = id;
            node.style.colour = colour;
            Kind::Row {
                min_child_columns,
                gap,
            }
        }
        Directive::Panel {
            id,
            colour,
            label,
            padding,
        } => {
            text(&label, 128, false)?;
            if padding > 4 {
                return Err("InvalidLayoutBound");
            }
            node.id = id;
            node.style.colour = colour;
            Kind::Panel { label, padding }
        }
        Directive::ScrollBox {
            id,
            colour,
            label,
            rows,
        } => {
            text(&label, 128, false)?;
            if !(2..=40).contains(&rows) {
                return Err("InvalidLayoutBound");
            }
            node.id = Some(id);
            node.style.colour = colour;
            Kind::ScrollBox { label, rows }
        }
        Directive::Text {
            colour,
            value,
            bold,
        } => {
            text(&value, 1024, false)?;
            node.style = Style { colour, bold };
            Kind::Text {
                text: value,
                kind: TextKind::Paragraph,
            }
        }
        Directive::Separator { colour } => {
            node.style.colour = colour;
            Kind::Separator
        }
        Directive::Spacer { rows } => {
            if !(1..=8).contains(&rows) {
                return Err("InvalidLayoutBound");
            }
            Kind::Spacer { rows }
        }
        Directive::Progress {
            colour,
            label,
            value,
            maximum,
        } => {
            text(&label, 128, false)?;
            if maximum == 0 || maximum > 1_000_000 || value > maximum {
                return Err("InvalidProgressBound");
            }
            node.style.colour = colour;
            Kind::Progress {
                label,
                value,
                maximum,
            }
        }
        Directive::Button {
            id,
            colour,
            label,
            action,
        } => {
            text(&label, 128, false)?;
            node.id = id;
            node.style.colour = colour;
            let action = match action {
                Action::Navigate { target } => navigation(target, &label, links)?,
                Action::Focus { target } => PageAction::Focus { target },
                Action::Scroll { target, direction } => PageAction::Scroll { target, direction },
            };
            Kind::Button { label, action }
        }
    };
    if node.id.as_ref().is_some_and(|id| !namespace(id)) {
        return Err("InvalidComponentId");
    }
    Ok(node)
}
fn container(node: &Node) -> bool {
    matches!(
        node.kind,
        Kind::Column { .. } | Kind::Row { .. } | Kind::Panel { .. } | Kind::ScrollBox { .. }
    )
}
fn append(node: Node, stack: &mut [Node], roots: &mut Vec<Node>) -> Result<(), &'static str> {
    if let Some(parent) = stack.last_mut() {
        if matches!(parent.kind, Kind::Row { .. }) && parent.children.len() == 8 {
            return Err("TooManyRowChildren");
        }
        parent.children.push(node);
    } else {
        roots.push(node);
    }
    Ok(())
}
fn plain(nodes: &[Node], links: &[Link], output: &mut Vec<String>) {
    for node in nodes {
        match &node.kind {
            Kind::Text { text, kind } => output.push(format!(
                "{}{text}",
                match kind {
                    TextKind::Paragraph => "",
                    TextKind::Heading2 => "## ",
                    TextKind::Heading3 => "### ",
                    TextKind::Item => "- ",
                    TextKind::Quote => "> ",
                    TextKind::Literal => "| ",
                }
            )),
            Kind::Panel { label, .. } | Kind::ScrollBox { label, .. } => {
                output.push(format!("[ {label} ]"))
            }
            Kind::Separator => output.push("---".into()),
            Kind::Spacer { rows } => output.extend((0..*rows).map(|_| String::new())),
            Kind::Progress {
                label,
                value,
                maximum,
            } => output.push(format!("{label}: {value}/{maximum}")),
            Kind::Button { label, action } => match action {
                PageAction::Navigate { link } => {
                    output.push(format!("[{}] {label}", link + 1));
                    output.push(format!("    {}", links[*link].target));
                }
                PageAction::Focus { target } => output.push(format!("[ {label} ] Focus {target}")),
                PageAction::Scroll { target, direction } => {
                    output.push(format!("[ {label} ] Scroll {target} {direction:?}"))
                }
            },
            Kind::Column { .. } | Kind::Row { .. } => {}
        }
        plain(&node.children, links, output);
    }
}
pub fn parse(body: &str) -> Result<Document, &'static str> {
    if body.len() > MAX_BYTES || !body.ends_with('\n') {
        return Err("InvalidPageSizeOrNewline");
    }
    let lines: Vec<_> = body.split_terminator('\n').collect();
    if !(2..=512).contains(&lines.len()) || lines[0] != PROFILE {
        return Err("InvalidPageProfile");
    }
    for line in &lines {
        text(line, 1024, true)?;
    }
    let title = lines[1].strip_prefix("# ").ok_or("MissingPageTitle")?;
    text(title, 128, false)?;
    let mut roots = Vec::new();
    let mut stack: Vec<Node> = Vec::new();
    let mut links = Vec::new();
    let mut ids = BTreeMap::new();
    let mut references = BTreeSet::new();
    let mut count = 0;
    let mut controls = 0;
    for line in lines.iter().skip(2) {
        if *line == "@End" {
            let node = stack.pop().ok_or("UnmatchedComponentEnd")?;
            if node.children.is_empty() {
                return Err("EmptyPageContainer");
            }
            append(node, &mut stack, &mut roots)?;
            continue;
        }
        count += 1;
        if count > MAX_NODES || stack.len() >= MAX_DEPTH {
            return Err("PageStructureLimit");
        }
        let node = if line.starts_with('@') {
            directive(line, count - 1, &mut links)?
        } else if let Some(link) = line.strip_prefix("=> ") {
            let (address, label) = link.split_once(' ').ok_or("InvalidPageLink")?;
            text(label, 128, false)?;
            Node {
                key: count - 1,
                id: None,
                style: Style::default(),
                kind: Kind::Button {
                    label: label.into(),
                    action: navigation(address.into(), label, &mut links)?,
                },
                children: Vec::new(),
            }
        } else if line.is_empty() {
            Node {
                key: count - 1,
                id: None,
                style: Style::default(),
                kind: Kind::Spacer { rows: 1 },
                children: Vec::new(),
            }
        } else {
            let (prefix, kind) = [
                ("### ", TextKind::Heading3),
                ("## ", TextKind::Heading2),
                (": ", TextKind::Paragraph),
                ("- ", TextKind::Item),
                ("> ", TextKind::Quote),
                ("| ", TextKind::Literal),
            ]
            .into_iter()
            .find(|(prefix, _)| line.starts_with(prefix))
            .ok_or("UnknownPageConstruct")?;
            let value = &line[prefix.len()..];
            text(value, 1024, false)?;
            Node {
                key: count - 1,
                id: None,
                style: Style {
                    colour: None,
                    bold: matches!(kind, TextKind::Heading2 | TextKind::Heading3),
                },
                kind: Kind::Text {
                    text: value.into(),
                    kind,
                },
                children: Vec::new(),
            }
        };
        if let Some(id) = &node.id
            && ids
                .insert(id.clone(), matches!(node.kind, Kind::ScrollBox { .. }))
                .is_some()
        {
            return Err("DuplicateComponentId");
        }
        if matches!(node.kind, Kind::ScrollBox { .. } | Kind::Button { .. }) {
            controls += 1;
            if controls > 64 {
                return Err("TooManyPageControls");
            }
        }
        if let Kind::Button {
            action: PageAction::Focus { target } | PageAction::Scroll { target, .. },
            ..
        } = &node.kind
        {
            if !namespace(target) {
                return Err("InvalidComponentReference");
            }
            references.insert(target.clone());
        }
        if container(&node) {
            stack.push(node);
        } else {
            append(node, &mut stack, &mut roots)?;
        }
    }
    if !stack.is_empty() {
        return Err("UnclosedPageContainer");
    }
    if references.iter().any(|id| ids.get(id) != Some(&true)) {
        return Err("UnknownScrollBox");
    }
    let mut lines = vec![format!("# {title}")];
    plain(&roots, &links, &mut lines);
    Ok(Document {
        title: title.into(),
        lines,
        links,
        nodes: roots,
    })
}
pub fn validate(body: &str) -> Result<(), &'static str> {
    parse(body).map(|_| ())
}
pub fn validate_profile(profile: &str, body: &str) -> Result<(), &'static str> {
    if profile != PROFILE {
        return Err("InvalidPageProfile");
    }
    validate(body)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grammar_vectors() {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../Tests/MarkupVectors.json")).unwrap();
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
}
