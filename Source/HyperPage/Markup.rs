// SPDX-License-Identifier: MIT
// Parse a bounded inert document; source bytes remain the publication identity.
#[path = "PageComponents.rs"]
mod components;
#[path = "FormSchema.rs"]
pub mod forms;
#[path = "MediaSchema.rs"]
pub mod media;
use components::{Action, Directive};
pub use components::{BorderStyle, Colour, ScrollDirection};
pub use media::{Effect, Fit, Preset};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    pub border: Option<BorderStyle>,
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
    Reveal {
        target: String,
    },
    Motion {
        target: String,
        running: bool,
    },
    Submit {
        form: String,
    },
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
    Image {
        asset: String,
        alt: String,
        rows: u16,
        fit: Fit,
    },
    Form {
        form: String,
        label: String,
    },
    Field {
        form: String,
        field: forms::Field,
    },
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
    pub motion: Option<Effect>,
    pub kind: Kind,
    pub children: Vec<Node>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Document {
    pub title: String,
    pub tags: Vec<String>,
    pub lines: Vec<String>,
    pub links: Vec<Link>,
    pub nodes: Vec<Node>,
    pub forms: Vec<forms::Form>,
    pub assets: Vec<media::Asset>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tags {
    values: Vec<String>,
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
fn directive(
    line: &str,
    key: usize,
    links: &mut Vec<Link>,
    forms: &mut Vec<forms::Form>,
    active_form: Option<&str>,
) -> Result<Node, &'static str> {
    let (name, attributes) = line
        .strip_prefix('@')
        .ok_or("UnknownPageConstruct")?
        .split_once(' ')
        .ok_or("InvalidComponentJson")?;
    let mut value = components::strict_json(attributes)?;
    if name == "Field" {
        let form = active_form.ok_or("FieldOutsideForm")?;
        let field = forms::field(value)?;
        let schema = forms
            .iter_mut()
            .find(|entry| entry.id == form)
            .ok_or("UnknownForm")?;
        if schema.fields.len() >= forms::MAX_FIELDS
            || schema.fields.iter().any(|entry| entry.id == field.id)
        {
            return Err("InvalidFormFields");
        }
        schema.fields.push(field.clone());
        return Ok(Node {
            key,
            id: None,
            style: Style::default(),
            motion: None,
            kind: Kind::Field {
                form: form.into(),
                field,
            },
            children: Vec::new(),
        });
    }
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
        motion: None,
        kind: Kind::Separator,
        children: Vec::new(),
    };
    node.kind = match props {
        Directive::Form {
            id,
            label,
            profile,
            recipient,
            owner,
        } => {
            if active_form.is_some() || forms.len() >= forms::MAX_FORMS {
                return Err("InvalidFormNestingOrCount");
            }
            text(&label, 128, false)?;
            if !namespace(&id)
                || profile != forms::PROFILE
                || !hex(&recipient, 64)
                || !hex(&owner, 64)
            {
                return Err("InvalidFormDestination");
            }
            forms.push(forms::Form {
                id: id.clone(),
                label: label.clone(),
                profile,
                recipient,
                owner,
                schema_digest: String::new(),
                fields: Vec::new(),
            });
            node.id = Some(id.clone());
            Kind::Form { form: id, label }
        }
        Directive::Submit { label } => {
            text(&label, 128, false)?;
            Kind::Button {
                label,
                action: PageAction::Submit {
                    form: active_form.ok_or("SubmitOutsideForm")?.into(),
                },
            }
        }
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
            motion,
            id,
            colour,
            border,
            label,
            padding,
        } => {
            text(&label, 128, false)?;
            if padding > 4 {
                return Err("InvalidLayoutBound");
            }
            node.id = id;
            node.style.colour = colour;
            node.style.border = border;
            node.motion = motion;
            Kind::Panel { label, padding }
        }
        Directive::ScrollBox {
            id,
            colour,
            border,
            label,
            rows,
        } => {
            text(&label, 128, false)?;
            if !(2..=40).contains(&rows) {
                return Err("InvalidLayoutBound");
            }
            node.id = Some(id);
            node.style.colour = colour;
            node.style.border = border;
            Kind::ScrollBox { label, rows }
        }
        Directive::Text {
            id,
            motion,
            colour,
            value,
            bold,
        } => {
            text(&value, 1024, false)?;
            node.id = id;
            node.motion = motion;
            node.style = Style {
                colour,
                bold,
                ..Style::default()
            };
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
            id,
            motion,
            colour,
            label,
            value,
            maximum,
        } => {
            text(&label, 128, false)?;
            if maximum == 0 || maximum > 1_000_000 || value > maximum {
                return Err("InvalidProgressBound");
            }
            node.id = id;
            node.motion = motion;
            node.style.colour = colour;
            Kind::Progress {
                label,
                value,
                maximum,
            }
        }
        Directive::Image {
            id,
            asset,
            alt,
            rows,
            fit,
            motion,
        } => {
            text(&alt, 128, false)?;
            if !namespace(&asset) || !(1..=40).contains(&rows) {
                return Err("InvalidImageViewport");
            }
            node.id = Some(id);
            node.motion = motion;
            Kind::Image {
                asset,
                alt,
                rows,
                fit,
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
                Action::Reveal { target } => PageAction::Reveal { target },
                Action::Motion { target, running } => PageAction::Motion { target, running },
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
    if let Some(effect) = &node.motion
        && (!(1000..=10000).contains(&effect.duration_ms)
            || !matches!(
                (&node.kind, effect.preset),
                (
                    Kind::Text { .. },
                    Preset::ColourPulse | Preset::TextFade | Preset::TextScroll
                ) | (Kind::Panel { .. }, Preset::BorderEmphasis)
                    | (Kind::Progress { .. }, Preset::ProgressSweep)
                    | (Kind::Image { .. }, Preset::ImagePan | Preset::ImageFade)
            ))
    {
        return Err("InvalidMotionPresetOrDuration");
    }
    Ok(node)
}
fn container(node: &Node) -> bool {
    matches!(
        node.kind,
        Kind::Column { .. }
            | Kind::Row { .. }
            | Kind::Panel { .. }
            | Kind::ScrollBox { .. }
            | Kind::Form { .. }
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
fn plain(nodes: &[Node], links: &[Link], forms: &[forms::Form], output: &mut Vec<String>) {
    for node in nodes {
        if let Some(effect) = node.motion {
            output.push(format!(
                "[ Effect {:?}: {} ms; explicit local activation ]",
                effect.preset, effect.duration_ms
            ));
        }
        match &node.kind {
            Kind::Image {
                asset,
                alt,
                rows,
                fit,
            } => output.push(format!(
                "[ Image {asset}: {alt}; {rows} rows, {fit:?}; hidden until revealed ]"
            )),
            Kind::Form { form, label } => {
                let schema = forms
                    .iter()
                    .find(|entry| &entry.id == form)
                    .expect("parsed form");
                output.push(format!("[ Form {label} ({form}) ]"));
                output.push(format!("Profile: {}", schema.profile));
                output.push(format!("Recipient: {}", schema.recipient));
                output.push(format!("Owner: {}", schema.owner));
                output.push(format!("Schema: {}", schema.schema_digest));
            }
            Kind::Field { field, .. } => output.push(forms::field_description(field)),
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
                PageAction::Reveal { target } => {
                    output.push(format!("[ {label} ] Reveal image {target}"))
                }
                PageAction::Motion { target, running } => {
                    output.push(format!("[ {label} ] Motion {target}: {running}"))
                }
                PageAction::Submit { form } => {
                    output.push(format!("[ {label} ] Review form {form} before sending"))
                }
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
        plain(&node.children, links, forms, output);
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
    let mut images = BTreeSet::new();
    let mut effects = BTreeSet::new();
    let mut media_references = BTreeSet::new();
    let mut reveal_references = BTreeSet::new();
    let mut motion_references = BTreeSet::new();
    let mut assets = Vec::new();
    let mut count = 0;
    let mut controls = 0;
    let mut forms: Vec<forms::Form> = Vec::new();
    let mut tags = Vec::new();
    let mut form_start = None;
    let mut offset = lines[0].len() + lines[1].len() + 2;
    let metadata_start = offset;
    for line in lines.iter().skip(2) {
        let line_start = offset;
        offset += line.len() + 1;
        if let Some(attributes) = line.strip_prefix("@Tags ") {
            if line_start != metadata_start {
                return Err("PageTagsMustFollowTitle");
            }
            let declared: Tags = serde_json::from_value(components::strict_json(attributes)?)
                .map_err(|_| "InvalidPageTags")?;
            if !(1..=16).contains(&declared.values.len()) {
                return Err("InvalidPageTags");
            }
            let mut unique = BTreeSet::new();
            for tag in &declared.values {
                text(tag, 64, false)?;
                if tag.trim() != tag || !unique.insert(tag.as_str()) {
                    return Err("InvalidPageTags");
                }
            }
            tags = declared.values;
            continue;
        }
        if *line == "@End" {
            let node = stack.pop().ok_or("UnmatchedComponentEnd")?;
            if node.children.is_empty() {
                return Err("EmptyPageContainer");
            }
            if let Kind::Form { form, .. } = &node.kind {
                let schema = forms
                    .iter_mut()
                    .find(|entry| &entry.id == form)
                    .ok_or("UnknownForm")?;
                if schema.fields.is_empty()
                    || node
                        .children
                        .iter()
                        .filter(|node| {
                            matches!(
                                node.kind,
                                Kind::Button {
                                    action: PageAction::Submit { .. },
                                    ..
                                }
                            )
                        })
                        .count()
                        != 1
                {
                    return Err("InvalidFormFieldsOrSubmit");
                }
                schema.schema_digest = hex::encode(Sha256::digest(
                    &body.as_bytes()[form_start.take().ok_or("InvalidFormSpan")?..offset],
                ));
            }
            append(node, &mut stack, &mut roots)?;
            continue;
        }
        if let Some(attributes) = line.strip_prefix("@Asset ") {
            if !stack.is_empty() {
                return Err("MediaDeclarationInContainer");
            }
            let asset = serde_json::from_value(components::strict_json(attributes)?)
                .map_err(|_| "InvalidMediaManifest")?;
            assets.push(asset);
            media::validate_assets(&assets)?;
            continue;
        }
        count += 1;
        if count > MAX_NODES || stack.len() >= MAX_DEPTH {
            return Err("PageStructureLimit");
        }
        let active_form = stack.last().and_then(|node| match &node.kind {
            Kind::Form { form, .. } => Some(form.as_str()),
            _ => None,
        });
        let node = if line.starts_with('@') {
            directive(line, count - 1, &mut links, &mut forms, active_form)?
        } else if let Some(link) = line.strip_prefix("=> ") {
            let (address, label) = link.split_once(' ').ok_or("InvalidPageLink")?;
            text(label, 128, false)?;
            Node {
                key: count - 1,
                id: None,
                style: Style::default(),
                motion: None,
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
                motion: None,
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
                motion: None,
                style: Style {
                    bold: matches!(kind, TextKind::Heading2 | TextKind::Heading3),
                    ..Style::default()
                },
                kind: Kind::Text {
                    text: value.into(),
                    kind,
                },
                children: Vec::new(),
            }
        };
        if active_form.is_some()
            && !matches!(
                node.kind,
                Kind::Field { .. }
                    | Kind::Button {
                        action: PageAction::Submit { .. },
                        ..
                    }
            )
        {
            return Err("InvalidFormChild");
        }
        if matches!(node.kind, Kind::Form { .. }) {
            form_start = Some(line_start);
        }
        if let Some(id) = &node.id
            && ids
                .insert(id.clone(), matches!(node.kind, Kind::ScrollBox { .. }))
                .is_some()
        {
            return Err("DuplicateComponentId");
        }
        if let Kind::Image { asset, .. } = &node.kind {
            media_references.insert(asset.clone());
            images.insert(node.id.clone().ok_or("MissingImageId")?);
        }
        if node.motion.is_some()
            && let Some(id) = &node.id
        {
            effects.insert(id.clone());
        }
        if let Kind::Button { action, .. } = &node.kind {
            match action {
                PageAction::Reveal { target } => {
                    reveal_references.insert(target.clone());
                }
                PageAction::Motion { target, .. } => {
                    motion_references.insert(target.clone());
                }
                _ => {}
            }
        }
        if matches!(
            node.kind,
            Kind::ScrollBox { .. } | Kind::Button { .. } | Kind::Field { .. }
        ) {
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
    let asset_ids: BTreeSet<_> = assets.iter().map(|asset| asset.id.clone()).collect();
    if media_references != asset_ids {
        return Err("UnknownOrUnusedMediaAsset");
    }
    if !reveal_references.is_subset(&images) || !motion_references.is_subset(&effects) {
        return Err("UnknownMediaOrMotionTarget");
    }
    let mut lines = vec![format!("# {title}")];
    if !tags.is_empty() {
        lines.push(format!(
            "[ Tags: {} ]",
            serde_json::to_string(&tags).map_err(|_| "InvalidPageTags")?
        ));
    }
    for asset in &assets {
        lines.push(format!(
            "[ Asset {}: {}; {}x{}; {} bytes; SHA256 {}; copies {}; hosts {} ]",
            asset.id,
            asset.profile,
            asset.width,
            asset.height,
            asset.bytes,
            asset.digest,
            asset.copies,
            asset.hosts.join(",")
        ));
    }
    plain(&roots, &links, &forms, &mut lines);
    Ok(Document {
        title: title.into(),
        tags,
        lines,
        links,
        nodes: roots,
        forms,
        assets,
    })
}
#[cfg(test)]
#[path = "MarkupTagTests.rs"]
mod tag_tests;
#[cfg(test)]
pub fn validate(body: &str) -> Result<(), &'static str> {
    parse(body).map(|_| ())
}
#[cfg(test)]
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
            serde_json::from_str(include_str!("../../Tests/MarkupVectors.json")).unwrap();
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
}
