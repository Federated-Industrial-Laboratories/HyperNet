// SPDX-License-Identifier: MIT
// Bounded immutable raster and vector media shared by independent page clients.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt::Write};

pub const RASTER_PROFILE: &str = "HyperNetRaster/1";
pub const VECTOR_PROFILE: &str = "HyperNetVector/1";
pub const MAX_ASSETS: usize = 8;
pub const MAX_PAGE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_VECTOR_BYTES: usize = 256 * 1024;
pub const MAX_PIXELS: u64 = 262_144;
#[allow(dead_code)]
pub const UNITS: i32 = 1024;
const COORDINATE_LIMIT: i32 = 16_777_216;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Asset {
    pub id: String,
    pub profile: String,
    pub width: u32,
    pub height: u32,
    pub bytes: u64,
    pub digest: String,
    pub hosts: Vec<String>,
    pub copies: u16,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Fit {
    #[default]
    Contain,
    Cover,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Preset {
    ColourPulse,
    TextFade,
    TextScroll,
    BorderEmphasis,
    ProgressSweep,
    ImagePan,
    ImageFade,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Effect {
    pub preset: Preset,
    pub duration_ms: u16,
}

pub fn dimensions(width: u32, height: u32) -> Result<(), &'static str> {
    if width == 0
        || height == 0
        || width > 1024
        || height > 1024
        || u64::from(width) * u64::from(height) > MAX_PIXELS
    {
        return Err("InvalidMediaDimensions");
    }
    Ok(())
}
pub fn validate_asset(asset: &Asset) -> Result<(), &'static str> {
    dimensions(asset.width, asset.height)?;
    if !super::namespace(&asset.id)
        || !super::hex(&asset.digest, 64)
        || !(1..=3).contains(&asset.hosts.len())
        || asset.copies == 0
        || usize::from(asset.copies) > asset.hosts.len()
        || asset.hosts.iter().any(|host| !super::hex(host, 64))
        || asset.hosts.iter().collect::<BTreeSet<_>>().len() != asset.hosts.len()
    {
        return Err("InvalidMediaManifest");
    }
    match asset.profile.as_str() {
        RASTER_PROFILE if asset.bytes == u64::from(asset.width) * u64::from(asset.height) * 3 => {
            Ok(())
        }
        VECTOR_PROFILE if asset.bytes > 0 && asset.bytes <= MAX_VECTOR_BYTES as u64 => Ok(()),
        _ => Err("InvalidMediaProfileOrLength"),
    }
}
pub fn validate_assets(assets: &[Asset]) -> Result<(), &'static str> {
    if assets.len() > MAX_ASSETS {
        return Err("TooManyMediaAssets");
    }
    let mut bytes = 0_u64;
    let mut ids = BTreeSet::new();
    for asset in assets {
        validate_asset(asset)?;
        bytes = bytes.checked_add(asset.bytes).ok_or("MediaPageBudget")?;
        if !ids.insert(&asset.id) || bytes > MAX_PAGE_BYTES {
            return Err("DuplicateMediaIdOrBudget");
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Vector {
    pub profile: String,
    pub width: u32,
    pub height: u32,
    pub background: [u8; 3],
    pub paths: Vec<VectorPath>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VectorPath {
    pub commands: Vec<PathCommand>,
    pub fill: Option<[u8; 4]>,
    pub stroke: Option<VectorStroke>,
    pub fill_rule: FillRule,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VectorStroke {
    pub colour: [u8; 4],
    pub width: u32,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum FillRule {
    NonZero,
    EvenOdd,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum PathCommand {
    Move {
        x: i32,
        y: i32,
    },
    Line {
        x: i32,
        y: i32,
    },
    Quad {
        x1: i32,
        y1: i32,
        x: i32,
        y: i32,
    },
    Cubic {
        x1: i32,
        y1: i32,
        x2: i32,
        y2: i32,
        x: i32,
        y: i32,
    },
    Close,
}
pub fn validate_vector(value: &Vector) -> Result<(), &'static str> {
    dimensions(value.width, value.height)?;
    if value.profile != VECTOR_PROFILE || value.paths.len() > 512 {
        return Err("InvalidVectorProfileOrPaths");
    }
    let mut count = 0_usize;
    for path in &value.paths {
        count = count
            .checked_add(path.commands.len())
            .ok_or("VectorCommandLimit")?;
        if path.commands.is_empty()
            || path.commands.len() > 2048
            || count > 8192
            || (path.fill.is_none() && path.stroke.is_none())
            || path
                .stroke
                .as_ref()
                .is_some_and(|s| !(1..=65_536).contains(&s.width))
        {
            return Err("InvalidVectorPath");
        }
        let mut open = false;
        for command in &path.commands {
            let coordinates: &[i32] = match command {
                PathCommand::Move { x, y } => {
                    open = true;
                    &[*x, *y]
                }
                PathCommand::Line { x, y } if open => &[*x, *y],
                PathCommand::Quad { x1, y1, x, y } if open => &[*x1, *y1, *x, *y],
                PathCommand::Cubic {
                    x1,
                    y1,
                    x2,
                    y2,
                    x,
                    y,
                } if open => &[*x1, *y1, *x2, *y2, *x, *y],
                PathCommand::Close if open => {
                    open = false;
                    &[]
                }
                _ => return Err("InvalidVectorContour"),
            };
            if coordinates
                .iter()
                .any(|n| !(-COORDINATE_LIMIT..=COORDINATE_LIMIT).contains(n))
            {
                return Err("VectorCoordinateLimit");
            }
        }
    }
    Ok(())
}
pub fn vector(bytes: &[u8]) -> Result<Vector, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_VECTOR_BYTES {
        return Err("VectorSizeLimit");
    }
    let input = std::str::from_utf8(bytes).map_err(|_| "InvalidVectorEncoding")?;
    let parsed = super::components::strict_json(input)?;
    let value: Vector = serde_json::from_value(parsed).map_err(|_| "InvalidVectorAttributes")?;
    validate_vector(&value)?;
    if serde_json::to_vec(&value).map_err(|_| "InvalidVectorEncoding")? != bytes {
        return Err("NonCanonicalVector");
    }
    Ok(value)
}
pub fn validate_asset_bytes(asset: &Asset, bytes: &[u8]) -> Result<(), &'static str> {
    validate_asset(asset)?;
    if bytes.len() as u64 != asset.bytes || hex::encode(Sha256::digest(bytes)) != asset.digest {
        return Err("MediaLengthOrDigestMismatch");
    }
    if asset.profile == VECTOR_PROFILE {
        let value = vector(bytes)?;
        if value.width != asset.width || value.height != asset.height {
            return Err("VectorManifestMismatch");
        }
    }
    Ok(())
}

// Integer viewBox units preserve geometry without XML, resource or CSS input.
#[allow(dead_code)]
pub fn vector_svg(value: &Vector) -> Result<String, &'static str> {
    validate_vector(value)?;
    if serde_json::to_vec(value)
        .map_err(|_| "InvalidVectorEncoding")?
        .len()
        > MAX_VECTOR_BYTES
    {
        return Err("VectorSizeLimit");
    }
    let width = value.width * UNITS as u32;
    let height = value.height * UNITS as u32;
    let mut out = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{}\" height=\"{}\" viewBox=\"0 0 {width} {height}\" overflow=\"hidden\"><rect width=\"{width}\" height=\"{height}\" fill=\"#{:02x}{:02x}{:02x}\"/>",
        value.width, value.height, value.background[0], value.background[1], value.background[2]
    );
    for path in &value.paths {
        out.push_str("<path d=\"");
        for c in &path.commands {
            match c {
                PathCommand::Move { x, y } => write!(out, "M{x} {y}"),
                PathCommand::Line { x, y } => write!(out, "L{x} {y}"),
                PathCommand::Quad { x1, y1, x, y } => write!(out, "Q{x1} {y1} {x} {y}"),
                PathCommand::Cubic {
                    x1,
                    y1,
                    x2,
                    y2,
                    x,
                    y,
                } => write!(out, "C{x1} {y1} {x2} {y2} {x} {y}"),
                PathCommand::Close => write!(out, "Z"),
            }
            .map_err(|_| "VectorExportFailed")?;
        }
        write!(
            out,
            "\" fill-rule=\"{}\"",
            match path.fill_rule {
                FillRule::NonZero => "nonzero",
                FillRule::EvenOdd => "evenodd",
            }
        )
        .map_err(|_| "VectorExportFailed")?;
        paint(&mut out, "fill", path.fill)?;
        paint(&mut out, "stroke", path.stroke.as_ref().map(|s| s.colour))?;
        if let Some(stroke) = &path.stroke {
            write!(out, " stroke-width=\"{}\" stroke-linecap=\"butt\" stroke-linejoin=\"miter\" stroke-miterlimit=\"4\"", stroke.width).map_err(|_| "VectorExportFailed")?;
        }
        out.push_str("/>");
    }
    out.push_str("</svg>\n");
    Ok(out)
}
#[allow(dead_code)]
fn paint(out: &mut String, name: &str, colour: Option<[u8; 4]>) -> Result<(), &'static str> {
    match colour {
        Some([r, g, b, a]) => write!(
            out,
            " {name}=\"#{r:02x}{g:02x}{b:02x}\" {name}-opacity=\"{:.8}\"",
            f64::from(a) / 255.0
        ),
        None => write!(out, " {name}=\"none\""),
    }
    .map_err(|_| "VectorExportFailed")
}

#[cfg(test)]
#[path = "../../Tests/Unit/HyperPage/MediaSchemaUnitTests.rs"]
mod tests;
