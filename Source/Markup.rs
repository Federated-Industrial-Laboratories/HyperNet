// SPDX-License-Identifier: MIT
// Validate the bounded HyperNetPage/1 text grammar without interpreting content.
use unicode_segmentation::UnicodeSegmentation;

pub const PROFILE: &str = "HyperNetPage/1";
pub const MAX_BYTES: usize = 16 * 1024;

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

pub fn validate(body: &str) -> Result<(), &'static str> {
    if body.len() > MAX_BYTES || !body.ends_with('\n') {
        return Err("InvalidPageSizeOrNewline");
    }
    let lines: Vec<_> = body.split_terminator('\n').collect();
    if !(2..=512).contains(&lines.len()) || lines[0] != PROFILE {
        return Err("InvalidPageProfile");
    }
    for (index, line) in lines.iter().enumerate() {
        if line.len() > 1024
            || line.chars().any(forbidden)
            || line.graphemes(true).count() > 512
            || line.graphemes(true).any(|g| g.chars().count() > 16)
        {
            return Err("InvalidPageText");
        }
        if index == 0 {
            continue;
        }
        if index == 1 {
            let title = line.strip_prefix("# ").ok_or("MissingPageTitle")?;
            if title.trim().is_empty() || title.len() > 128 {
                return Err("InvalidPageTitle");
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if let Some(link) = line.strip_prefix("=> ") {
            let (address, label) = link.split_once(' ').ok_or("InvalidPageLink")?;
            if !target(address) || label.trim().is_empty() || label.len() > 128 {
                return Err("InvalidPageLink");
            }
        } else if let Some(text) = ["### ", "## ", ": ", "- ", "> ", "| "]
            .iter()
            .find_map(|prefix| line.strip_prefix(prefix))
        {
            if text.trim().is_empty() {
                return Err("EmptyPageBlock");
            }
        } else {
            return Err("UnknownPageConstruct");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar_vectors_are_stable() {
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
        assert!(
            validate(&format!(
                "HyperNetPage/1\n# Title\n: x{}\n",
                "\u{0301}".repeat(16)
            ))
            .is_err()
        );
        assert!(
            validate(&format!(
                "HyperNetPage/1\n# Title\n{}",
                ": text\n".repeat(511)
            ))
            .is_err()
        );
        assert!(
            validate(&format!(
                "HyperNetPage/1\n# Title\n: {}\n",
                "x".repeat(1023)
            ))
            .is_err()
        );
    }
}
