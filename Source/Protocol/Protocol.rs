// SPDX-License-Identifier: MIT
// Canonical hexadecimal identifiers reject alternate textual encodings.
pub fn fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    if value.len() != N * 2
        || value
            .bytes()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err("InvalidEncoding");
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| "InvalidEncoding")?;
    Ok(bytes)
}
