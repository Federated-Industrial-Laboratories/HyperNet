// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
#[cfg(test)]
pub fn verify_response(request: &Request, encoded: &[u8]) -> Result<(Vec<u8>, Option<Match>)> {
    let value = wire::decode(encoded)?;
    let f = value.array(6)?;
    ensure!(
        f[0].uint()? == 201
            && f[1].uint()? == 1
            && f[2].text()? == "PageSearchResult"
            && f[3].fixed::<32>()? == request.digest()?,
        "search response belongs to another query"
    );
    let source = f[4].bytes()?;
    let found = matching(request, source)?;
    ensure!(
        f[5] == found.as_ref().map_or(V::Null, Match::value),
        "search response score or snippet differs from exact source"
    );
    Ok((source.to_vec(), found))
}
