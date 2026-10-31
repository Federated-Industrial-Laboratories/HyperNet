// SPDX-License-Identifier: MIT
// Test fixtures and accessors in the owning module scope.
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
