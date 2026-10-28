// SPDX-License-Identifier: MIT
// The imported application mount retains its exact canonical binding and mapped owner.
use super::*;

pub fn validate_host(path: &Path, application: &Application) -> Result<()> {
    let result = crate::runtime_management::services::mapped::inspect_host(path)?;
    ensure!(
        result["encoded"] == hex::encode(application.binding.encode()?),
        "application ingress differs from exact local consent"
    );
    Ok(())
}
