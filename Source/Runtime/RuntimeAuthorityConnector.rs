// SPDX-License-Identifier: MIT
// Local consent pins the remote authority connector's network and immutable public route.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Binding {
    format: String,
    network: String,
    incarnation: String,
    bootstrap_digest: String,
    target_digest: String,
}
impl Binding {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.format == "HyperNetAuthorityConnector/1",
            "unsupported authority connector binding"
        );
        for value in [
            &self.network,
            &self.incarnation,
            &self.bootstrap_digest,
            &self.target_digest,
        ] {
            let digest = crate::trust_bootstrap::hex32(value)?;
            ensure!(
                digest != [0; 32] && hex::encode(digest) == *value,
                "authority connector binding has an invalid digest"
            );
        }
        Ok(())
    }
    pub(super) fn check(&self, manifest: &Manifest) -> Result<()> {
        self.validate()?;
        ensure!(
            self.network == hex::encode(manifest.network)
                && self.incarnation == hex::encode(manifest.incarnation)
                && self.bootstrap_digest == hex::encode(manifest.bootstrap_digest),
            "authority connector differs from the accepted service network"
        );
        Ok(())
    }
    pub(super) fn read(path: &Path, manifest: &Manifest) -> Result<Self> {
        let inspected = mapped::inspect_host(path)?;
        let binding: Self = serde_json::from_value(inspected["binding"].clone())?;
        binding.check(manifest)?;
        ensure!(
            inspected["encoded"] == hex::encode(serde_json::to_vec(&binding)?),
            "authority connector binding is not canonical"
        );
        Ok(binding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_connector_binding_pins_network_and_rejects_unknown_fields() {
        let mut manifest = crate::authority_deployment_tests::manifest();
        let value = json!({"format":"HyperNetAuthorityConnector/1",
            "network":hex::encode(manifest.network),
            "incarnation":hex::encode(manifest.incarnation),
            "bootstrapDigest":hex::encode(manifest.bootstrap_digest),
            "targetDigest":hex::encode([31;32])});
        let binding: Binding = serde_json::from_value(value.clone()).unwrap();
        binding.check(&manifest).unwrap();
        manifest.bootstrap_digest = [18; 32];
        assert!(binding.check(&manifest).is_err());
        let mut unknown = value.clone();
        unknown["profile"] = json!("/private/profile");
        assert!(serde_json::from_value::<Binding>(unknown).is_err());
        let mut zero = value;
        zero["targetDigest"] = json!(hex::encode([0; 32]));
        assert!(
            serde_json::from_value::<Binding>(zero)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
