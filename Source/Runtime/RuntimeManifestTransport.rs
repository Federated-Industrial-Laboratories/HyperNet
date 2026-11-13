// SPDX-License-Identifier: MIT
// Certificate origins preserve the original resource digest across explicitly signed transport successors.
use super::*;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OriginalEndpoint {
    pub endpoint: Key,
    pub leaf_der: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Origin {
    pub endpoints: Vec<OriginalEndpoint>,
    pub authority_tls_digests: Option<[Key; 3]>,
    pub issuer_pem: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Certificates {
    pub origin: Origin,
    pub issuer_pem: String,
}

impl Certificates {
    pub fn validate(&self, manifest: &Manifest) -> Result<()> {
        ensure!(
            !manifest.endpoints.is_empty()
                && self.origin.endpoints.len() == manifest.endpoints.len(),
            "Certificate origin endpoint count differs"
        );
        let original_issuer = if self.origin.authority_tls_digests.is_some() {
            certificates::repeated_issuer_der(&self.origin.issuer_pem)?
        } else {
            certificates::der(&self.origin.issuer_pem)?
        };
        let current_issuer = certificates::der(&self.issuer_pem)?;
        certificates::issuer_successor(&original_issuer, &current_issuer)?;
        for (original, current) in self.origin.endpoints.iter().zip(&manifest.endpoints) {
            ensure!(
                original.endpoint == current.endpoint_id
                    && leaf_key(&original.leaf_der)? == current.transport_key,
                "Certificate origin changes endpoint or transport identity"
            );
            certificates::leaf_successor(
                &original.leaf_der,
                &current.leaf_der,
                &original_issuer,
                &current_issuer,
            )?;
        }
        match (
            &manifest.authority_config,
            self.origin.authority_tls_digests,
        ) {
            (Some(config), Some(original)) => {
                ensure!(
                    original.iter().all(|digest| *digest != [0; 32])
                        && original[2] == config.tls_file_digests[2]
                        && original[0]
                            == <[u8; 32]>::from(Sha256::digest(self.origin.issuer_pem.as_bytes()))
                        && config.tls_file_digests[0]
                            == <[u8; 32]>::from(Sha256::digest(self.issuer_pem.as_bytes())),
                    "Certificate successor changes private key or issuer pins"
                );
                let own = manifest
                    .endpoints
                    .iter()
                    .find(|e| manifest.roles[0].bind_endpoint_ids.contains(&e.endpoint_id))
                    .ok_or_else(|| anyhow::anyhow!("Authority certificate endpoint absent"))?;
                ensure!(
                    config.tls_file_digests[1]
                        == <[u8; 32]>::from(Sha256::digest(
                            certificates::pem(&own.leaf_der)?.as_bytes()
                        )),
                    "Authority successor leaf file pin differs"
                );
            }
            (None, None) => (),
            _ => anyhow::bail!("Certificate origin authority role changed"),
        }
        Ok(())
    }
    pub fn current(&self, manifest: &Manifest, at: u64) -> Result<()> {
        let issuer = certificates::der(&self.issuer_pem)?;
        for endpoint in &manifest.endpoints {
            certificates::current(&endpoint.leaf_der, &issuer, endpoint.address, at)?;
        }
        Ok(())
    }
    pub fn restore_origin(&self, manifest: &mut Manifest) {
        for (original, current) in self.origin.endpoints.iter().zip(&mut manifest.endpoints) {
            current.leaf_der = original.leaf_der.clone();
        }
        if let (Some(config), Some(original)) = (
            &mut manifest.authority_config,
            self.origin.authority_tls_digests,
        ) {
            config.tls_file_digests = original;
        }
        manifest.transport_certificates = None;
    }
    pub fn value(&self) -> V {
        let long_origin = self.origin.issuer_pem.len() > 1024;
        a([
            V::Uint(if long_origin { 2 } else { 1 }),
            a(self
                .origin
                .endpoints
                .iter()
                .map(|e| a([b(&e.endpoint), V::Bytes(e.leaf_der.clone())]))),
            self.origin
                .authority_tls_digests
                .as_ref()
                .map_or(V::Null, |digests| ids(digests)),
            if long_origin {
                V::Bytes(self.origin.issuer_pem.as_bytes().to_vec())
            } else {
                V::Text(self.origin.issuer_pem.clone())
            },
            V::Text(self.issuer_pem.clone()),
        ])
    }
    pub fn parse(value: &V) -> Result<Self> {
        let v = value.array(5)?;
        let issuer_pem = match v[0].uint()? {
            1 => {
                let text = v[3].text()?;
                ensure!(
                    text.len() <= 1024,
                    "Short certificate origin exceeds its bound"
                );
                text.to_owned()
            }
            2 => {
                let bytes = v[3].bytes()?;
                ensure!(
                    (1025..=65536).contains(&bytes.len()),
                    "Long certificate origin has a noncanonical length"
                );
                String::from_utf8(bytes.to_vec())?
            }
            _ => anyhow::bail!("Unsupported certificate successor schema"),
        };
        Ok(Self {
            origin: Origin {
                endpoints: v[1]
                    .list(16)?
                    .iter()
                    .map(|entry| {
                        let fields = entry.array(2)?;
                        Ok(OriginalEndpoint {
                            endpoint: key(&fields[0])?,
                            leaf_der: fields[1].bytes()?.to_vec(),
                        })
                    })
                    .collect::<Result<_>>()?,
                authority_tls_digests: if v[2] == V::Null {
                    None
                } else {
                    Some(
                        keys(&v[2])?
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("Three origin TLS pins required"))?,
                    )
                },
                issuer_pem,
            },
            issuer_pem: v[4].text()?.into(),
        })
    }
}

impl Manifest {
    pub fn transport_changed(&self, previous: &Self) -> bool {
        self.transport_certificates.as_ref().is_some_and(|current| {
            let old_issuer = previous
                .transport_certificates
                .as_ref()
                .map(|old| &old.issuer_pem)
                .unwrap_or(&current.origin.issuer_pem);
            self.endpoints != previous.endpoints || current.issuer_pem != *old_issuer
        })
    }
    pub fn transport_interval(&self) -> Result<Option<(u64, u64)>> {
        let Some(transport) = &self.transport_certificates else {
            return Ok(None);
        };
        let (mut start, mut end) =
            certificates::interval(&certificates::der(&transport.issuer_pem)?)?;
        for endpoint in &self.endpoints {
            let (before, after) = certificates::interval(&endpoint.leaf_der)?;
            start = start.max(before);
            end = end.min(after);
        }
        Ok(Some((
            start
                .checked_mul(1000)
                .ok_or_else(|| anyhow::anyhow!("Certificate time overflow"))?,
            end.checked_mul(1000)
                .ok_or_else(|| anyhow::anyhow!("Certificate time overflow"))?,
        )))
    }
    pub fn transport_expiry(&self) -> Result<Option<u64>> {
        Ok(self.transport_interval()?.map(|(_, end)| end))
    }
    pub fn current_transport(&self, at: u64) -> Result<()> {
        if let Some(transport) = &self.transport_certificates {
            transport.current(self, at)?;
        }
        Ok(())
    }
    pub fn adopt_certificates(
        &mut self,
        previous: &Self,
        issuer: String,
        leaves: &BTreeMap<Key, Vec<u8>>,
        original_issuer: String,
    ) -> Result<()> {
        ensure!(
            leaves.len() == self.endpoints.len() && !leaves.is_empty(),
            "Certificate bundle must replace every exact endpoint"
        );
        let origin = previous
            .transport_certificates
            .as_ref()
            .map(|c| c.origin.clone())
            .unwrap_or_else(|| Origin {
                endpoints: previous
                    .endpoints
                    .iter()
                    .map(|e| OriginalEndpoint {
                        endpoint: e.endpoint_id,
                        leaf_der: e.leaf_der.clone(),
                    })
                    .collect(),
                authority_tls_digests: previous
                    .authority_config
                    .as_ref()
                    .map(|c| c.tls_file_digests),
                issuer_pem: original_issuer,
            });
        if let Some(old) = &previous.transport_certificates {
            certificates::issuer_successor(
                &certificates::der(&old.issuer_pem)?,
                &certificates::der(&issuer)?,
            )?;
        }
        for endpoint in &mut self.endpoints {
            let leaf = leaves
                .get(&endpoint.endpoint_id)
                .ok_or_else(|| anyhow::anyhow!("Certificate endpoint absent"))?;
            endpoint.leaf_der = leaf.clone();
        }
        if let Some(config) = &mut self.authority_config {
            let own = self
                .endpoints
                .iter()
                .find(|e| self.roles[0].bind_endpoint_ids.contains(&e.endpoint_id))
                .ok_or_else(|| anyhow::anyhow!("Authority endpoint absent"))?;
            config.tls_file_digests[0] = Sha256::digest(issuer.as_bytes()).into();
            config.tls_file_digests[1] =
                Sha256::digest(certificates::pem(&own.leaf_der)?.as_bytes()).into();
        }
        self.transport_certificates = Some(Certificates {
            origin,
            issuer_pem: issuer,
        });
        self.successor_of(previous)
    }
}
