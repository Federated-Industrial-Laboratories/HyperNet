// SPDX-License-Identifier: MIT
// Static assets cross only explicitly pinned federation media routes.
use super::{BridgeMediaEndpoint, Connection, fixed_hex, now, read_bounded};
use crate::{mail_authority, media_types as media, types};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Configuration {
    pub network: String,
    pub host_key: String,
    pub ca_certificate: PathBuf,
    pub relay_address: SocketAddr,
}
pub(super) struct Route {
    pub endpoint: BridgeMediaEndpoint,
    pub relay: SocketAddr,
    client: reqwest::Client,
}
impl Route {
    pub fn new(raw: Configuration, endpoint: BridgeMediaEndpoint) -> Result<Self> {
        let ca = read_bounded(&raw.ca_certificate, 65536)?;
        ensure!(
            hex::encode(Sha256::digest(&ca)) == endpoint.ca_digest,
            "media CA differs from consent"
        );
        ensure!(
            raw.network == endpoint.network
                && raw.host_key == endpoint.host_key
                && raw.relay_address.port() == endpoint.address.port()
                && !raw.relay_address.ip().is_loopback()
                && !raw.relay_address.ip().is_unspecified()
                && !raw.relay_address.ip().is_multicast(),
            "media relay differs from consent"
        );
        let url = reqwest::Url::parse(&endpoint.endpoint)?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .tls_built_in_root_certs(false)
            .use_preconfigured_tls(crate::media_tls::config(&ca, &endpoint.certificate_digest)?)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .max_tls_version(reqwest::tls::Version::TLS_1_3)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(1))
            .resolve(url.host_str().context("media TLS name")?, raw.relay_address)
            .build()?;
        Ok(Self {
            endpoint,
            relay: raw.relay_address,
            client,
        })
    }
    pub async fn execute(
        &self,
        connection: &Connection,
        op: &media::Operation,
        payload: Option<&[u8]>,
    ) -> Result<(types::Envelope, Option<Vec<u8>>)> {
        let object = mail_authority::sign(
            media::OPERATION,
            &connection.configuration.network,
            op,
            &connection.key,
        )
        .map_err(anyhow::Error::msg)?;
        let response=self.client.post(reqwest::Url::parse(&self.endpoint.endpoint)?.join("V1/PageMedia")?)
            .json(&serde_json::json!({"operation":object,"payload":payload.map(|p|URL_SAFE_NO_PAD.encode(p))})).send().await?;
        ensure!(
            response.status().is_success(),
            "media host refused operation"
        );
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= media::MAX_REQUEST,
                "media reply exceeds bound"
            );
            bytes.extend_from_slice(&chunk);
        }
        let reply: types::Reply = serde_json::from_slice(&bytes)?;
        ensure!(reply.ok, "media operation denied");
        let envelope: types::Envelope = serde_json::from_value(reply.result["receipt"].clone())?;
        ensure!(
            envelope.public_key == self.endpoint.host_key,
            "wrong media receipt signer"
        );
        let receipt: media::StoreReceipt =
            mail_authority::verify(media::RECEIPT, &envelope, &op.network)
                .map_err(anyhow::Error::msg)?;
        ensure!(
            receipt.version == 1
                && receipt.network == op.network
                && receipt.host_key == op.host_key
                && receipt.agreement_id == op.agreement_id
                && receipt.page_id == op.page_id
                && receipt.revision == op.revision
                && receipt.asset_id == op.asset_id
                && receipt.source_digest == op.source_digest
                && receipt.action == op.action
                && receipt.requester_key == hex::encode(connection.key.verifying_key().as_bytes())
                && receipt.recorded_at <= now()?.saturating_add(2),
            "media receipt differs from operation"
        );
        fixed_hex::<32>(&receipt.digest)?;
        let payload = reply.result["payload"]
            .as_str()
            .map(|s| URL_SAFE_NO_PAD.decode(s))
            .transpose()?;
        if let Some(bytes) = &payload {
            ensure!(
                bytes.len() as u64 == op.chunk_bytes,
                "media chunk size differs"
            );
        }
        Ok((envelope, payload))
    }
}
