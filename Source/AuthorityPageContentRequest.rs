// SPDX-License-Identifier: MIT
// Shared participant proofs bind content effects to the exact selected store and immutable placement.
use super::*;
impl Request {
    pub fn is_content(&self) -> bool {
        matches!(
            self.command(),
            Command::Content(content::Command::Authorise { .. })
        )
    }
    pub fn exchange_tag(&self) -> &'static str {
        if self.is_content() {
            "ContentExchange"
        } else {
            "MediaExchange"
        }
    }
    pub fn receipt_tag(&self) -> &'static str {
        if self.is_content() {
            "PageContentEffectReceipt"
        } else {
            "PageMediaEffectReceipt"
        }
    }
    pub fn completion_tag(&self) -> &'static str {
        if self.is_content() {
            "PageContentEffectComplete"
        } else {
            "PageMediaEffectComplete"
        }
    }
    pub fn result_content(
        &self,
        result: &OperationResult,
    ) -> Result<(HostProfile, content::Placement, Option<Revision>)> {
        let (_, _, state, _) = self.context(result)?;
        let Command::Content(content::Command::Authorise {
            placement,
            host,
            effect,
            ..
        }) = self.command()
        else {
            anyhow::bail!("request is not a finite content effect")
        };
        let record = state.record(content::PLACEMENT_KIND, placement.id)?;
        let selected = state.record(147, host.id)?;
        ensure!(
            record.reference == *placement && selected.reference == *host,
            "content result selected another placement or host"
        );
        let configured = Host::parse(
            &selected.payload,
            self.intent.network,
            self.intent.incarnation,
        )?;
        let placement = content::Placement::parse(&record.payload)?;
        ensure!(
            !configured.withdrawn
                && configured.profile.role == 1
                && configured.profile.content.is_some()
                && placement.hosts.contains(host),
            "content result is outside current hosting consent"
        );
        let revision = if *effect == content::Effect::Purge || placement.opaque {
            None
        } else {
            let record = state.record(141, placement.revision.id)?;
            ensure!(
                record.reference == placement.revision,
                "content revision differs"
            );
            Some(Revision::parse(
                &record.payload,
                self.intent.network,
                self.intent.incarnation,
            )?)
        };
        Ok((configured.profile, placement, revision))
    }
    pub(super) fn validate_content_response(
        &self,
        result: &OperationResult,
        bytes: &[u8],
    ) -> Result<()> {
        let (_, value, _) = self.result_content(result)?;
        let Command::Content(content::Command::Authorise {
            placement,
            host,
            effect,
            offset,
            bytes: count,
            digest,
        }) = self.command()
        else {
            unreachable!()
        };
        let response = wire::decode(bytes)?;
        let f = response.array(11)?;
        ensure!(
            f[0].uint()? == 201
                && f[1].uint()? == 1
                && f[2].text()? == "PageContentEffect"
                && version(&f[3])? == *placement
                && version(&f[4])? == *host
                && f[5].uint()? == effect.code()
                && f[6].uint()? == *offset
                && f[7].uint()? == *count,
            "content response changed its exact effect"
        );
        let payload = f[9].bytes()?;
        let hash = f[8].fixed::<32>()?;
        match effect {
            content::Effect::Upload | content::Effect::Repair => ensure!(
                payload.is_empty() && Some(hash) == *digest,
                "content upload response changed its signed chunk"
            ),
            content::Effect::Read | content::Effect::Inspect => {
                use sha2::{Digest as _, Sha256};
                ensure!(
                    payload.len() as u64 == *count
                        && hash == Digest::from(Sha256::digest(payload))
                        && f[10] != V::Null,
                    "content response lacks validated exact bytes"
                );
            }
            content::Effect::Purge => ensure!(
                payload.is_empty() && *count == 0 && f[10] == V::Null,
                "content purge response differs"
            ),
        }
        if f[10] != V::Null {
            let copy =
                content::Copy::parse(f[10].bytes()?, self.intent.network, self.intent.incarnation)?;
            ensure!(
                copy.placement == *placement
                    && copy.host == *host
                    && copy.digest == value.digest
                    && copy.bytes == value.bytes
                    && copy.expires_ms == value.expires_ms,
                "content receipt differs from complete placement"
            );
        }
        Ok(())
    }
}
