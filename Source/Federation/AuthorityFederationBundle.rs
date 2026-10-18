// SPDX-License-Identifier: MIT
// Direct body transfers reconstruct exact bundles from independently verified source metadata.
use super::*;
impl ForeignProof {
    pub fn exported_publication(&self) -> Result<(page::Revision, page::Review)> {
        let (_, metadata) = self.exported_share_metadata()?;
        let (_, native) = self.exported_revision()?;
        let intent = self.intent()?;
        let result = authority::OperationResult::parse(&self.result)?;
        let value = wire::decode(&result.value)?;
        let body = value.array(5)?[4].array(4)?;
        let mut review = None;
        for bytes in body[1].list(MAXIMUM_CONTEXT_RECORDS)? {
            let record = Record::parse(bytes.bytes()?, intent.network, intent.incarnation)?;
            if record.reference.kind == 142 && record.reference.id == native.id {
                ensure!(review.is_none(), "source approval repeats");
                let parsed =
                    page::Review::parse(&record.payload, intent.network, intent.incarnation)?;
                ensure!(
                    parsed.statement.approve
                        && parsed.statement.revision == native
                        && parsed.statement.author == metadata.author.intent.requester
                        && parsed.statement.author_statement == metadata.author.intent.digest
                        && parsed.statement.source == metadata.author.source,
                    "source approval differs from exact author metadata"
                );
                review = Some(parsed);
            }
        }
        Ok((
            metadata,
            review.context("source Export omitted its exact approval")?,
        ))
    }
    pub fn rebuild_bundle(&self, source: &[u8]) -> Result<page::objects::Bundle> {
        let (metadata, review) = self.exported_publication()?;
        metadata.verify_source(source)?;
        let bytes =
            page::objects::Bundle::encode(source, &metadata.author.bytes, &review.statement.bytes)?;
        review
            .bundle
            .context("source approval has no bundle reference")?
            .verify(&bytes)?;
        page::objects::Bundle::parse(
            &bytes,
            metadata.author.intent.network,
            metadata.author.intent.incarnation,
        )
    }
}
