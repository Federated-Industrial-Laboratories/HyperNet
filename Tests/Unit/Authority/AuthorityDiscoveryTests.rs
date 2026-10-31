// SPDX-License-Identifier: MIT
// Page boundaries include their wire wrapper and preserve the complete record sequence.
use super::*;

#[test]
fn context_page_count_and_encoded_receipt_bounds_preserve_all_records() {
    for width in [128, 2500] {
        let records = (1u8..=140).map(|n| vec![n; width]).collect::<Vec<_>>();
        let refs = records
            .iter()
            .enumerate()
            .map(|(n, bytes)| VersionRef {
                kind: 102,
                id: [n as u8 + 1; 32],
                generation: 1,
                digest: wire::digest(bytes),
            })
            .collect::<Vec<_>>();
        let mut start = 0;
        let mut assembled = Vec::new();
        while start < records.len() {
            let page = context_page(&[1; 32], &refs, &records, start)
                .unwrap()
                .unwrap();
            let f = page.array(5).unwrap();
            let body = f[4].array(5).unwrap();
            let selected = body[4].list(64).unwrap();
            assert_eq!(body[2].uint().unwrap() as usize, start);
            let encoded = wire::encode(&array(vec![
                V::Uint(24),
                V::Uint(1),
                V::Text("AuthorityContext".into()),
                V::Uint(0),
                V::Uint(0),
                b(&wire::encode(&page).unwrap()),
            ]))
            .unwrap();
            assert!(encoded.len() <= 32768);
            if width == 128 {
                assert_eq!(selected.len(), (records.len() - start).min(64));
            } else {
                assert!(selected.len() < 64);
            }
            assembled.extend(selected.iter().map(|v| v.bytes().unwrap().to_vec()));
            start += selected.len();
            assert_eq!(
                body[3],
                if start == records.len() {
                    V::Null
                } else {
                    V::Uint(start as u64)
                }
            );
        }
        assert_eq!(assembled, records);
    }
}

#[test]
fn an_oversized_record_refuses_instead_of_emitting_an_empty_continuation() {
    let bytes = vec![1; 32768];
    let refs = [VersionRef {
        kind: 102,
        id: [2; 32],
        generation: 1,
        digest: wire::digest(&bytes),
    }];
    assert!(
        context_page(&[3; 32], &refs, &[bytes], 0)
            .unwrap()
            .is_none()
    );
}
