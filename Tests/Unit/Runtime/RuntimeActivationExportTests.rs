// SPDX-License-Identifier: MIT
// Optional receipt exports distinguish a missing final entry from malformed or unsafe retained evidence.
use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
#[test]
fn optional_activation_receipt_reports_only_genuine_absence() {
    let root = std::env::temp_dir().join(format!("hypernet-receipt-{}", crate::random_hex::<16>()));
    crate::authority_files::create_directory(&root).unwrap();
    let path = root.join("ActivationReceipt.cbor");
    let result = (|| -> Result<()> {
        assert!(receipt_bytes(&path, true)?.is_none());
        assert!(receipt_bytes(&path, false).is_err());
        assert!(receipt_bytes(&root.join("Missing/ActivationReceipt.cbor"), true).is_err());
        std::fs::write(&path, b"malformed receipt")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert!(receipt_bytes(&path, true).is_err());
        std::fs::write(&path, [])?;
        assert!(receipt_bytes(&path, true).is_err());
        use crate::trust_wire::{self as wire, Value as V};
        // Export forwards the same canonical historical wrapper as strict mode; proof verification is a separate operation.
        let mut fields = vec![
            V::Uint(200),
            V::Uint(1),
            V::Text("RuntimeActivationReceipt".into()),
        ];
        fields.extend(vec![V::Null; 9]);
        let bytes = wire::encode_state(&V::Array(fields))?;
        std::fs::write(&path, &bytes)?;
        assert_eq!(receipt_bytes(&path, true)?.unwrap(), bytes);
        assert_eq!(receipt_bytes(&path, false)?.unwrap(), bytes);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        assert!(receipt_bytes(&path, true).is_err());
        std::fs::remove_file(&path)?;
        symlink(root.join("Absent.cbor"), &path)?;
        assert!(receipt_bytes(&path, true).is_err());
        Ok(())
    })();
    std::fs::remove_dir_all(root).unwrap();
    result.unwrap();
}
