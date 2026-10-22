//! Descriptor loading and pinning (design `http-target` §3.2, §5.1).
//!
//! The configuration pins the descriptor set by its sha256, so a renumbered or replaced
//! field can never receive the value silently. Every named method must exist in the loaded
//! pool; the codec reads replies through it, never through JSON.

use prost_reflect::{DescriptorPool, MethodDescriptor};
use sha2::{Digest, Sha256};

/// Load the pinned `FileDescriptorSet` in `bytes`, refusing anything whose sha256 is not
/// `sha256_hex` (the configuration's `descriptor_sha256`). The error names the rule, never
/// the file's bytes.
pub fn load(bytes: &[u8], sha256_hex: &str) -> Result<DescriptorPool, String> {
    let actual = hex::encode(Sha256::digest(bytes));
    if !actual.eq_ignore_ascii_case(sha256_hex) {
        return Err("descriptor_sha256 does not match the descriptor file".to_string());
    }
    DescriptorPool::decode(bytes).map_err(|e| format!("descriptor could not be read: {e}"))
}

/// The method named `"pkg.Service/Method"` in `pool`, if both the service and the method
/// exist.
pub fn method(pool: &DescriptorPool, name: &str) -> Option<MethodDescriptor> {
    let (service, method) = name.split_once('/')?;
    pool.get_service_by_name(service)?
        .methods()
        .find(|m| m.name() == method)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_refuses_a_descriptor_whose_hash_does_not_match() {
        assert!(load(b"not the pinned descriptor", &"00".repeat(32)).is_err());
    }
}
