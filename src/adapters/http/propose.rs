//! The `http` section generated from an application's descriptor set (design `http-target`
//! §7): `opv propose target <env> <name> --provider http --http-descriptor <file>
//! --http-service <full.name>`. Deterministic: the same descriptor always yields
//! byte-identical text. No network call; the result passes the same load rules as
//! hand-written configuration.

/// The TOML lines of an `http` target section for `service` in the descriptor set
/// `descriptor` (read from `descriptor_path`, which the section names), or why not. Never a
/// value: a descriptor holds names, numbers and types only.
pub fn section(descriptor: &[u8], descriptor_path: &str, service: &str) -> Result<String, String> {
    let _ = (descriptor, descriptor_path, service);
    Err("the http section generator is not built yet".to_string())
}
