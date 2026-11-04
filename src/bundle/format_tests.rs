//! Behavioural tests for the `opv-sealed/1` codec (design sealed-target §5.1–§5.3, §10).
//! Each test asserts one observable outcome of the public codec; no value here is real.
//! Fixture names come from `tests/fixtures/sealed/downstream/shape.json` (names only).

use std::path::PathBuf;

use super::format::{
    Envelope, FormatError, Header, MAX_BUNDLE, MAX_HEADER, Name, Payload, canonical_header,
    contract_digest, decode_payload, encode_envelope, encode_payload, parse_envelope, parse_header,
};

/// A fixed placement whose canonical bytes and digest are locked by the tests below.
fn fixture_header() -> Header {
    Header {
        format: "opv-sealed/1".to_string(),
        project: "fleet".to_string(),
        environment: "prod-zonetico".to_string(),
        product: "zonetico".to_string(),
        target: "box".to_string(),
        revision: 42,
        created_at: "2026-01-02T03:04:05Z".to_string(),
        opv_version: "0.18.0".to_string(),
        plan_id: "plan_0000".to_string(),
        contract_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        recipients: vec!["sha256:1111111111111111".to_string()],
        signer: "SHA256:2222222222222222222222222222222222222222222".to_string(),
        names: vec![
            Name {
                name: "DATABASE_URL".to_string(),
                destination: "env:DATABASE_URL".to_string(),
            },
            Name {
                name: "GITHUB_APP_KEY".to_string(),
                destination: "file:github-app/private-key".to_string(),
            },
        ],
        secrets_dir_env: None,
    }
}

/// The exact canonical bytes of [`fixture_header`] (test 4).
const FIXTURE_HEADER: &[u8] = b"{\"contract_digest\":\"sha256:0000000000000000000000000000000000000000000000000000000000000000\",\"created_at\":\"2026-01-02T03:04:05Z\",\"environment\":\"prod-zonetico\",\"format\":\"opv-sealed/1\",\"names\":[{\"destination\":\"env:DATABASE_URL\",\"name\":\"DATABASE_URL\"},{\"destination\":\"file:github-app/private-key\",\"name\":\"GITHUB_APP_KEY\"}],\"opv_version\":\"0.18.0\",\"plan_id\":\"plan_0000\",\"product\":\"zonetico\",\"project\":\"fleet\",\"recipients\":[\"sha256:1111111111111111\"],\"revision\":42,\"signer\":\"SHA256:2222222222222222222222222222222222222222222\",\"target\":\"box\"}";

/// The contract digest of [`fixture_header`]'s placement (test 4).
const FIXTURE_CONTRACT_DIGEST: &str =
    "sha256:4f4e43c8d9f1fc6b912e4d448646e8f4dddaa8dd912d9b42c6c2db407e3485d2";

/// A minimal valid envelope around `age`/`signature` armor, with the fixed header.
fn fixture_envelope() -> Envelope {
    let data = encode_envelope(FIXTURE_HEADER, fixture_age(), fixture_signature()).expect("encode");
    parse_envelope(&data).expect("parse")
}

fn fixture_age() -> &'static [u8] {
    b"-----BEGIN AGE ENCRYPTED FILE-----\nZmFrZQ==\n-----END AGE ENCRYPTED FILE-----\n"
}

fn fixture_signature() -> &'static [u8] {
    b"-----BEGIN SSH SIGNATURE-----\nZmFrZQ==\n-----END SSH SIGNATURE-----\n"
}

fn shape() -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sealed/downstream/shape.json");
    serde_json::from_slice(&std::fs::read(path).expect("shape.json")).expect("shape.json json")
}

fn production_zonetico_names() -> Vec<String> {
    shape()["platforms"]["production"]["products"]["zonetico"]["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|k| k["name"].as_str().expect("name").to_string())
        .collect()
}

// --- test 4: the canonical header is a fixed, digestible value ---

#[test]
fn canonical_header_bytes_are_fixed() {
    assert_eq!(
        canonical_header(&fixture_header()).expect("canonical"),
        FIXTURE_HEADER
    );
}

#[test]
fn contract_digest_is_fixed() {
    let header = fixture_header();
    assert_eq!(
        contract_digest(
            &header.names,
            header.secrets_dir_env.as_deref(),
            &header.recipients,
            &header.signer,
        ),
        FIXTURE_CONTRACT_DIGEST
    );
}

#[test]
fn canonical_header_round_trips_through_parse() {
    assert_eq!(
        parse_header(FIXTURE_HEADER).expect("parse"),
        fixture_header()
    );
}

#[test]
fn header_that_does_not_re_serialize_is_refused() {
    let spaced = [b" ".as_slice(), FIXTURE_HEADER].concat();
    assert!(matches!(
        parse_header(&spaced),
        Err(FormatError::HeaderNotCanonical)
    ));
}

#[test]
fn unknown_header_field_is_refused() {
    let extra = br#"{"bogus":1,"contract_digest":"","created_at":"","environment":"","format":"opv-sealed/1","names":[],"opv_version":"","plan_id":"","product":"","project":"","recipients":[],"revision":0,"signer":"","target":""}"#;
    assert!(matches!(
        parse_header(extra),
        Err(FormatError::UnknownHeaderField)
    ));
}

#[test]
fn duplicate_header_key_is_refused() {
    let dup = br#"{"contract_digest":"a","contract_digest":"b","created_at":"","environment":"","format":"opv-sealed/1","names":[],"opv_version":"","plan_id":"","product":"","project":"","recipients":[],"revision":0,"signer":"","target":""}"#;
    assert!(matches!(
        parse_header(dup),
        Err(FormatError::DuplicateHeaderKey)
    ));
}

// --- test 6: the payload framing is fixed and round-trips every value shape ---

#[test]
fn payload_frames_to_fixed_bytes() {
    let framed = encode_payload(FIXTURE_HEADER, &[("DATABASE_URL", b"fake")]).expect("frame");
    assert_eq!(&framed[..], PAYLOAD_FIXTURE);
}

/// The exact framing of `DATABASE_URL -> "fake"` under [`FIXTURE_HEADER`] (test 6).
const PAYLOAD_FIXTURE: &[u8] = b"OPV-SEALED-PAYLOAD 1\n\x94\x79\x10\xea\x37\xb3\x1b\x4b\x10\x68\xbb\xe4\xfe\xd5\x7c\x4a\x60\xdf\x55\x10\xdb\x1b\x45\xe5\x6d\x18\xed\xf0\xb3\xad\x47\xe5\x00\x00\x00\x01\x00\x0cDATABASE_URL\x00\x00\x00\x04fakeEND\n";

#[test]
fn payload_round_trips_pem_binary_and_empty_values() {
    let entries: &[(&str, &[u8])] = &[
        ("PEM", b"-----BEGIN KEY-----\nZmFrZQ==\n-----END KEY-----\n"),
        ("BLOB", &[0, 1, 2, 255, 254]),
        ("EMPTY", b""),
    ];
    let names = names_of(entries);
    let framed = encode_payload(FIXTURE_HEADER, entries).expect("frame");
    assert_eq!(
        decode_payload(&names, FIXTURE_HEADER, &framed).expect("decode"),
        expected_entries(entries)
    );
}

fn names_of(entries: &[(&str, &[u8])]) -> Vec<Name> {
    entries
        .iter()
        .map(|(name, _)| Name {
            name: (*name).to_string(),
            destination: format!("env:{name}"),
        })
        .collect()
}

fn expected_entries(entries: &[(&str, &[u8])]) -> Payload {
    entries
        .iter()
        .map(|(name, value)| ((*name).to_string(), zeroize::Zeroizing::new(value.to_vec())))
        .collect()
}

#[test]
fn payload_digest_mismatch_is_refused() {
    let framed = encode_payload(b"header-a", &[("A", b"x")]).expect("frame");
    let names = [Name {
        name: "A".to_string(),
        destination: "env:A".to_string(),
    }];
    assert!(matches!(
        decode_payload(&names, b"header-b", &framed),
        Err(FormatError::PayloadDigestMismatch)
    ));
}

#[test]
fn op_prefixed_payload_name_is_refused() {
    assert!(matches!(
        encode_payload(FIXTURE_HEADER, &[("OP_SERVICE_ACCOUNT_TOKEN", b"x")]),
        Err(FormatError::OpName)
    ));
}

#[test]
fn value_over_one_mib_is_refused() {
    let big = vec![0u8; (1 << 20) + 1];
    assert!(matches!(
        encode_payload(FIXTURE_HEADER, &[("BIG", &big)]),
        Err(FormatError::ValueTooLarge)
    ));
}

#[test]
fn more_than_two_hundred_fifty_six_names_is_refused() {
    let names: Vec<String> = (0..257).map(|i| format!("K{i}")).collect();
    let entries: Vec<(&str, &[u8])> = names
        .iter()
        .map(|n| (n.as_str(), b"x".as_slice()))
        .collect();
    assert!(matches!(
        encode_payload(FIXTURE_HEADER, &entries),
        Err(FormatError::TooManyNames)
    ));
}

// --- envelope structure and line endings ---

#[test]
fn envelope_signature_covers_every_byte_before_it() {
    let envelope = fixture_envelope();
    let prefix = [super::format::FORMAT_LINE, FIXTURE_HEADER, b"\n"].concat();
    let prefix = [prefix.as_slice(), fixture_age()].concat();
    assert_eq!(envelope.signed, prefix);
}

#[test]
fn crlf_line_ending_is_refused() {
    let mut data =
        encode_envelope(FIXTURE_HEADER, fixture_age(), fixture_signature()).expect("encode");
    let first_lf = data.iter().position(|&byte| byte == b'\n').expect("LF");
    data.insert(first_lf, b'\r');
    assert!(matches!(
        parse_envelope(&data),
        Err(FormatError::CarriageReturn)
    ));
}

#[test]
fn envelope_without_signature_block_is_refused() {
    let data = [
        b"opv-sealed v1\n".as_slice(),
        FIXTURE_HEADER,
        b"\n",
        fixture_age(),
    ]
    .concat();
    assert!(matches!(
        parse_envelope(&data),
        Err(FormatError::NoSignatureBlock)
    ));
}

#[test]
fn envelope_with_a_second_header_is_refused() {
    let data = [
        b"opv-sealed v1\n".as_slice(),
        FIXTURE_HEADER,
        b"\n",
        FIXTURE_HEADER,
        b"\n",
        fixture_age(),
        fixture_signature(),
    ]
    .concat();
    assert!(matches!(
        parse_envelope(&data),
        Err(FormatError::SecondHeader)
    ));
}

#[test]
fn envelope_with_unknown_format_line_is_refused() {
    let data = [
        b"opv-sealed v2\n".as_slice(),
        FIXTURE_HEADER,
        b"\n",
        fixture_age(),
        fixture_signature(),
    ]
    .concat();
    assert!(matches!(
        parse_envelope(&data),
        Err(FormatError::UnknownFormatLine)
    ));
}

#[test]
fn header_over_sixty_four_kib_is_refused() {
    let big = vec![b'a'; MAX_HEADER + 1];
    assert!(matches!(
        parse_header(&big),
        Err(FormatError::HeaderTooLarge)
    ));
}

#[test]
fn bundle_over_eight_mib_is_refused() {
    let big = vec![b'a'; MAX_BUNDLE + 1];
    assert!(matches!(
        parse_envelope(&big),
        Err(FormatError::BundleTooLarge)
    ));
}

// --- the file path rule (T6) ---

#[test]
fn file_path_with_dotdot_is_refused() {
    assert!(matches!(
        super::format::check_file_path("../x"),
        Err(FormatError::BadFilePath(_))
    ));
}

#[test]
fn absolute_file_path_is_refused() {
    assert!(matches!(
        super::format::check_file_path("/etc/passwd"),
        Err(FormatError::BadFilePath(_))
    ));
}

#[test]
fn file_path_with_nul_is_refused() {
    assert!(matches!(
        super::format::check_file_path("a\0b"),
        Err(FormatError::BadFilePath(_))
    ));
}

#[test]
fn file_path_with_backslash_is_refused() {
    assert!(matches!(
        super::format::check_file_path("a\\b"),
        Err(FormatError::BadFilePath(_))
    ));
}

#[test]
fn destination_with_unknown_prefix_is_refused() {
    assert!(matches!(
        super::format::check_destination("box:name"),
        Err(FormatError::BadDestination(_))
    ));
}

// --- the downstream shape (39 names, 35 characters, multi-line PEM/JSON) ---

#[test]
fn thirty_nine_name_scope_round_trips() {
    let names = production_zonetico_names();
    assert_eq!(payload_name_round_trip(&names).len(), 39);
}

#[test]
fn thirty_five_character_name_round_trips() {
    let names = vec!["PORTAL_GATEWAY_ACCESS_CLIENT_SECRET".to_string()];
    assert_eq!(payload_name_round_trip(&names), names);
}

#[test]
fn multi_line_pem_value_round_trips() {
    let framed = encode_payload(
        FIXTURE_HEADER,
        &[(
            "PEM",
            b"-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n",
        )],
    )
    .expect("frame");
    let header_names = names_of(&[("PEM", b"x")]);
    let decoded = decode_payload(&header_names, FIXTURE_HEADER, &framed).expect("decode");
    assert_eq!(
        decoded[0].1.as_slice(),
        b"-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n"
    );
}

#[test]
fn multi_line_json_value_round_trips() {
    let framed =
        encode_payload(FIXTURE_HEADER, &[("JSON", br#"{"a":"fake","b":[1,2,3]}"#)]).expect("frame");
    let header_names = names_of(&[("JSON", b"x")]);
    let decoded = decode_payload(&header_names, FIXTURE_HEADER, &framed).expect("decode");
    assert_eq!(decoded[0].1.as_slice(), br#"{"a":"fake","b":[1,2,3]}"#);
}

fn payload_name_round_trip(names: &[String]) -> Vec<String> {
    let entries: Vec<(&str, &[u8])> = names
        .iter()
        .map(|n| (n.as_str(), b"fake".as_slice()))
        .collect();
    let header_names = names_of(&entries);
    let framed = encode_payload(FIXTURE_HEADER, &entries).expect("frame");
    decode_payload(&header_names, FIXTURE_HEADER, &framed)
        .expect("decode")
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}
