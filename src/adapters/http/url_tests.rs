//! Destination parsing (design `http-target` §4.2): every malformed form is refused, and
//! the request URI is built from the parsed value. One behavioral assertion per test.

use super::*;

const HOST: &str = "central.zonetico.com";

#[test]
fn a_plain_base_url_is_parsed() {
    assert!(parse_base_url("https://central.zonetico.com", HOST).is_ok());
}

#[test]
fn userinfo_is_refused() {
    assert!(parse_base_url("https://user@central.zonetico.com", HOST).is_err());
}

#[test]
fn a_port_is_refused() {
    assert!(parse_base_url("https://central.zonetico.com:8443", HOST).is_err());
}

#[test]
fn a_query_is_refused() {
    assert!(parse_base_url("https://central.zonetico.com/api?a=b", HOST).is_err());
}

#[test]
fn a_fragment_is_refused() {
    assert!(parse_base_url("https://central.zonetico.com/api#x", HOST).is_err());
}

#[test]
fn the_http_scheme_is_refused() {
    assert!(parse_base_url("http://central.zonetico.com", HOST).is_err());
}

#[test]
fn an_ipv4_literal_is_refused() {
    assert!(parse_base_url("https://192.0.2.1", HOST).is_err());
}

#[test]
fn an_ipv6_literal_is_refused() {
    assert!(parse_base_url("https://[2001:db8::1]", HOST).is_err());
}

#[test]
fn an_upper_case_host_is_refused() {
    assert!(parse_base_url("https://Central.Zonetico.com", HOST).is_err());
}

#[test]
fn a_trailing_dot_in_the_host_is_refused() {
    assert!(parse_base_url("https://central.zonetico.com.", HOST).is_err());
}

#[test]
fn a_host_that_is_not_the_target_host_is_refused() {
    assert!(parse_base_url("https://staging.zonetico.com", HOST).is_err());
}

#[test]
fn a_bad_path_segment_is_refused() {
    assert!(parse_base_url("https://central.zonetico.com/a b", HOST).is_err());
}

#[test]
fn a_prefix_is_kept() {
    let d = parse_base_url("https://central.zonetico.com/api/v1", HOST).unwrap();
    assert_eq!(d.prefix, "/api/v1");
}

#[test]
fn the_uri_is_built_from_the_parsed_value() {
    let d = parse_base_url("https://central.zonetico.com/api", HOST).unwrap();
    assert_eq!(
        d.uri("/v1/connections"),
        "central.zonetico.com/api/v1/connections"
    );
}

#[test]
fn a_refusal_does_not_quote_the_input() {
    assert!(
        !parse_base_url("https://evil.example.com", HOST)
            .unwrap_err()
            .contains("evil.example.com")
    );
}
