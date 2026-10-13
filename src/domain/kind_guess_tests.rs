//! Behaviour of `kind_for_name`: one observable outcome per test.

use super::*;

// --- Exact config names -------------------------------------------------------

#[test]
fn config_when_name_is_exactly_port() {
    assert_eq!(kind_for_name("PORT"), Kind::Config);
}

#[test]
fn config_when_name_is_exactly_node_env() {
    assert_eq!(kind_for_name("NODE_ENV"), Kind::Config);
}

#[test]
fn config_when_name_is_exactly_log_level() {
    assert_eq!(kind_for_name("LOG_LEVEL"), Kind::Config);
}

#[test]
fn config_when_name_is_exactly_rust_log() {
    assert_eq!(kind_for_name("RUST_LOG"), Kind::Config);
}

#[test]
fn config_when_name_is_exactly_tz() {
    assert_eq!(kind_for_name("TZ"), Kind::Config);
}

// --- Config suffixes ----------------------------------------------------------

#[test]
fn config_when_name_ends_with_enabled() {
    assert_eq!(kind_for_name("FEATURE_ENABLED"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_disabled() {
    assert_eq!(kind_for_name("FEATURE_DISABLED"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_model() {
    assert_eq!(kind_for_name("CHAT_MODEL"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_port() {
    assert_eq!(kind_for_name("DB_PORT"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_origin() {
    assert_eq!(kind_for_name("ALLOWED_ORIGIN"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_bind() {
    assert_eq!(kind_for_name("SERVER_BIND"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_host() {
    assert_eq!(kind_for_name("DB_HOST"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_environment() {
    assert_eq!(kind_for_name("APP_ENVIRONMENT"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_env() {
    assert_eq!(kind_for_name("APP_ENV"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_region() {
    assert_eq!(kind_for_name("AWS_REGION"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_log_level() {
    assert_eq!(kind_for_name("APP_LOG_LEVEL"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_client_id() {
    assert_eq!(kind_for_name("OAUTH_CLIENT_ID"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_key_id() {
    assert_eq!(kind_for_name("SIGNING_KEY_ID"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_price_id() {
    assert_eq!(kind_for_name("STRIPE_PRICE_ID"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_account_id() {
    assert_eq!(kind_for_name("AWS_ACCOUNT_ID"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_project_id() {
    assert_eq!(kind_for_name("GCP_PROJECT_ID"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_redirect_uri() {
    assert_eq!(kind_for_name("OAUTH_REDIRECT_URI"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_issuer() {
    assert_eq!(kind_for_name("OIDC_ISSUER"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_audience() {
    assert_eq!(kind_for_name("OIDC_AUDIENCE"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_provider() {
    assert_eq!(kind_for_name("AUTH_PROVIDER"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_mode() {
    assert_eq!(kind_for_name("APP_MODE"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_timeout() {
    assert_eq!(kind_for_name("HTTP_TIMEOUT"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_ttl() {
    assert_eq!(kind_for_name("CACHE_TTL"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_domain() {
    assert_eq!(kind_for_name("COOKIE_DOMAIN"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_email() {
    assert_eq!(kind_for_name("SUPPORT_EMAIL"), Kind::Config);
}

#[test]
fn config_when_name_ends_with_from() {
    assert_eq!(kind_for_name("MAIL_FROM"), Kind::Config);
}

// --- Secret suffixes ----------------------------------------------------------

#[test]
fn secret_when_name_ends_with_url() {
    assert_eq!(kind_for_name("DATABASE_URL"), Kind::Secret);
}

#[test]
fn secret_for_stripe_webhook_url() {
    assert_eq!(kind_for_name("STRIPE_WEBHOOK_URL"), Kind::Secret);
}

#[test]
fn secret_when_name_ends_with_uri_other_than_redirect() {
    assert_eq!(kind_for_name("CALLBACK_URI"), Kind::Secret);
}

#[test]
fn secret_when_name_ends_with_key() {
    assert_eq!(kind_for_name("OPENROUTER_API_KEY"), Kind::Secret);
}

#[test]
fn secret_when_name_ends_with_secret() {
    assert_eq!(kind_for_name("APP_SECRET"), Kind::Secret);
}

#[test]
fn secret_when_name_ends_with_token() {
    assert_eq!(kind_for_name("BOT_TOKEN"), Kind::Secret);
}

#[test]
fn secret_when_name_ends_with_password() {
    assert_eq!(kind_for_name("DB_PASSWORD"), Kind::Secret);
}

#[test]
fn secret_when_name_ends_with_keys() {
    assert_eq!(kind_for_name("API_KEYS"), Kind::Secret);
}

// --- Always-secret words override config --------------------------------------

#[test]
fn secret_when_name_contains_secret_and_a_config_suffix() {
    assert_eq!(kind_for_name("CLIENT_SECRET_ID"), Kind::Secret);
}

#[test]
fn secret_when_name_contains_private_and_a_config_suffix() {
    assert_eq!(kind_for_name("PRIVATE_KEY_ID"), Kind::Secret);
}

#[test]
fn secret_when_name_contains_token_and_a_config_suffix() {
    assert_eq!(kind_for_name("TOKEN_ISSUER"), Kind::Secret);
}

#[test]
fn secret_when_name_contains_password_and_a_config_suffix() {
    assert_eq!(kind_for_name("PASSWORD_MODEL"), Kind::Secret);
}

#[test]
fn secret_when_name_contains_passwd_and_a_config_suffix() {
    assert_eq!(kind_for_name("PASSWD_MODE"), Kind::Secret);
}

#[test]
fn secret_when_name_contains_credential_and_a_config_suffix() {
    assert_eq!(kind_for_name("CREDENTIAL_PROVIDER"), Kind::Secret);
}

// --- Case sensitivity and safe default ----------------------------------------

#[test]
fn secret_when_name_is_lowercase_port() {
    assert_eq!(kind_for_name("port"), Kind::Secret);
}

#[test]
fn secret_when_name_is_mixed_case_log_level() {
    assert_eq!(kind_for_name("Log_Level"), Kind::Secret);
}

#[test]
fn secret_by_default_for_an_unknown_name() {
    assert_eq!(kind_for_name("SOMETHING_ELSE"), Kind::Secret);
}

#[test]
fn secret_for_the_empty_name() {
    assert_eq!(kind_for_name(""), Kind::Secret);
}

#[test]
fn secret_for_a_non_ascii_name() {
    assert_eq!(kind_for_name("ключ"), Kind::Secret);
}
