use tonic::transport::Channel;
use url::Url;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, Empty, LightdInfo,
};

use crate::{
    error::{ZeckError, ZeckResult},
    models::{LightwalletdProbe, ZeckNetwork},
};

const MAINNET_SAPLING_ACTIVATION: u64 = 419_200;
const TESTNET_SAPLING_ACTIVATION: u64 = 280_000;

/// Whether a lightwalletd error string looks like a *transient* network failure
/// worth retrying — a transport/stream drop **or** a DNS-resolution failure — as
/// opposed to a configuration or network-validation error that won't improve by
/// waiting.
///
/// Matching is by lowercased substring because the underlying tonic/hyper/std
/// errors don't expose a stable typed cause and their wording (especially for
/// DNS) varies by platform resolver. Used by both the mid-sync reconnect loop
/// and the startup connect retry so the two agree on what is retryable.
pub(crate) fn is_transient_network_error(msg: &str) -> bool {
    let msg = msg.to_ascii_lowercase();
    // Lowercased tokens. The transport set preserves the previous matcher's
    // behaviour (e.g. "GoAway" -> "goaway", "UnexpectedEof" -> "unexpectedeof").
    const TOKENS: &[&str] = &[
        // transport / stream drops
        "transport error",
        "h2 protocol error",
        "goaway",
        "timedout",
        "close_notify",
        "unexpectedeof",
        "connection refused",
        "connection reset",
        "broken pipe",
        // A batch that never committed within its budget. Retrying reconnects
        // and restarts the batch, which is the right move for a hung stream
        // and harmless (if wasteful) for a merely slow one.
        "scan stalled",
        // DNS resolution failures (resolver wording differs across OSes)
        "dns error",
        "failed to lookup address",
        "name resolution",
        "temporary failure in name resolution",
        "no such host",
        "nodename nor servname",
        "name or service not known",
    ];
    TOKENS.iter().any(|token| msg.contains(token))
}

pub fn parse_lightwalletd_endpoints(raw: &str) -> Vec<String> {
    let mut endpoints = Vec::new();
    for endpoint in raw
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !endpoints.iter().any(|existing| existing == endpoint) {
            endpoints.push(endpoint.to_owned());
        }
    }
    endpoints
}

pub fn prioritized_lightwalletd_endpoints(raw: &str, preferred: Option<&str>) -> Vec<String> {
    let mut endpoints = parse_lightwalletd_endpoints(raw);
    if let Some(preferred) = preferred.map(str::trim).filter(|value| !value.is_empty()) {
        if let Some(index) = endpoints.iter().position(|endpoint| endpoint == preferred) {
            let preferred = endpoints.remove(index);
            endpoints.insert(0, preferred);
        } else {
            endpoints.insert(0, preferred.to_owned());
        }
    }
    endpoints
}

pub fn validated_lightwalletd_endpoints(raw: &str) -> ZeckResult<Vec<String>> {
    let endpoints = parse_lightwalletd_endpoints(raw);
    if endpoints.is_empty() {
        return Err(ZeckError::InvalidConfig(
            "at least one lightwalletd endpoint is required".to_owned(),
        ));
    }

    endpoints
        .into_iter()
        .map(|endpoint| validate_lightwalletd_endpoint(&endpoint))
        .collect()
}

pub async fn connect_lightwalletd_endpoints(
    raw: &str,
    preferred: Option<&str>,
) -> ZeckResult<(CompactTxStreamerClient<Channel>, String)> {
    let mut endpoints = validated_lightwalletd_endpoints(raw)?;
    if let Some(preferred) = preferred.map(str::trim).filter(|value| !value.is_empty()) {
        let preferred = validate_lightwalletd_endpoint(preferred)?;
        if let Some(index) = endpoints.iter().position(|endpoint| endpoint == &preferred) {
            let preferred = endpoints.remove(index);
            endpoints.insert(0, preferred);
        } else {
            endpoints.insert(0, preferred);
        }
    }

    let mut errors = Vec::new();
    for endpoint in endpoints {
        match CompactTxStreamerClient::connect(endpoint.clone()).await {
            Ok(client) => return Ok((client, endpoint)),
            Err(err) => errors.push(format!("{endpoint}: {err}")),
        }
    }

    Err(ZeckError::Lightwalletd(format!(
        "failed to connect to any configured lightwalletd endpoint: {}",
        errors.join(" | ")
    )))
}

pub async fn probe_lightwalletd_endpoints(
    raw: &str,
) -> ZeckResult<(CompactTxStreamerClient<Channel>, String, LightdInfo)> {
    let endpoints = validated_lightwalletd_endpoints(raw)?;

    let mut errors = Vec::new();
    for endpoint in endpoints {
        match CompactTxStreamerClient::connect(endpoint.clone()).await {
            Ok(mut client) => match client.get_lightd_info(Empty {}).await {
                Ok(response) => return Ok((client, endpoint, response.into_inner())),
                Err(err) => errors.push(format!("{endpoint}: {err}")),
            },
            Err(err) => errors.push(format!("{endpoint}: {err}")),
        }
    }

    Err(ZeckError::Lightwalletd(format!(
        "all configured lightwalletd endpoints failed probing: {}",
        errors.join(" | ")
    )))
}

/// Attempts for an initial connect/probe before giving up, so a transient
/// DNS/network blip at startup doesn't fail an operation before it begins.
const INITIAL_CONNECT_ATTEMPTS: u32 = 4;
const INITIAL_CONNECT_RETRY_DELAY_SECS: u64 = 5;

/// [`probe_lightwalletd_endpoints`] with bounded retry on transient
/// (transport/DNS) failures — see [`is_transient_network_error`]. A
/// configuration/validation error is returned immediately (not retried).
pub async fn probe_lightwalletd_endpoints_with_retry(
    raw: &str,
) -> ZeckResult<(CompactTxStreamerClient<Channel>, String, LightdInfo)> {
    let mut attempt = 1u32;
    loop {
        match probe_lightwalletd_endpoints(raw).await {
            Ok(ready) => return Ok(ready),
            Err(err) if attempt < INITIAL_CONNECT_ATTEMPTS
                && is_transient_network_error(&err.to_string()) =>
            {
                attempt += 1;
                tokio::time::sleep(std::time::Duration::from_secs(
                    INITIAL_CONNECT_RETRY_DELAY_SECS,
                ))
                .await;
            }
            Err(err) => return Err(err),
        }
    }
}

/// [`connect_lightwalletd_endpoints`] with bounded retry on transient
/// (transport/DNS) failures — see [`is_transient_network_error`].
pub async fn connect_lightwalletd_endpoints_with_retry(
    raw: &str,
    preferred: Option<&str>,
) -> ZeckResult<(CompactTxStreamerClient<Channel>, String)> {
    let mut attempt = 1u32;
    loop {
        match connect_lightwalletd_endpoints(raw, preferred).await {
            Ok(ready) => return Ok(ready),
            Err(err) if attempt < INITIAL_CONNECT_ATTEMPTS
                && is_transient_network_error(&err.to_string()) =>
            {
                attempt += 1;
                tokio::time::sleep(std::time::Duration::from_secs(
                    INITIAL_CONNECT_RETRY_DELAY_SECS,
                ))
                .await;
            }
            Err(err) => return Err(err),
        }
    }
}

pub fn describe_lightwalletd_endpoints(raw: &str) -> String {
    let endpoints = parse_lightwalletd_endpoints(raw);
    match endpoints.as_slice() {
        [] => "no configured endpoints".to_owned(),
        [endpoint] => endpoint.clone(),
        _ => format!("{} endpoints ({})", endpoints.len(), endpoints.join(", ")),
    }
}

pub fn build_probe(endpoint: String, info: &LightdInfo) -> LightwalletdProbe {
    LightwalletdProbe {
        endpoint,
        vendor: Some(info.vendor.clone()),
        chain_name: Some(info.chain_name.clone()),
        latest_block_height: Some(info.block_height),
        sapling_activation_height: Some(info.sapling_activation_height),
    }
}

pub fn validate_lightwalletd_network(network: ZeckNetwork, info: &LightdInfo) -> ZeckResult<()> {
    let chain_name = info.chain_name.trim().to_ascii_lowercase();
    let chain_matches = match network {
        ZeckNetwork::Mainnet => matches!(chain_name.as_str(), "main" | "mainnet"),
        // When the `argos-network` feature is enabled, accept the regtest
        // chain name as a synonym for testnet so the C2 integration tests
        // in tests/regtest_integration.rs can scan a local Argos-network
        // (zcashd-regtest) stack. Production builds compile this branch
        // out — a hostile mainnet lightwalletd cannot claim to be regtest
        // to bypass network validation in a released Argos binary.
        ZeckNetwork::Testnet => {
            #[cfg(feature = "argos-network")]
            {
                matches!(chain_name.as_str(), "test" | "testnet" | "regtest")
            }
            #[cfg(not(feature = "argos-network"))]
            {
                matches!(chain_name.as_str(), "test" | "testnet")
            }
        }
    };
    if !chain_matches {
        return Err(ZeckError::Lightwalletd(format!(
            "server chain '{}' does not match selected {} network",
            info.chain_name,
            network.label()
        )));
    }

    // Skip the Sapling-activation-height check when the server identifies
    // itself as regtest: regtest activates Sapling at height 1 (via the
    // `nuparams=sapling:1` style config in tests/regtest/zcashd-regtest.conf),
    // which deliberately differs from public testnet's 280 000. Gated on
    // the feature so a non-argos-network build still enforces the testnet
    // activation height even if the chain name match relaxed somehow.
    #[cfg(feature = "argos-network")]
    let skip_sapling_check =
        matches!(network, ZeckNetwork::Testnet) && chain_name == "regtest";
    #[cfg(not(feature = "argos-network"))]
    let skip_sapling_check = false;

    if !skip_sapling_check {
        let expected_activation = match network {
            ZeckNetwork::Mainnet => MAINNET_SAPLING_ACTIVATION,
            ZeckNetwork::Testnet => TESTNET_SAPLING_ACTIVATION,
        };
        // Real lightwalletd servers always report the expected nonzero
        // Sapling activation height. A reported height of 0 is rejected
        // outright so a malicious or broken server cannot use it to bypass
        // the height comparison below (audit Suggestion 5).
        if info.sapling_activation_height != expected_activation {
            return Err(ZeckError::Lightwalletd(format!(
                "server Sapling activation height {} does not match expected {} for {}",
                info.sapling_activation_height,
                expected_activation,
                network.label()
            )));
        }
    }

    Ok(())
}

fn validate_lightwalletd_endpoint(endpoint: &str) -> ZeckResult<String> {
    let url = Url::parse(endpoint).map_err(|err| {
        ZeckError::InvalidConfig(format!("invalid lightwalletd endpoint '{endpoint}': {err}"))
    })?;
    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host(url.host_str()) => {}
        "http" => {
            return Err(ZeckError::InvalidConfig(format!(
                "lightwalletd endpoint '{endpoint}' must use https unless it targets localhost"
            )));
        }
        scheme => {
            return Err(ZeckError::InvalidConfig(format!(
                "lightwalletd endpoint '{endpoint}' uses unsupported scheme '{scheme}'"
            )));
        }
    }

    Ok(endpoint.to_owned())
}

fn is_loopback_host(host: Option<&str>) -> bool {
    host.map(|host| {
        let host = host.to_ascii_lowercase();
        // `url::Url::host_str()` returns IPv6 addresses inside brackets
        // (e.g. `[::1]` for `http://[::1]:9067`), so both forms must be
        // recognised as loopback. RFC 6761 .localhost subdomains are also
        // loopback by convention.
        host == "localhost"
            || host == "127.0.0.1"
            || host == "::1"
            || host == "[::1]"
            || host.ends_with(".localhost")
    })
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{
        describe_lightwalletd_endpoints, parse_lightwalletd_endpoints,
        prioritized_lightwalletd_endpoints, validate_lightwalletd_network,
        validated_lightwalletd_endpoints, TESTNET_SAPLING_ACTIVATION,
    };
    use crate::models::ZeckNetwork;
    use zcash_client_backend::proto::service::LightdInfo;

    #[test]
    fn parse_endpoints_splits_and_deduplicates() {
        let endpoints = parse_lightwalletd_endpoints(
            "https://one.test:9067, https://two.test:9067\nhttps://one.test:9067",
        );

        assert_eq!(
            endpoints,
            vec![
                "https://one.test:9067".to_owned(),
                "https://two.test:9067".to_owned()
            ]
        );
    }

    #[test]
    fn preferred_endpoint_is_prioritized() {
        let endpoints = prioritized_lightwalletd_endpoints(
            "https://one.test:9067,https://two.test:9067",
            Some("https://two.test:9067"),
        );

        assert_eq!(endpoints[0], "https://two.test:9067");
        assert_eq!(endpoints[1], "https://one.test:9067");
    }

    #[test]
    fn describe_empty_returns_sentinel() {
        assert_eq!(describe_lightwalletd_endpoints(""), "no configured endpoints");
    }

    #[test]
    fn describe_single_endpoint_returns_it_verbatim() {
        assert_eq!(
            describe_lightwalletd_endpoints("https://zec.rocks:443"),
            "https://zec.rocks:443"
        );
    }

    #[test]
    fn describe_multiple_endpoints_includes_count() {
        let desc = describe_lightwalletd_endpoints(
            "https://one.test:9067,https://two.test:9067,https://three.test:9067",
        );
        assert!(desc.starts_with("3 endpoints"), "got: {desc}");
        assert!(desc.contains("https://one.test:9067"));
    }

    #[test]
    fn preferred_endpoint_not_in_list_is_prepended() {
        let endpoints = prioritized_lightwalletd_endpoints(
            "https://one.test:9067",
            Some("https://preferred.test:9067"),
        );
        assert_eq!(endpoints[0], "https://preferred.test:9067");
        assert_eq!(endpoints[1], "https://one.test:9067");
    }

    #[test]
    fn empty_preferred_is_ignored() {
        let endpoints = prioritized_lightwalletd_endpoints(
            "https://one.test:9067,https://two.test:9067",
            Some("  "),
        );
        assert_eq!(endpoints[0], "https://one.test:9067");
        assert_eq!(endpoints.len(), 2);
    }

    #[test]
    fn endpoint_validation_rejects_remote_plaintext_http() {
        let err = validated_lightwalletd_endpoints("http://wallet.example:9067")
            .expect_err("remote http should be rejected");

        assert!(err.to_string().contains("must use https"));
    }

    #[test]
    fn endpoint_validation_allows_loopback_http_for_local_testing() {
        let endpoints = validated_lightwalletd_endpoints("http://127.0.0.1:9067")
            .expect("loopback http should be allowed");

        assert_eq!(endpoints, vec!["http://127.0.0.1:9067".to_owned()]);
    }

    #[test]
    fn network_validation_rejects_wrong_chain() {
        let info = LightdInfo {
            chain_name: "test".to_owned(),
            sapling_activation_height: TESTNET_SAPLING_ACTIVATION,
            ..LightdInfo::default()
        };
        let err = validate_lightwalletd_network(ZeckNetwork::Mainnet, &info)
            .expect_err("wrong chain should be rejected");

        assert!(err.to_string().contains("does not match selected mainnet"));
    }

    #[test]
    fn network_validation_rejects_zero_sapling_activation_height() {
        // A server reporting a Sapling activation height of 0 must be
        // rejected: real servers always report the expected nonzero value,
        // and allowing 0 would let a hostile server bypass the height check
        // (audit Suggestion 5).
        let info = LightdInfo {
            chain_name: "test".to_owned(),
            sapling_activation_height: 0,
            ..LightdInfo::default()
        };
        let err = validate_lightwalletd_network(ZeckNetwork::Testnet, &info)
            .expect_err("zero sapling activation height should be rejected");

        assert!(
            err.to_string().contains("Sapling activation height"),
            "got: {err}"
        );
    }

    // ─── argos-network feature flag ──────────────────────────────────────────
    //
    // Production builds (no feature) MUST reject a regtest server. The
    // C2 integration tests opt in via `cargo test --features argos-network`.

    #[cfg(not(feature = "argos-network"))]
    #[test]
    fn network_validation_rejects_regtest_chain_without_feature() {
        // Without the argos-network feature, a server claiming "regtest"
        // must be rejected even when the operator selected Testnet.
        // Defends against a hostile lightwalletd talking a released Argos
        // binary out of network validation.
        let info = LightdInfo {
            chain_name: "regtest".to_owned(),
            sapling_activation_height: 1,
            ..LightdInfo::default()
        };
        let err = validate_lightwalletd_network(ZeckNetwork::Testnet, &info)
            .expect_err("regtest chain must be rejected in production builds");
        assert!(
            err.to_string().contains("does not match"),
            "got: {err}"
        );
    }

    #[cfg(feature = "argos-network")]
    #[test]
    fn network_validation_accepts_regtest_chain_with_feature() {
        // With the feature enabled, the regtest chain name is accepted as
        // a synonym for testnet, and the Sapling-activation-height check
        // is skipped (regtest activates Sapling at height 1, not testnet's
        // 280 000).
        let info = LightdInfo {
            chain_name: "regtest".to_owned(),
            sapling_activation_height: 1,
            ..LightdInfo::default()
        };
        validate_lightwalletd_network(ZeckNetwork::Testnet, &info)
            .expect("regtest chain must be accepted under the argos-network feature");
    }

    #[cfg(feature = "argos-network")]
    #[test]
    fn network_validation_still_rejects_regtest_against_mainnet_with_feature() {
        // Even with the feature on, a regtest server cannot satisfy a
        // Mainnet selection — the relaxation is scoped to Testnet only.
        let info = LightdInfo {
            chain_name: "regtest".to_owned(),
            sapling_activation_height: 1,
            ..LightdInfo::default()
        };
        let err = validate_lightwalletd_network(ZeckNetwork::Mainnet, &info)
            .expect_err("regtest chain must still be rejected when Mainnet is selected");
        assert!(
            err.to_string().contains("does not match selected mainnet"),
            "got: {err}"
        );
    }

    #[cfg(feature = "argos-network")]
    #[test]
    fn network_validation_still_enforces_testnet_height_for_testnet_chain_name() {
        // The Sapling-height skip applies only when chain_name == "regtest"
        // under the feature. A real-testnet server still has to report the
        // canonical activation height even with the feature enabled.
        let info = LightdInfo {
            chain_name: "test".to_owned(),
            sapling_activation_height: 9999,
            ..LightdInfo::default()
        };
        let err = validate_lightwalletd_network(ZeckNetwork::Testnet, &info)
            .expect_err("testnet sapling height mismatch must still be rejected");
        assert!(
            err.to_string().contains("Sapling activation height"),
            "got: {err}"
        );
    }

    // ─── Endpoint URL resilience (R-N4..R-N7) ─────────────────────────────────
    //
    // Coverage gaps named in docs/superpowers/test-plans/recovery-resilience.md.
    // These exercise inputs a user might type into the lightwalletd field
    // without realising. Each must reject (or accept for the IPv6 loopback
    // case) cleanly without panicking.

    #[test]
    fn endpoint_validation_rejects_input_without_scheme() {
        // R-N4: `wallet.example.com:9067` without a scheme is not a URL
        // even though it looks like a host:port. The validator must reject
        // it rather than silently picking a scheme.
        let err = validated_lightwalletd_endpoints("wallet.example.com:9067")
            .expect_err("scheme-less input should be rejected");
        assert!(
            matches!(err, crate::error::ZeckError::InvalidConfig(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn endpoint_validation_rejects_non_http_schemes() {
        // R-N5: only http (for loopback) and https are valid lightwalletd
        // transports. ftp / file / gopher / data must all reject, not
        // silently accept.
        for url in &[
            "ftp://wallet.example.com:9067",
            "file:///etc/passwd",
            "gopher://wallet.example.com:9067",
            "data:text/plain,whatever",
            "ws://wallet.example.com:9067",
        ] {
            let result = validated_lightwalletd_endpoints(url);
            assert!(result.is_err(), "URL '{url}' should have been rejected");
            assert!(
                matches!(
                    result.unwrap_err(),
                    crate::error::ZeckError::InvalidConfig(_)
                ),
                "URL '{url}' should produce InvalidConfig"
            );
        }
    }

    #[test]
    fn endpoint_validation_allows_ipv6_loopback_http() {
        // R-N6: a local lightwalletd reachable via the IPv6 loopback `::1`
        // should be permitted on plain http, mirroring the IPv4 127.0.0.1
        // case. The host_str() that the loopback check sees is `::1`
        // (without the bracket-wrapping from the URL form).
        let endpoints = validated_lightwalletd_endpoints("http://[::1]:9067")
            .expect("IPv6 loopback over http should be allowed for local testing");
        assert_eq!(endpoints, vec!["http://[::1]:9067".to_owned()]);
    }

    #[test]
    fn endpoint_validation_allows_dot_localhost_http() {
        // R-N6 cont.: `.localhost` subdomains (RFC 6761) are also loopback
        // by convention and explicitly allowed by `is_loopback_host`. Useful
        // for users running a privacy-proxy with a stable hostname.
        let endpoints = validated_lightwalletd_endpoints("http://lwd.localhost:9067")
            .expect(".localhost subdomains over http should be allowed for local testing");
        assert_eq!(endpoints, vec!["http://lwd.localhost:9067".to_owned()]);
    }

    #[test]
    fn endpoint_validation_accepts_embedded_credentials_in_https() {
        // R-N7: documents that the validator does NOT strip embedded
        // credentials. `https://user:pass@host:port` parses as a valid URL
        // and `url::Url::host_str()` returns "host", so the loopback /
        // scheme check passes. The credentials are passed through to
        // `tonic::transport::Channel::from_static`, which will use them as
        // basic-auth on the gRPC layer. Argos does not warn or strip; users
        // who paste a credentialed URL get what they pasted.
        //
        // This is the current behaviour as of v0.1.0-rc — flagged in the
        // test plan as documented rather than enforced; the validator could
        // tighten this in a future revision if we decide credentials in
        // lightwalletd URLs are out of scope.
        let result = validated_lightwalletd_endpoints("https://user:pass@wallet.example.com:443");
        assert!(result.is_ok(), "current behaviour: credentialed URLs pass validation");
    }

    #[test]
    fn classifies_transient_transport_and_dns_errors_as_retryable() {
        use super::is_transient_network_error;
        // Transport/stream drops the previous matcher already caught (regression
        // guard — these must keep matching after the case-insensitive rework).
        assert!(is_transient_network_error(
            "status: Unavailable, message: transport error"
        ));
        assert!(is_transient_network_error("h2 protocol error: GoAway"));
        assert!(is_transient_network_error("operation TimedOut"));
        assert!(is_transient_network_error("received fatal alert: close_notify"));
        assert!(is_transient_network_error("connection closed: UnexpectedEof"));
        // DNS resolution failures (varied OS resolver wording) — the gap this fixes.
        assert!(is_transient_network_error(
            "error trying to connect: dns error: failed to lookup address information: \
             nodename nor servname provided, or not known"
        ));
        assert!(is_transient_network_error("Temporary failure in name resolution"));
        assert!(is_transient_network_error("No such host is known. (os error 11001)"));
        assert!(is_transient_network_error("Name or service not known"));
        // Connection-level transients.
        assert!(is_transient_network_error("tcp connect error: Connection refused"));
        assert!(is_transient_network_error("Connection reset by peer"));
    }

    #[test]
    fn does_not_classify_config_or_validation_errors_as_retryable() {
        use super::is_transient_network_error;
        // A wrong-chain / validation failure or a bad endpoint won't get better
        // by waiting, so it must NOT be retried.
        assert!(!is_transient_network_error(
            "network validation failed: server chain 'main' does not match selected testnet network"
        ));
        assert!(!is_transient_network_error(
            "endpoint must use the https:// scheme"
        ));
        assert!(!is_transient_network_error("wallet summary is unavailable"));
    }
}
