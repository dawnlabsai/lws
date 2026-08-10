use crate::error::{PayError, PayErrorCode};
use crate::types::{DiscoverResult, DiscoveredService, Protocol, RawDiscoveryResponse, Service};

const CDP_DISCOVERY_URL: &str = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources";

const TESTNETS: &[&str] = &[
    "base-sepolia",
    "eip155:84532",
    "eip155:11155111",
    "solana-devnet",
];

// ===========================================================================
// Unified discovery (public API)
// ===========================================================================

/// Discover payable services.
///
/// Fetches the x402 directory with the given pagination parameters,
/// filters testnets, and returns services with pagination metadata.
///
/// When a query is provided the upstream API does not support server-side
/// filtering, so we paginate through pages internally until we have
/// collected enough matching results (up to `limit`).
pub async fn discover_all(
    query: Option<&str>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> Result<DiscoverResult, PayError> {
    let limit = limit.unwrap_or(100);
    let offset = offset.unwrap_or(0);

    if let Some(q) = query {
        // Client-side search: page through the full directory to find matches.
        return discover_with_query(q, limit, offset).await;
    }

    // No query — single page fetch.
    let resp = fetch_x402(limit, offset).await?;
    let total = resp.total;

    let services = filter_services(resp.items, None);

    Ok(DiscoverResult {
        services,
        total,
        limit,
        offset,
    })
}

/// Paginate through the upstream directory collecting services that match
/// `query` until we have `limit` results (after skipping `offset` matches).
async fn discover_with_query(
    query: &str,
    limit: u64,
    offset: u64,
) -> Result<DiscoverResult, PayError> {
    discover_with_query_at(CDP_DISCOVERY_URL, query, limit, offset).await
}

/// Same as [`discover_with_query`] but against an explicit feed URL, so tests
/// can point it at a local mock server instead of the live CDP endpoint.
async fn discover_with_query_at(
    base_url: &str,
    query: &str,
    limit: u64,
    offset: u64,
) -> Result<DiscoverResult, PayError> {
    const PAGE_SIZE: u64 = 500;
    const MAX_PAGES: u64 = 30; // safety cap: don't fetch more than 15 000 items

    let mut collected: Vec<Service> = Vec::new();
    let mut skipped: u64 = 0;
    let mut api_offset: u64 = 0;
    let mut total: u64 = 0;

    for _ in 0..MAX_PAGES {
        let resp = fetch_x402_at(base_url, PAGE_SIZE, api_offset).await?;
        total = resp.total;
        // Advance by the RAW number of records the feed returned for this
        // page, not by `resp.items.len()` (the number that survived
        // `parse_items_tolerant`). Malformed records are dropped from
        // `items` but were still consumed from the feed's own offset space;
        // advancing by the parsed count under-advances whenever a page has
        // a skipped record, which re-visits already-seen records on the
        // next request and can stop before `total` is reached, silently
        // omitting matches that strict paging would eventually find.
        let page_len = resp.raw_count;

        let matches = filter_services(resp.items, Some(query));
        for svc in matches {
            if skipped < offset {
                skipped += 1;
                continue;
            }
            collected.push(svc);
            if collected.len() as u64 >= limit {
                break;
            }
        }

        if collected.len() as u64 >= limit {
            break;
        }

        api_offset += page_len;
        if api_offset >= total {
            break;
        }
    }

    Ok(DiscoverResult {
        services: collected,
        total,
        limit,
        offset,
    })
}

/// Filter and convert raw discovered services, optionally matching against a
/// query string (case-insensitive, checked against URL and descriptions).
fn filter_services(
    items: Vec<crate::types::DiscoveredService>,
    query: Option<&str>,
) -> Vec<Service> {
    let q = query.map(|q| q.to_lowercase());
    let mut services = Vec::new();

    for svc in items {
        let accept = match svc.accepts.first() {
            Some(a) => a,
            None => continue,
        };

        let is_testnet = TESTNETS.iter().any(|t| accept.network.contains(t));
        if is_testnet {
            continue;
        }

        if let Some(ref q) = q {
            let url_match = svc.resource.to_lowercase().contains(q);
            let accepts_desc = accept
                .description
                .as_ref()
                .map(|d| d.to_lowercase().contains(q))
                .unwrap_or(false);
            let meta_desc = svc
                .metadata
                .as_ref()
                .and_then(|m| m.description.as_ref())
                .map(|d| d.to_lowercase().contains(q))
                .unwrap_or(false);
            if !url_match && !accepts_desc && !meta_desc {
                continue;
            }
        }

        let desc = accept
            .description
            .as_deref()
            .or_else(|| svc.metadata.as_ref().and_then(|m| m.description.as_deref()))
            .unwrap_or("");

        services.push(Service {
            protocol: Protocol::X402,
            name: svc.resource.clone(),
            url: svc.resource,
            description: truncate(desc, 80),
            price: format_price(&accept.amount, &accept.network),
            network: accept.network.clone(),
            tags: vec![],
        });
    }

    services
}

// ===========================================================================
// x402 fetching (internal)
// ===========================================================================

struct FetchResult {
    items: Vec<crate::types::DiscoveredService>,
    total: u64,
    /// The number of records the feed returned on this page, before any
    /// were dropped for failing to parse. This is what pagination must
    /// advance the offset by; `items.len()` is the post-filter count and
    /// undercounts whenever a record was skipped (see `discover_with_query_at`).
    raw_count: u64,
}

async fn fetch_x402(limit: u64, offset: u64) -> Result<FetchResult, PayError> {
    fetch_x402_at(CDP_DISCOVERY_URL, limit, offset).await
}

/// Same as [`fetch_x402`] but against an explicit feed URL, so tests can
/// point it at a local mock server instead of the live CDP endpoint.
async fn fetch_x402_at(base_url: &str, limit: u64, offset: u64) -> Result<FetchResult, PayError> {
    let client = reqwest::Client::new();
    let resp = client
        .get(base_url)
        .query(&[("limit", limit.to_string()), ("offset", offset.to_string())])
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(PayError::new(
            PayErrorCode::DiscoveryFailed,
            format!("x402 discovery returned {status}: {body}"),
        ));
    }

    // Parse the envelope (items array + pagination) without eagerly
    // deserializing each item. The x402 discovery feed aggregates records
    // from many independent third-party providers, and some do not match
    // the expected schema. Deserializing straight into
    // `Vec<DiscoveredService>` means one malformed record fails the whole
    // page; parsing the envelope first and converting each item on its own
    // (see `parse_items_tolerant`) means only that record is skipped.
    let raw: RawDiscoveryResponse = resp.json().await.map_err(|e| {
        PayError::new(
            PayErrorCode::DiscoveryFailed,
            format!("failed to parse x402 discovery: {e}"),
        )
    })?;

    let total = raw.pagination.map(|p| p.total).unwrap_or(0);
    let raw_count = raw.items.len() as u64;
    let (items, skipped) = parse_items_tolerant(raw.items);
    if skipped > 0 {
        eprintln!(
            "warning: skipped {skipped} malformed x402 discovery record(s) out of {}",
            items.len() + skipped
        );
    }

    Ok(FetchResult {
        items,
        total,
        raw_count,
    })
}

/// Convert each raw discovery item independently so that a single
/// malformed record (unexpected field type, missing required field, etc.)
/// does not fail the whole page. Returns the successfully parsed services
/// and a count of how many raw records were skipped.
fn parse_items_tolerant(raw_items: Vec<serde_json::Value>) -> (Vec<DiscoveredService>, usize) {
    let mut items = Vec::with_capacity(raw_items.len());
    let mut skipped = 0usize;

    for value in raw_items {
        match serde_json::from_value::<DiscoveredService>(value) {
            Ok(item) => items.push(item),
            Err(e) => {
                skipped += 1;
                eprintln!("warning: skipping malformed x402 discovery record: {e}");
            }
        }
    }

    (items, skipped)
}

// ===========================================================================
// Formatting helpers
// ===========================================================================

pub(crate) fn format_price(amount_str: &str, network: &str) -> String {
    let chain_type = crate::chains::resolve_chain_type(network);
    match chain_type {
        Some(ows_core::ChainType::Nano) => format_nano(amount_str),
        Some(ows_core::ChainType::Near) => format_near(amount_str),
        _ => format_usdc(amount_str),
    }
}

pub(crate) fn format_usdc(amount_str: &str) -> String {
    let amount: u128 = amount_str.parse().unwrap_or(0);
    let whole = amount / 1_000_000;
    let frac = amount % 1_000_000;
    let frac_str = format!("{frac:06}");
    let trimmed = frac_str.trim_end_matches('0');
    let trimmed = if trimmed.is_empty() { "00" } else { trimmed };
    format!("${whole}.{trimmed}")
}

pub(crate) fn format_nano(amount_str: &str) -> String {
    let amount: u128 = amount_str.parse().unwrap_or(0);
    let divisor = 1_000_000_000_000_000_000_000_000_000_000u128;
    let whole = amount / divisor;
    let frac = amount % divisor;
    if frac == 0 {
        format!("{whole} XNO")
    } else {
        let frac_str = format!("{frac:030}");
        let trimmed = frac_str.trim_end_matches('0');
        format!("{whole}.{trimmed} XNO")
    }
}

/// Format a NEAR amount expressed in yoctoNEAR (10^24 yoctoNEAR per NEAR).
pub(crate) fn format_near(amount_str: &str) -> String {
    let amount: u128 = amount_str.parse().unwrap_or(0);
    let divisor = 1_000_000_000_000_000_000_000_000u128; // 10^24
    let whole = amount / divisor;
    let frac = amount % divisor;
    if frac == 0 {
        format!("{whole} NEAR")
    } else {
        let frac_str = format!("{frac:024}");
        let trimmed = frac_str.trim_end_matches('0');
        format!("{whole}.{trimmed} NEAR")
    }
}

fn truncate(s: &str, max: usize) -> String {
    let first_line = s.lines().next().unwrap_or("");
    if first_line.len() > max {
        let cutoff = first_line
            .char_indices()
            .map(|(idx, _)| idx)
            .chain(std::iter::once(first_line.len()))
            .take_while(|&idx| idx <= max.saturating_sub(3))
            .last()
            .unwrap_or(0);

        format!("{}...", &first_line[..cutoff])
    } else {
        first_line.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // format_usdc
    // -----------------------------------------------------------------------

    #[test]
    fn format_usdc_zero() {
        assert_eq!(format_usdc("0"), "$0.00");
    }

    #[test]
    fn format_usdc_one_cent() {
        assert_eq!(format_usdc("10000"), "$0.01");
    }

    #[test]
    fn format_usdc_one_dollar() {
        assert_eq!(format_usdc("1000000"), "$1.00");
    }

    #[test]
    fn format_usdc_fractional() {
        assert_eq!(format_usdc("1500000"), "$1.5");
    }

    #[test]
    fn format_usdc_large() {
        assert_eq!(format_usdc("100000000"), "$100.00");
    }

    #[test]
    fn format_usdc_sub_cent() {
        assert_eq!(format_usdc("1"), "$0.000001");
    }

    #[test]
    fn format_usdc_non_numeric() {
        assert_eq!(format_usdc("abc"), "$0.00");
    }

    #[test]
    fn format_usdc_empty() {
        assert_eq!(format_usdc(""), "$0.00");
    }

    // -----------------------------------------------------------------------
    // format_nano
    // -----------------------------------------------------------------------

    #[test]
    fn format_nano_whole() {
        assert_eq!(format_nano("1000000000000000000000000000000"), "1 XNO");
    }

    #[test]
    fn format_nano_fractional() {
        assert_eq!(format_nano("1500000000000000000000000000000"), "1.5 XNO");
    }

    #[test]
    fn format_nano_very_small() {
        assert_eq!(format_nano("1"), "0.000000000000000000000000000001 XNO");
    }

    #[test]
    fn format_price_dispatches() {
        assert_eq!(format_price("10000", "eip155:8453"), "$0.01");
        assert_eq!(
            format_price("1000000000000000000000000000000", "nano:mainnet"),
            "1 XNO"
        );
        assert_eq!(
            format_price("1000000000000000000000000", "near:mainnet"),
            "1 NEAR"
        );
        assert_eq!(format_price("1000000000000000000000000", "near"), "1 NEAR");
    }

    // -----------------------------------------------------------------------
    // format_near
    // -----------------------------------------------------------------------

    #[test]
    fn format_near_whole() {
        // 1 NEAR = 10^24 yoctoNEAR
        assert_eq!(format_near("1000000000000000000000000"), "1 NEAR");
    }

    #[test]
    fn format_near_fractional() {
        assert_eq!(format_near("1500000000000000000000000"), "1.5 NEAR");
    }

    #[test]
    fn format_near_zero() {
        assert_eq!(format_near("0"), "0 NEAR");
    }

    #[test]
    fn format_near_one_yocto() {
        // Smallest unit: 1 yoctoNEAR (10^-24 NEAR).
        assert_eq!(format_near("1"), "0.000000000000000000000001 NEAR");
    }

    #[test]
    fn format_near_storage_deposit() {
        // 0.00125 NEAR (typical NEP-141 storage deposit).
        assert_eq!(format_near("1250000000000000000000"), "0.00125 NEAR");
    }

    #[test]
    fn format_near_non_numeric() {
        assert_eq!(format_near("abc"), "0 NEAR");
    }

    // -----------------------------------------------------------------------
    // truncate
    // -----------------------------------------------------------------------

    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate("hello", 80), "hello");
    }

    #[test]
    fn truncate_long_string() {
        let long = "a".repeat(100);
        let result = truncate(&long, 20);
        assert!(result.len() <= 20);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn truncate_long_utf8_string_respects_char_boundaries() {
        let prefix = "a".repeat(76);
        let input = format!("{prefix}“🙂 rest");
        let result = truncate(&input, 80);

        assert_eq!(result, format!("{prefix}..."));
    }

    #[test]
    fn truncate_multiline_uses_first_line() {
        assert_eq!(truncate("first\nsecond\nthird", 80), "first");
    }

    #[test]
    fn truncate_empty() {
        assert_eq!(truncate("", 80), "");
    }

    // -----------------------------------------------------------------------
    // testnet filtering (unit-level, no network)
    // -----------------------------------------------------------------------

    #[test]
    fn testnet_list_contains_expected_entries() {
        assert!(TESTNETS.contains(&"base-sepolia"));
        assert!(TESTNETS.contains(&"eip155:84532"));
        assert!(TESTNETS.contains(&"eip155:11155111"));
        assert!(TESTNETS.contains(&"solana-devnet"));
    }

    #[test]
    fn testnet_check_matches() {
        let network = "base-sepolia";
        assert!(TESTNETS.iter().any(|t| network.contains(t)));
    }

    #[test]
    fn mainnet_check_does_not_match() {
        let network = "base";
        assert!(!TESTNETS.iter().any(|t| network.contains(t)));
    }

    // -----------------------------------------------------------------------
    // discover_all (live, ignored by default)
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore]
    async fn live_discover_returns_services() {
        let result = discover_all(None, Some(10), Some(0)).await.unwrap();
        assert!(result.total > 0);
        assert!(!result.services.is_empty());
        assert_eq!(result.limit, 10);
        assert_eq!(result.offset, 0);

        // No testnets should appear.
        for svc in &result.services {
            assert!(
                !TESTNETS.iter().any(|t| svc.network.contains(t)),
                "testnet {} leaked through",
                svc.network
            );
        }
    }

    #[tokio::test]
    #[ignore]
    async fn live_discover_pagination() {
        let page1 = discover_all(None, Some(5), Some(0)).await.unwrap();
        let page2 = discover_all(None, Some(5), Some(5)).await.unwrap();

        // Pages should have same total.
        assert_eq!(page1.total, page2.total);

        // Pages should have different services (unless one is empty due to testnet filtering).
        if !page1.services.is_empty() && !page2.services.is_empty() {
            assert_ne!(page1.services[0].url, page2.services[0].url);
        }
    }

    #[tokio::test]
    #[ignore]
    async fn live_discover_query_filters() {
        let result = discover_all(Some("heurist"), Some(50), Some(0))
            .await
            .unwrap();
        for svc in &result.services {
            let combined = format!("{} {}", svc.url, svc.description).to_lowercase();
            assert!(
                combined.contains("heurist"),
                "service should match query: {}",
                svc.url
            );
        }
    }

    // -----------------------------------------------------------------------
    // tolerant item-level parsing (regression test for malformed CDP records)
    // -----------------------------------------------------------------------

    /// A synthetic discovery page containing two well-formed synthetic
    /// records plus two REAL, verbatim records captured from the live CDP
    /// x402 discovery feed
    /// (https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources)
    /// on 2026-08-10, which fail strict `PaymentRequirements` deserialization:
    ///
    /// - offset 0, limit 500: the `api.interzoid.com/translatetoany` record's
    ///   `accepts[0].resource` is a JSON OBJECT ({description, mimeType, url})
    ///   but `PaymentRequirements.resource` is typed `Option<String>`.
    /// - offset 14000, limit 500: the `ez-qr-generator.com/a2a/generate`
    ///   record's second `accepts` entry (network `solana:...`) has no
    ///   `asset` field at all, but `PaymentRequirements.asset` is a required
    ///   `String` with no default.
    const MALFORMED_PAGE_FIXTURE: &str = r##"{
  "items": [
    {
      "resource": "https://api.example.com/good1",
      "type": "http",
      "x402Version": 1,
      "accepts": [
        {
          "scheme": "exact",
          "network": "eip155:8453",
          "amount": "1000",
          "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          "payTo": "0x0000000000000000000000000000000000000001"
        }
      ]
    },
    {
      "resource": "https://api.interzoid.com/translatetoany",
      "type": "http",
      "x402Version": 2,
      "accepts": [
        {
          "scheme": "exact",
          "network": "eip155:8453",
          "amount": "10000",
          "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          "payTo": "0xdCEca23FF8A7145e1b5B35427C9886CF21A67566",
          "resource": {
            "description": "Detect the language of input text and translate it to any specified target language. AI-powered translation supporting numerous world languages.",
            "mimeType": "application/json",
            "url": "https://api.interzoid.com/translatetoany"
          }
        }
      ]
    },
    {
      "resource": "https://ez-qr-generator.com/a2a/generate",
      "type": "http",
      "x402Version": 2,
      "accepts": [
        {
          "scheme": "exact",
          "network": "eip155:8453",
          "amount": "1000",
          "payTo": "0x67CE366B323b47561C6a1154Bc633440822497b4",
          "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
        },
        {
          "scheme": "exact",
          "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
          "amount": "1000",
          "payTo": "7V7wYJ2CP1p57fi9L6MoomQsJTXVyrYRc7QAnFtRm8FQ"
        }
      ]
    },
    {
      "resource": "https://api.example.com/good2",
      "type": "http",
      "x402Version": 1,
      "accepts": [
        {
          "scheme": "exact",
          "network": "eip155:8453",
          "amount": "2000",
          "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          "payTo": "0x0000000000000000000000000000000000000002"
        }
      ]
    }
  ],
  "pagination": {
    "limit": 500,
    "offset": 0,
    "total": 14445
  }
}"##;

    #[test]
    fn baseline_strict_page_deserialize_fails_on_real_malformed_records() {
        // Documents the bug this file fixes: strictly deserializing the
        // whole `items` array fails because of two malformed records, even
        // though the other two records in the same page are perfectly
        // valid.
        let raw: RawDiscoveryResponse = serde_json::from_str(MALFORMED_PAGE_FIXTURE).unwrap();
        let strict: Result<Vec<DiscoveredService>, _> =
            raw.items.into_iter().map(serde_json::from_value).collect();
        assert!(
            strict.is_err(),
            "strict per-page deserialization should fail on this fixture"
        );
    }

    #[test]
    fn parse_items_tolerant_skips_malformed_records_not_whole_page() {
        let raw: RawDiscoveryResponse = serde_json::from_str(MALFORMED_PAGE_FIXTURE).unwrap();
        assert_eq!(raw.items.len(), 4, "fixture should carry 4 raw records");

        let (items, skipped) = parse_items_tolerant(raw.items);

        // Only the 2 good synthetic records should have parsed; the 2 live
        // malformed records should have been skipped, not failed the page.
        assert_eq!(items.len(), 2, "expected 2 valid records to parse");
        assert_eq!(skipped, 2, "expected 2 malformed records to be skipped");

        let resources: Vec<&str> = items.iter().map(|i| i.resource.as_str()).collect();
        assert!(resources.contains(&"https://api.example.com/good1"));
        assert!(resources.contains(&"https://api.example.com/good2"));
    }

    // -----------------------------------------------------------------------
    // search pagination must advance by the raw feed page size, not by how
    // many records survived parsing (regression test for the Bugbot finding
    // on PR #251: skipped records must not shrink the offset step, or
    // search pagination overlaps pages and can stop before `total`,
    // silently omitting matches strict paging would eventually reach).
    // -----------------------------------------------------------------------

    fn item_json(resource: &str, asset: Option<&str>) -> serde_json::Value {
        let mut accept = serde_json::json!({
            "scheme": "exact",
            "network": "eip155:8453",
            "amount": "1000",
            "payTo": "0x0000000000000000000000000000000000000001",
        });
        if let Some(a) = asset {
            accept["asset"] = serde_json::json!(a);
        }
        // `asset` is a required field on `PaymentRequirements` with no
        // default, so omitting it makes this record fail item-level parsing
        // - the same class of real-world malformed record documented in
        // `MALFORMED_PAGE_FIXTURE` above.
        serde_json::json!({
            "resource": resource,
            "type": "http",
            "x402Version": 1,
            "accepts": [accept],
        })
    }

    const ASSET: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

    #[tokio::test]
    async fn discover_with_query_advances_offset_by_raw_page_size_not_parsed_count() {
        let mut server = mockito::Server::new_async().await;

        // Page 1 (feed offset 0): 3 RAW records, but the middle one is
        // malformed (no `asset`) and gets dropped by `parse_items_tolerant`,
        // leaving only 2 parsed items. `total` (4) requires a second page.
        let page1 = serde_json::json!({
            "items": [
                item_json("https://api.example.com/widget-a", Some(ASSET)),
                item_json("https://api.example.com/widget-b-broken", None),
                item_json("https://api.example.com/widget-c", Some(ASSET)),
            ],
            "pagination": {"limit": 500, "offset": 0, "total": 4},
        })
        .to_string();

        // Page 2 must be requested at feed offset 3 (the RAW count of page
        // 1). The pre-fix code advanced by the PARSED count (2) instead,
        // which would request offset 2 here and get no matching mock.
        let page2 = serde_json::json!({
            "items": [item_json("https://api.example.com/widget-d", Some(ASSET))],
            "pagination": {"limit": 500, "offset": 3, "total": 4},
        })
        .to_string();

        let page1_mock = server
            .mock("GET", "/discovery")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("limit".into(), "500".into()),
                mockito::Matcher::UrlEncoded("offset".into(), "0".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page1)
            .create_async()
            .await;

        let page2_mock = server
            .mock("GET", "/discovery")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("limit".into(), "500".into()),
                mockito::Matcher::UrlEncoded("offset".into(), "3".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(page2)
            .create_async()
            .await;

        let base_url = format!("{}/discovery", server.url());
        let result = discover_with_query_at(&base_url, "widget", 100, 0)
            .await
            .unwrap();

        // Confirms the second request actually landed at offset=3, not
        // offset=2: if it didn't, this mock never matched and the call
        // above would have failed with a discovery error instead.
        page1_mock.assert_async().await;
        page2_mock.assert_async().await;

        let urls: Vec<&str> = result.services.iter().map(|s| s.url.as_str()).collect();
        assert_eq!(
            urls.len(),
            3,
            "expected exactly the 3 well-formed widget records, no duplicates, no omissions: {urls:?}"
        );
        assert!(urls.contains(&"https://api.example.com/widget-a"));
        assert!(urls.contains(&"https://api.example.com/widget-c"));
        assert!(
            urls.contains(&"https://api.example.com/widget-d"),
            "widget-d lives on page 2 at the correct raw offset; under-advancing the \
             offset would either skip it or fetch page 2 at the wrong offset and \
             error out: {urls:?}"
        );
    }
}
