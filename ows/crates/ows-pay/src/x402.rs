use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::chains;
use crate::error::{PayError, PayErrorCode};
use crate::types::{
    Eip3009Authorization, Eip3009Payload, PayResult, PaymentInfo, PaymentPayload, PaymentPayloadV1,
    PaymentPayloadV2, PaymentRequirements, Protocol, X402Response,
};
use crate::wallet::WalletAccess;

const HEADER_PAYMENT_REQUIRED: &str = "x-payment-required";
const HEADER_PAYMENT_REQUIRED_V2: &str = "payment-required";
const HEADER_PAYMENT: &str = "X-PAYMENT";
const HEADER_PAYMENT_V2: &str = "payment-signature";

/// Handle x402 payment for a 402 response we already received.
pub(crate) async fn handle_x402(
    wallet: &dyn WalletAccess,
    url: &str,
    method: &str,
    req_body: Option<&str>,
    resp_headers: &reqwest::header::HeaderMap,
    body_402: &str,
) -> Result<PayResult, PayError> {
    let (x402_version, resource, requirements, extensions) = parse_requirements(resp_headers, body_402)?;
    let (req, network) = pick_payment_option(wallet, &requirements)?;

    let (payload, payment_info) =
        build_signed_payment(wallet, req, &network, x402_version, resource, extensions)?;

    let payload_json = serde_json::to_string(&payload)?;
    let payload_b64 = B64.encode(payload_json.as_bytes());

    let client = reqwest::Client::new();
    let retry = build_request(&client, url, method, req_body, Some(&payload_b64))?
        .send()
        .await?;

    let status = retry.status().as_u16();
    let response_body = retry.text().await.unwrap_or_default();

    Ok(PayResult {
        protocol: Protocol::X402,
        status,
        body: response_body,
        payment: Some(payment_info),
    })
}

// ---------------------------------------------------------------------------
// Scheme dispatch
// ---------------------------------------------------------------------------

/// Build a signed payment payload, dispatching on the scheme.
fn build_signed_payment(
    wallet: &dyn WalletAccess,
    req: &PaymentRequirements,
    network: &str,
    x402_version: u32,
    resource: Option<serde_json::Value>,
    extensions: Option<serde_json::Value>,
) -> Result<(PaymentPayload, PaymentInfo), PayError> {
    match req.scheme.as_str() {
        "exact" => build_evm_exact(wallet, req, network, x402_version, resource, extensions),
        scheme => Err(PayError::new(
            PayErrorCode::ProtocolUnknown,
            format!("unsupported payment scheme: {scheme}"),
        )),
    }
}

/// Build an EVM "exact" (EIP-3009 TransferWithAuthorization) payment.
fn build_evm_exact(
    wallet: &dyn WalletAccess,
    req: &PaymentRequirements,
    network: &str,
    x402_version: u32,
    resource: Option<serde_json::Value>,
    extensions: Option<serde_json::Value>,
) -> Result<(PaymentPayload, PaymentInfo), PayError> {
    let account = wallet.account(network)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let valid_after = now.saturating_sub(5);
    let valid_before = now + req.max_timeout_seconds;

    let mut nonce_bytes = [0u8; 32];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| PayError::new(PayErrorCode::SigningFailed, format!("rng: {e}")))?;
    let nonce_hex = format!("0x{}", hex::encode(nonce_bytes));

    let token_name = req
        .extra
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("USD Coin");
    let token_version = req
        .extra
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("2");

    let chain_id_num = ows_core::parse_chain(network)
        .map_err(|err| PayError::new(PayErrorCode::ProtocolMalformed, err))?
        .evm_chain_id_u64()
        .map_err(|err| PayError::new(PayErrorCode::ProtocolMalformed, err))?;

    let typed_data_json = serde_json::json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "TransferWithAuthorization": [
                { "name": "from", "type": "address" },
                { "name": "to", "type": "address" },
                { "name": "value", "type": "uint256" },
                { "name": "validAfter", "type": "uint256" },
                { "name": "validBefore", "type": "uint256" },
                { "name": "nonce", "type": "bytes32" }
            ]
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": token_name,
            "version": token_version,
            "chainId": chain_id_num.to_string(),
            "verifyingContract": req.asset
        },
        "message": {
            "from": account.address,
            "to": req.pay_to,
            "value": req.amount,
            "validAfter": valid_after.to_string(),
            "validBefore": valid_before.to_string(),
            "nonce": &nonce_hex
        }
    })
    .to_string();

    let signature = wallet.sign_payload(&req.scheme, network, &typed_data_json)?;

    let eip3009 = Eip3009Payload {
        signature,
        authorization: Eip3009Authorization {
            from: account.address,
            to: req.pay_to.clone(),
            value: req.amount.clone(),
            valid_after: valid_after.to_string(),
            valid_before: valid_before.to_string(),
            nonce: nonce_hex,
        },
    };

    let inner = serde_json::to_value(eip3009)?;
    let payload = if x402_version >= 2 {
        PaymentPayload::V2(PaymentPayloadV2 {
            x402_version,
            accepted: req.clone(),
            resource,
            payload: inner,
            extensions,
        })
    } else {
        PaymentPayload::V1(PaymentPayloadV1 {
            x402_version,
            scheme: req.scheme.clone(),
            network: req.network.clone(),
            payload: inner,
        })
    };

    let amount_display = crate::discovery::format_usdc(&req.amount);
    let payment_info = PaymentInfo {
        amount: amount_display,
        network: chains::display_name(network).to_string(),
        token: "USDC".to_string(),
    };

    Ok((payload, payment_info))
}

// ---------------------------------------------------------------------------
// Requirement parsing & chain selection
// ---------------------------------------------------------------------------

fn parse_requirements(
    headers: &reqwest::header::HeaderMap,
    body_text: &str,
) -> Result<(u32, Option<serde_json::Value>, Vec<PaymentRequirements>, Option<serde_json::Value>), PayError> {
    for header_name in &[HEADER_PAYMENT_REQUIRED_V2, HEADER_PAYMENT_REQUIRED] {
        if let Some(header_val) = headers.get(*header_name) {
            if let Ok(header_str) = header_val.to_str() {
                if let Ok(decoded) = B64.decode(header_str) {
                    if let Ok(parsed) = serde_json::from_slice::<X402Response>(&decoded) {
                        if !parsed.accepts.is_empty() {
                            let version = match *header_name {
                                HEADER_PAYMENT_REQUIRED_V2 => parsed.x402_version.unwrap_or(2),
                                _ => parsed.x402_version.unwrap_or(1),
                            };
                            return Ok((version, parsed.resource, parsed.accepts, parsed.extensions));
                        }
                    }
                }
            }
        }
    }

    let parsed: X402Response = serde_json::from_str(body_text).map_err(|e| {
        PayError::new(
            PayErrorCode::ProtocolMalformed,
            format!("failed to parse x402 402 response: {e}"),
        )
    })?;

    if parsed.accepts.is_empty() {
        return Err(PayError::new(
            PayErrorCode::ProtocolMalformed,
            "402 response has empty accepts",
        ));
    }

    Ok((
        parsed.x402_version.unwrap_or(1),
        parsed.resource,
        parsed.accepts,
        parsed.extensions,
    ))
}

/// Payment schemes we know how to handle.
const SUPPORTED_SCHEMES: &[&str] = &["exact"];

fn is_gateway_batched(req: &PaymentRequirements) -> bool {
    req.extra
        .get("name")
        .and_then(|v| v.as_str())
        .map(|name| name == "GatewayWalletBatched")
        .unwrap_or(false)
}

fn parsed_amount(req: &PaymentRequirements) -> Option<u128> {
    req.amount.parse().ok()
}

/// Pick the first payment option whose scheme we support and whose
/// network the wallet supports. Returns the requirement and its
/// resolved CAIP-2 network string.
fn pick_payment_option<'a>(
    wallet: &dyn WalletAccess,
    requirements: &'a [PaymentRequirements],
) -> Result<(&'a PaymentRequirements, String), PayError> {
    let supported = wallet.supported_chains();
    let mut candidates = Vec::new();

    for req in requirements {
        if !SUPPORTED_SCHEMES.contains(&req.scheme.as_str()) {
            continue;
        }

        // GatewayWalletBatched requires a pre-funded gateway wallet, which
        // this client does not currently manage.
        if is_gateway_batched(req) {
            continue;
        }

        let chain_type = match chains::resolve_chain_type(&req.network) {
            Some(ct) => ct,
            None => continue,
        };

        if !supported.contains(&chain_type) {
            continue;
        }

        // Resolve to CAIP-2 if the server sent a human name.
        let network = match ows_core::parse_chain(&req.network) {
            Ok(c) => c.chain_id.to_string(),
            Err(_) => req.network.clone(), // Already CAIP-2 (unknown to registry but namespace matched).
        };

        candidates.push((req, network));
    }

    if let Some((_, first_network)) = candidates.first() {
        let mut best = &candidates[0];
        for candidate in candidates.iter().skip(1) {
            if candidate.1 != *first_network {
                break;
            }

            let current = parsed_amount(candidate.0);
            let best_amount = parsed_amount(best.0);
            if current
                .zip(best_amount)
                .map(|(a, b)| a < b)
                .unwrap_or(false)
            {
                best = candidate;
            }
        }

        return Ok((best.0, best.1.clone()));
    }

    let networks: Vec<_> = requirements.iter().map(|r| r.network.as_str()).collect();
    Err(PayError::new(
        PayErrorCode::UnsupportedChain,
        format!(
            "no supported chain in 402 response (networks: {networks:?}, wallet supports: {supported:?})"
        ),
    ))
}

pub(crate) fn build_request(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    body: Option<&str>,
    payment_header: Option<&str>,
) -> Result<reqwest::RequestBuilder, PayError> {
    let mut req = match method.to_uppercase().as_str() {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        other => {
            return Err(PayError::new(
                PayErrorCode::InvalidInput,
                format!("unsupported HTTP method: {other}"),
            ))
        }
    };

    if let Some(b) = body {
        req = req
            .header("content-type", "application/json")
            .body(b.to_string());
    }

    if let Some(payment) = payment_header {
        req = req
            .header(HEADER_PAYMENT, payment)
            .header(HEADER_PAYMENT_V2, payment);
    }

    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ows_core::ChainType;
    use reqwest::header::HeaderMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn base_requirement() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".into(),
            network: "eip155:8453".into(),
            amount: "10000".into(),
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
            pay_to: "0x1234567890abcdef1234567890abcdef12345678".into(),
            max_timeout_seconds: 60,
            extra: serde_json::json!({"name": "USD Coin", "version": "2"}),
            description: Some("test service".into()),
            resource: None,
        }
    }

    fn read_headers(stream: &mut std::net::TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(err) => panic!("failed to read request: {err}"),
            }
        }

        String::from_utf8(buf).unwrap()
    }

    fn header_value(request: &str, header_name: &str) -> String {
        request
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case(header_name) {
                    Some(value.trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| panic!("missing header {header_name} in request:\n{request}"))
    }

    fn decode_payment_payload(encoded: &str) -> PaymentPayload {
        let decoded = B64.decode(encoded).unwrap();
        serde_json::from_slice(&decoded).unwrap()
    }

    fn spawn_x402_flow_server(
        payment_header_name: &str,
        payment_header_value: String,
    ) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let header_name = payment_header_name.to_string();

        let handle = thread::spawn(move || {
            let (mut initial_stream, _) = listener.accept().unwrap();
            let _initial_request = read_headers(&mut initial_stream);
            let first_response = format!(
                "HTTP/1.1 402 Payment Required\r\nContent-Length: 0\r\nConnection: close\r\n{header_name}: {payment_header_value}\r\n\r\n"
            );
            initial_stream.write_all(first_response.as_bytes()).unwrap();

            let (mut retry_stream, _) = listener.accept().unwrap();
            let retry_request = read_headers(&mut retry_stream);
            tx.send(retry_request).unwrap();

            let second_response =
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            retry_stream.write_all(second_response.as_bytes()).unwrap();
        });

        (format!("http://{addr}"), rx, handle)
    }

    // -----------------------------------------------------------------------
    // Mock wallets
    // -----------------------------------------------------------------------

    struct EvmWallet;
    impl WalletAccess for EvmWallet {
        fn supported_chains(&self) -> Vec<ChainType> {
            vec![ChainType::Evm]
        }
        fn account(&self, _network: &str) -> Result<crate::wallet::Account, PayError> {
            Ok(crate::wallet::Account {
                address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            })
        }
        fn sign_payload(
            &self,
            _scheme: &str,
            _network: &str,
            _payload: &str,
        ) -> Result<String, PayError> {
            Ok("0xdeadbeef".into())
        }
    }

    struct SolanaWallet;
    impl WalletAccess for SolanaWallet {
        fn supported_chains(&self) -> Vec<ChainType> {
            vec![ChainType::Solana]
        }
        fn account(&self, _network: &str) -> Result<crate::wallet::Account, PayError> {
            Ok(crate::wallet::Account {
                address: "So11111111111111111111111111111111111111112".into(),
            })
        }
        fn sign_payload(
            &self,
            _scheme: &str,
            _network: &str,
            _payload: &str,
        ) -> Result<String, PayError> {
            Ok("0xdeadbeef".into())
        }
    }

    struct MultiWallet;
    impl WalletAccess for MultiWallet {
        fn supported_chains(&self) -> Vec<ChainType> {
            vec![ChainType::Evm, ChainType::Solana]
        }
        fn account(&self, _network: &str) -> Result<crate::wallet::Account, PayError> {
            Ok(crate::wallet::Account {
                address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            })
        }
        fn sign_payload(
            &self,
            _scheme: &str,
            _network: &str,
            _payload: &str,
        ) -> Result<String, PayError> {
            Ok("0xdeadbeef".into())
        }
    }

    // -----------------------------------------------------------------------
    // build_request
    // -----------------------------------------------------------------------

    #[test]
    fn build_request_valid_methods() {
        let client = reqwest::Client::new();
        for method in &["GET", "POST", "PUT", "DELETE", "PATCH"] {
            let result = build_request(&client, "https://example.com", method, None, None);
            assert!(result.is_ok(), "method {method} should be valid");
        }
    }

    #[test]
    fn build_request_case_insensitive() {
        let client = reqwest::Client::new();
        for method in &["get", "Post", "pUT", "dElEtE", "patch"] {
            let result = build_request(&client, "https://example.com", method, None, None);
            assert!(
                result.is_ok(),
                "method {method} should be valid (case-insensitive)"
            );
        }
    }

    #[test]
    fn build_request_invalid_method() {
        let client = reqwest::Client::new();
        let result = build_request(&client, "https://example.com", "FOOBAR", None, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, PayErrorCode::InvalidInput);
        assert!(err.message.contains("FOOBAR"));
    }

    #[test]
    fn build_request_head_is_invalid() {
        let client = reqwest::Client::new();
        let result = build_request(&client, "https://example.com", "HEAD", None, None);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // parse_requirements
    // -----------------------------------------------------------------------

    #[test]
    fn parse_requirements_from_body() {
        let headers = HeaderMap::new();
        let body = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "10000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xabc",
                "maxTimeoutSeconds": 30
            }]
        })
        .to_string();

        let (_, _, reqs, _) = parse_requirements(&headers, &body).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].scheme, "exact");
        assert_eq!(reqs[0].network, "eip155:8453");
    }

    #[test]
    fn parse_requirements_from_header() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xdef"
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("x-payment-required", encoded.parse().unwrap());

        let (_, _, reqs, _) = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].pay_to, "0xdef");
    }

    #[test]
    fn parse_requirements_header_fallback_to_body() {
        let mut headers = HeaderMap::new();
        headers.insert("x-payment-required", "not-valid-base64!!!".parse().unwrap());

        let body = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "1000",
                "asset": "0xaaa",
                "payTo": "0xbbb"
            }]
        })
        .to_string();

        let (_, _, reqs, _) = parse_requirements(&headers, &body).unwrap();
        assert_eq!(reqs[0].pay_to, "0xbbb");
    }

    #[test]
    fn parse_requirements_from_v2_header() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv2"
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("payment-required", encoded.parse().unwrap());

        let (_, _, reqs, _) = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].pay_to, "0xv2");
    }

    #[test]
    fn parse_requirements_v2_header_defaults_version_to_2() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv2"
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("payment-required", encoded.parse().unwrap());

        let (version, _, reqs, _) = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(version, 2);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].pay_to, "0xv2");
    }

    #[test]
    fn v2_header_without_version_builds_v2_payment_payload() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv2",
                "extra": {
                    "name": "USD Coin",
                    "version": "2"
                }
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("payment-required", encoded.parse().unwrap());

        let (version, resource, reqs, extensions) = parse_requirements(&headers, "not json").unwrap();
        let (req, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        let (payload, _) =
            build_signed_payment(&EvmWallet, req, &network, version, resource, extensions).unwrap();

        match payload {
            PaymentPayload::V2(v2) => {
                assert_eq!(v2.x402_version, 2);
                assert_eq!(v2.accepted.pay_to, "0xv2");
            }
            PaymentPayload::V1(_) => panic!("expected v2 payload for payment-required header"),
        }
    }

    #[test]
    fn parse_requirements_v2_header_takes_priority_over_v1() {
        let x402_v2 = serde_json::json!({
            "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "1", "asset": "0xaaa", "payTo": "0xv2"}]
        });
        let x402_v1 = serde_json::json!({
            "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "1", "asset": "0xaaa", "payTo": "0xv1"}]
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            "payment-required",
            B64.encode(serde_json::to_string(&x402_v2).unwrap().as_bytes())
                .parse()
                .unwrap(),
        );
        headers.insert(
            "x-payment-required",
            B64.encode(serde_json::to_string(&x402_v1).unwrap().as_bytes())
                .parse()
                .unwrap(),
        );

        let (_, _, reqs, _) = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(reqs[0].pay_to, "0xv2");
    }

    #[test]
    fn build_request_sends_both_payment_headers() {
        let client = reqwest::Client::new();
        let req = build_request(
            &client,
            "https://example.com",
            "GET",
            None,
            Some("payload123"),
        )
        .unwrap()
        .build()
        .unwrap();
        let headers = req.headers();
        assert_eq!(headers.get("X-PAYMENT").unwrap(), "payload123");
        assert_eq!(headers.get("payment-signature").unwrap(), "payload123");
    }

    #[test]
    fn parse_requirements_empty_accepts_errors() {
        let headers = HeaderMap::new();
        let body = r#"{"accepts":[]}"#;
        let err = parse_requirements(&headers, body).unwrap_err();
        assert_eq!(err.code, PayErrorCode::ProtocolMalformed);
    }

    #[test]
    fn parse_requirements_bad_json_errors() {
        let headers = HeaderMap::new();
        let err = parse_requirements(&headers, "this is not json").unwrap_err();
        assert_eq!(err.code, PayErrorCode::ProtocolMalformed);
    }

    // -----------------------------------------------------------------------
    // pick_payment_option
    // -----------------------------------------------------------------------

    #[test]
    fn pick_evm_by_caip2() {
        let reqs = vec![base_requirement()];
        let (req, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        assert_eq!(req.network, "eip155:8453");
        assert_eq!(network, "eip155:8453");
    }

    #[test]
    fn pick_evm_by_name() {
        let mut req = base_requirement();
        req.network = "base".into();
        let reqs = [req];
        let (_, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        // Human name resolved to CAIP-2.
        assert_eq!(network, "eip155:8453");
    }

    #[test]
    fn pick_skips_unsupported_namespace() {
        let mut req = base_requirement();
        req.network = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into();
        let reqs = [req];
        let err = pick_payment_option(&EvmWallet, &reqs).unwrap_err();
        assert_eq!(err.code, PayErrorCode::UnsupportedChain);
    }

    #[test]
    fn pick_solana_with_solana_wallet() {
        let mut req = base_requirement();
        req.network = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into();
        let reqs = [req];
        let (_, network) = pick_payment_option(&SolanaWallet, &reqs).unwrap();
        assert!(network.starts_with("solana:"));
    }

    #[test]
    fn pick_multi_wallet_prefers_first() {
        let evm_req = base_requirement();
        let mut sol_req = base_requirement();
        sol_req.network = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into();
        let reqs = [sol_req, evm_req];
        let (_, network) = pick_payment_option(&MultiWallet, &reqs).unwrap();
        assert!(network.starts_with("solana:"));
    }

    #[test]
    fn pick_prefers_cheapest_option_within_first_supported_network() {
        let expensive = base_requirement();
        let mut cheap = base_requirement();
        cheap.amount = "1000".into();
        let reqs = [expensive, cheap];
        let (req, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        assert_eq!(network, "eip155:8453");
        assert_eq!(req.amount, "1000");
    }

    #[test]
    fn pick_skips_gateway_batched_offer() {
        let mut gateway = base_requirement();
        gateway.amount = "100".into();
        gateway.extra = serde_json::json!({
            "name": "GatewayWalletBatched",
            "version": "1"
        });

        let mut regular = base_requirement();
        regular.amount = "1000".into();

        let reqs = [gateway, regular];
        let (req, _) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        assert_eq!(req.amount, "1000");
        assert_eq!(req.extra["name"], "USD Coin");
    }

    #[test]
    fn pick_unknown_namespace_errors() {
        let mut req = base_requirement();
        req.network = "foochain:1".into();
        let reqs = [req];
        let err = pick_payment_option(&EvmWallet, &reqs).unwrap_err();
        assert_eq!(err.code, PayErrorCode::UnsupportedChain);
    }

    #[test]
    fn pick_unsupported_scheme_skipped() {
        let mut req = base_requirement();
        req.scheme = "subscription".into();
        let reqs = [req];
        let err = pick_payment_option(&EvmWallet, &reqs).unwrap_err();
        assert_eq!(err.code, PayErrorCode::UnsupportedChain);
    }

    #[test]
    fn pick_unknown_evm_chain_still_works() {
        // Chain not in KNOWN_CHAINS but namespace is recognized.
        let mut req = base_requirement();
        req.network = "eip155:999999".into();
        let reqs = [req];
        let (_, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        assert_eq!(network, "eip155:999999");
    }

    // -----------------------------------------------------------------------
    // build_evm_exact
    // -----------------------------------------------------------------------

    #[test]
    fn build_evm_exact_produces_valid_payload() {
        let req = base_requirement();
        let (payload, info) = build_evm_exact(&EvmWallet, &req, "eip155:8453", 1, None, None).unwrap();

        let v1 = match &payload {
            PaymentPayload::V1(p) => p,
            PaymentPayload::V2(_) => panic!("expected V1"),
        };
        assert_eq!(v1.scheme, "exact");
        assert_eq!(v1.network, "eip155:8453");
        assert_eq!(v1.x402_version, 1);

        assert!(v1.payload.get("signature").is_some());
        assert!(v1.payload.get("authorization").is_some());
        let auth = &v1.payload["authorization"];
        assert_eq!(auth["from"], "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        assert_eq!(auth["to"], req.pay_to);
        assert_eq!(auth["value"], req.amount);

        assert_eq!(info.network, "base");
        assert_eq!(info.token, "USDC");
    }

    #[test]
    fn build_evm_exact_produces_valid_v2_payload() {
        let req = base_requirement();
        let resource = serde_json::json!({
            "url": "https://example.com/api",
            "description": "test",
            "mimeType": "application/json"
        });
        let (payload, _) =
            build_evm_exact(&EvmWallet, &req, "eip155:8453", 2, Some(resource.clone()), None).unwrap();

        let v2 = match &payload {
            PaymentPayload::V2(p) => p,
            PaymentPayload::V1(_) => panic!("expected V2"),
        };
        assert_eq!(v2.x402_version, 2);
        assert_eq!(v2.accepted.scheme, req.scheme);
        assert_eq!(v2.accepted.network, req.network);
        assert_eq!(v2.accepted.pay_to, req.pay_to);
        assert_eq!(v2.resource, Some(resource));

        assert!(v2.payload.get("signature").is_some());
        let auth = &v2.payload["authorization"];
        assert_eq!(auth["from"], "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        assert_eq!(auth["to"], req.pay_to);
        assert_eq!(auth["value"], req.amount);
    }

    #[test]
    fn build_evm_exact_v2_with_no_resource() {
        let req = base_requirement();
        let (payload, _) = build_evm_exact(&EvmWallet, &req, "eip155:8453", 2, None, None).unwrap();

        let v2 = match &payload {
            PaymentPayload::V2(p) => p,
            PaymentPayload::V1(_) => panic!("expected V2"),
        };
        assert_eq!(v2.x402_version, 2);
        assert!(v2.resource.is_none());
    }

    #[test]
    fn build_evm_exact_v2_omits_null_requirement_fields() {
        let mut req = base_requirement();
        req.extra = serde_json::Value::Null;
        req.description = None;
        req.resource = None;

        let (payload, _) = build_evm_exact(&EvmWallet, &req, "eip155:8453", 2, None, None).unwrap();
        let encoded = serde_json::to_value(payload).unwrap();
        let accepted = &encoded["accepted"];

        assert!(accepted.get("extra").is_none());
        assert!(accepted.get("description").is_none());
        assert!(accepted.get("resource").is_none());
    }

    #[test]
    fn build_evm_exact_fails_for_non_numeric_chain_id() {
        let req = base_requirement();
        let err = build_evm_exact(&EvmWallet, &req, "solana:mainnet", 1, None, None).unwrap_err();
        assert_eq!(err.code, PayErrorCode::ProtocolMalformed);
    }

    // -----------------------------------------------------------------------
    // parse → pick roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn parse_and_pick_roundtrip() {
        let body = serde_json::json!({
            "x402Version": 1,
            "accepts": [{
                "scheme": "exact",
                "network": "base",
                "maxAmountRequired": "10000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0x7d9d1821d15B9e0b8Ab98A058361233E255E405D",
                "maxTimeoutSeconds": 120,
                "extra": {"name": "USD Coin", "version": "2"}
            }]
        })
        .to_string();

        let headers = HeaderMap::new();
        let (_, _, reqs, _) = parse_requirements(&headers, &body).unwrap();
        let (req, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        assert_eq!(req.pay_to, "0x7d9d1821d15B9e0b8Ab98A058361233E255E405D");
        assert_eq!(network, "eip155:8453"); // "base" resolved to CAIP-2
    }

    #[test]
    fn mock_wallet_satisfies_trait() {
        let wallet = EvmWallet;
        assert_eq!(wallet.supported_chains(), vec![ChainType::Evm]);
        let account = wallet.account("eip155:8453").unwrap();
        assert!(account.address.starts_with("0x"));
        let sig = wallet.sign_payload("exact", "eip155:8453", "{}").unwrap();
        assert_eq!(sig, "0xdeadbeef");
    }

    #[tokio::test]
    async fn pay_retries_v1_flow_with_v1_payload() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv1",
                "extra": {
                    "name": "USD Coin",
                    "version": "2"
                }
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());
        let (url, rx, handle) = spawn_x402_flow_server("x-payment-required", encoded);

        let result = crate::pay(&EvmWallet, &url, "GET", None).await.unwrap();
        let retry_request = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        handle.join().unwrap();

        assert_eq!(result.status, 200);
        assert_eq!(result.body, "ok");

        let x_payment = header_value(&retry_request, "X-PAYMENT");
        let payment_signature = header_value(&retry_request, "payment-signature");
        assert_eq!(x_payment, payment_signature);

        match decode_payment_payload(&x_payment) {
            PaymentPayload::V1(v1) => {
                assert_eq!(v1.x402_version, 1);
                assert_eq!(v1.network, "eip155:8453");
                assert_eq!(v1.payload["authorization"]["to"], "0xv1");
            }
            PaymentPayload::V2(_) => panic!("expected v1 payload for x-payment-required flow"),
        }
    }

    #[tokio::test]
    async fn pay_retries_v2_flow_with_v2_payload_without_explicit_version() {
        let resource = serde_json::json!({
            "uri": "https://api.example.com/paid"
        });
        let x402 = serde_json::json!({
            "resource": resource,
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv2",
                "extra": {
                    "name": "USD Coin",
                    "version": "2"
                }
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());
        let (url, rx, handle) = spawn_x402_flow_server("payment-required", encoded);

        let result = crate::pay(&EvmWallet, &url, "GET", None).await.unwrap();
        let retry_request = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        handle.join().unwrap();

        assert_eq!(result.status, 200);
        assert_eq!(result.body, "ok");

        let x_payment = header_value(&retry_request, "X-PAYMENT");
        let payment_signature = header_value(&retry_request, "payment-signature");
        assert_eq!(x_payment, payment_signature);

        match decode_payment_payload(&payment_signature) {
            PaymentPayload::V2(v2) => {
                assert_eq!(v2.x402_version, 2);
                assert_eq!(v2.accepted.pay_to, "0xv2");
                assert_eq!(
                    v2.resource,
                    Some(serde_json::json!({"uri": "https://api.example.com/paid"}))
                );
            }
            PaymentPayload::V1(_) => panic!("expected v2 payload for payment-required flow"),
        }
    }
}
