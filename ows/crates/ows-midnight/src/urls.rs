//! URL scheme helpers shared between the indexer-backed sync modules and the
//! node submission pipeline.

/// `https://` / `http://` → `wss://` / `ws://`. Caller must reject non-http(s) schemes.
pub(super) fn http_url_to_ws_url(trimmed: &str) -> Option<String> {
    if let Some(rest) = trimmed.strip_prefix("https://") {
        Some(format!("wss://{rest}"))
    } else {
        trimmed
            .strip_prefix("http://")
            .map(|rest| format!("ws://{rest}"))
    }
}

/// Derive the GraphQL-over-WebSocket endpoint from a configured Indexer URL.
///
/// Accepts:
/// - `wss://host/.../graphql/ws` (returned as-is)
/// - `https://host/.../graphql`  (→ `wss://.../graphql/ws`)
/// - `https://host/.../graphql/` (→ `wss://.../graphql/ws`)
pub(super) fn indexer_ws_url(indexer_url: &str) -> Result<String, std::io::Error> {
    let trimmed = indexer_url.trim_end_matches('/');

    if trimmed.starts_with("wss://") || trimmed.starts_with("ws://") {
        return Ok(trimmed.to_string());
    }
    let Some(ws) = http_url_to_ws_url(trimmed) else {
        return Err(std::io::Error::other(format!(
            "invalid Midnight indexer URL scheme: {indexer_url}"
        )));
    };

    // If it's the GraphQL HTTP endpoint, append `/ws`.
    if ws.ends_with("/graphql") {
        Ok(format!("{ws}/ws"))
    } else {
        Ok(ws)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_url_from_https_graphql() {
        let ws = indexer_ws_url("https://example.com/api/v4/graphql").unwrap();
        assert_eq!(ws, "wss://example.com/api/v4/graphql/ws");
    }

    #[test]
    fn ws_url_passthrough() {
        let ws = indexer_ws_url("wss://example.com/api/v4/graphql/ws").unwrap();
        assert_eq!(ws, "wss://example.com/api/v4/graphql/ws");
    }
}
