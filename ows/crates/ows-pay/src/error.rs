use thiserror::Error;

/// Error codes for programmatic handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayErrorCode {
    /// HTTP transport error (DNS, TLS, timeout).
    HttpTransport,
    /// Server returned an unexpected HTTP status.
    HttpStatus,
    /// Protocol-level error (malformed 402, bad header encoding).
    ProtocolMalformed,
    /// Could not detect which payment protocol to use.
    ProtocolUnknown,
    /// Wallet not found or inaccessible.
    WalletNotFound,
    /// Key decryption or signing failed.
    SigningFailed,
    /// No supported chain/network in the payment requirements.
    UnsupportedChain,
    /// Discovery API error.
    DiscoveryFailed,
    /// Invalid input (e.g. unsupported HTTP method).
    InvalidInput,
    /// Invalid data (e.g. invalid balance).
    InvalidData,
}

#[derive(Debug, Error)]
#[error("[{code:?}] {message}")]
pub struct PayError {
    pub code: PayErrorCode,
    pub message: String,
}

impl PayError {
    pub fn new(code: PayErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<reqwest::Error> for PayError {
    fn from(e: reqwest::Error) -> Self {
        PayError::new(PayErrorCode::HttpTransport, e.to_string())
    }
}

impl From<serde_json::Error> for PayError {
    fn from(e: serde_json::Error) -> Self {
        PayError::new(PayErrorCode::ProtocolMalformed, format!("json: {e}"))
    }
}
