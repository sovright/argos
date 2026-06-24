use thiserror::Error;

pub type ZeckResult<T> = Result<T, ZeckError>;

#[derive(Debug, Error)]
pub enum ZeckError {
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("invalid destination address: {0}")]
    InvalidAddress(String),

    #[error("destination must be a Zcash Unified Address")]
    DestinationMustBeUnified,

    #[error("destination address is for the wrong network: expected {expected}, got {actual}")]
    WrongNetwork { expected: String, actual: String },

    #[error("destination must include an Orchard or Sapling receiver")]
    UnsupportedDestination,

    #[error("invalid scan configuration: {0}")]
    InvalidConfig(String),

    #[error("failed to parse date: {0}")]
    InvalidDate(String),

    #[error("lightwalletd probe failed: {0}")]
    Lightwalletd(String),

    #[error("scan session not found")]
    UnknownScanHandle,

    #[error("scan was cancelled")]
    Cancelled,

    #[error("scan is not ready for sweeping: {0}")]
    ScanNotReady(String),

    #[error("estimated sweep fees exceed the configured maximum: {0}")]
    MaxFeeExceeded(String),

    #[error("invalid memo: {0}")]
    InvalidMemo(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("wallet error: {0}")]
    Wallet(String),

    #[error("transaction build failed: {0}")]
    TransactionBuild(String),

    #[error("broadcast failed: {0}")]
    Broadcast(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("internal error: {0}")]
    Internal(String),
}
