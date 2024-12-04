use thiserror::Error;

#[derive(Error, Debug)]
pub enum MonitorError {
    #[error("ネットワークエラー: {0}")]
    NetworkError(String),

    #[error("未対応のチャンネルタイプです")]
    UnsupportedChannelType,
}
