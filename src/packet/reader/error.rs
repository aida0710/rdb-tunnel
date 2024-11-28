use thiserror::Error;

#[derive(Error, Debug)]
pub enum PacketReaderError {
    #[error("ネットワークエラー: {0}")]
    NetworkError(String),

    #[error("未対応のチャネルタイプです")]
    UnsupportedChannelType,

    #[error("パケット送信エラー: {0}")]
    SendError(String),

    #[error("設定エラー: {0}")]
    ConfigurationError(String),
}
