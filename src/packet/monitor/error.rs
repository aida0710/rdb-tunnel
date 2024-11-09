use thiserror::Error;

#[derive(Error, Debug)]
pub enum MonitorError {
    // interface_handler
    #[error("ネットワークエラー: {0}")]
    NetworkError(String),

    #[error("未対応のチャンネルタイプです")]
    UnsupportedChannelType,

    #[error("パケットの処理に失敗しました: {0}")]
    PacketParseError(String),

    #[error("パケットの読み取りに失敗しました: {0}")]
    PacketReadError(String),

    #[error("無効なパケットサイズです")]
    InvalidPacketSize,

    #[error("パケット処理エラー: {0}")]
    ProcessingError(String),

    // network monitor
    #[error("Mainインターフェイスでエラーが発生しました: {0}")]
    MainInterfaceError(String),

    #[error("Tapインターフェイスでエラーが発生しました: {0}")]
    TapInterfaceError(String),

    #[error("インターフェース {0} が見つかりません")]
    InterfaceNotFound(String),
}