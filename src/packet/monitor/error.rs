use thiserror::Error;

#[derive(Error, Debug)]
pub enum MonitorError {
    // interface_handler
    #[error("ネットワークエラー: {0}")]
    NetworkError(String),

    #[error("未対応のチャンネルタイプです")]
    UnsupportedChannelType,

    // network monitor
    #[error("Mainインターフェイスでエラーが発生しました: {0}")]
    MainInterfaceError(String),
}
