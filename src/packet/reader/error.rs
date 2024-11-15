use crate::database::DatabaseError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PacketReaderError {
    #[error("フィルタリングされたパケットの取得に失敗しました: {0}")]
    FilteredPacketsFetchError(#[from] DatabaseError),

    #[error("指定されたインターフェイスのipv4アドレスが見つかりませんでした: {0}")]
    InterfaceIpv4AddressNotFound(String),

    #[error("ポーリングとパケット送信中にエラーが発生しました: {0}")]
    PollingAndSendingError(String),

    #[error("ネットワークエラー: {0}")]
    NetworkError(String),

    #[error("未対応のチャネルタイプです")]
    UnsupportedChannelType,

    #[error("パケット送信エラー: {0}")]
    SendError(String),
}
