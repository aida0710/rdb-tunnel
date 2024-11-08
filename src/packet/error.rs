// error.rs の修正

use crate::database::DbError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PacketError {
    #[error("データベースエラー: {0}")]
    DatabaseError(String),

    #[error("ネットワークエラー: {0}")]
    NetworkError(String),

    #[error("デバイスエラー: {0}")]
    DeviceError(String),

    #[error("未対応のチャネルタイプです")]
    UnsupportedChannelType,

    #[error("パケットサイズが大きすぎます: {0} bytes")]
    PacketSizeTooLarge(usize),

    #[error("パケット送信エラー: {0}")]
    SendError(String),

    #[error("パケット解析エラー: {0}")]
    ParseError(String),

    #[error("パケットフィルタリングエラー: {0}")]
    FilterError(String),

    #[error("パケットバッファエラー: {0}")]
    BufferError(String),

    #[error("プロトコルエラー: {0}")]
    ProtocolError(String),

    #[error("タイムスタンプエラー: {0}")]
    TimestampError(String),

    #[error("パケットカウンターエラー: {0}")]
    CounterError(String),
}

impl From<DbError> for PacketError {
    fn from(error: DbError) -> Self {
        match error {
            DbError::ConnectionError(e) => PacketError::DatabaseError(format!("接続エラー: {}", e)),
            DbError::QueryError(e) => PacketError::DatabaseError(format!("クエリエラー: {}", e)),
            DbError::TransactionError(e) => PacketError::DatabaseError(format!("トランザクションエラー: {}", e)),
            DbError::PoolError(e) => PacketError::DatabaseError(format!("プールエラー: {}", e)),
            DbError::Postgres(e) => PacketError::DatabaseError(format!("PostgreSQLエラー: {}", e)),
            DbError::Initialization => PacketError::DatabaseError("初期化エラー".to_string()),
            _ => PacketError::DatabaseError(error.to_string()),
        }
    }
}