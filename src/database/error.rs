use thiserror::Error;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("データベース接続エラー: {0}")]
    Postgres(#[from] tokio_postgres::Error),

    #[error("プール接続エラー: {0}")]
    Pool(#[from] bb8::RunError<tokio_postgres::Error>),

    #[error("シリアル化エラー: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("データベース初期化エラー")]
    Initialization,

    #[error("トランザクションエラー: {0}")]
    Transaction(String),

    #[error("クエリエラー: {0}")]
    Query(String),

    #[error("プール設定エラー: {0}")]
    PoolConfig(String),

    #[error("データベース接続エラー: {0}")]
    ConnectionError(String),

    #[error("クエリ実行エラー: {0}")]
    QueryError(String),

    #[error("トランザクションエラー: {0}")]
    TransactionError(String),

    #[error("データベースプール取得エラー: {0}")]
    PoolError(String),

    #[error("データ型変換エラー: {0}")]
    TypeConversionError(String),

    #[error("テーブル操作エラー: {0}")]
    TableOperationError(String),
}