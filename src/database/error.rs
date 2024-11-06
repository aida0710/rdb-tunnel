use thiserror::Error;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("データベースエラー: {0}")]
    Postgres(#[from] tokio_postgres::Error),

    #[error("接続プールエラー: {0}")]
    Pool(#[from] bb8::RunError<tokio_postgres::Error>),

    #[error("JSONシリアル化エラー: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("データベース初期化エラー")]
    Initialization,
}