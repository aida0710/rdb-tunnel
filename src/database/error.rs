use log::error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("接続マネージャの作成に失敗しました: {0}")]
    ConnectionManagerError(#[from] tokio_postgres::Error),

    #[error("データベースプールの作成に失敗しました: {0}")]
    CreatePoolError(String),

    #[error("初期プロセスでデータベースの接続に失敗しました: {0}")]
    InitFailedConnectDatabase(String),

    #[error("データベースプールの初期化に失敗しました")]
    InitializationError,

    #[error("データベースプールが初期化されていません")]
    PoolNotInitialized,

    #[error("データベース接続エラー: {0}")]
    ConnectionError(String),

    #[error("クエリの実行に失敗しました: {0}")]
    QueryExecutionError(String),

    #[error("クエリの準備に失敗しました: {0}")]
    QueryPreparationError(String),

    #[error("データベースプールの取得に失敗しました: {0}")]
    PoolRetrievalError(String),

    #[error("トランザクション処理に失敗しました: {0}")]
    TransactionError(String),
}
