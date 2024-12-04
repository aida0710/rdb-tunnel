use thiserror::Error;

#[derive(Error, Debug)]
pub enum InitProcessError {
    #[error("ロガーのセットアップに失敗しました: {0}")]
    LoggerError(String),

    #[error("設定エラー: {0}")]
    ConfigurationError(String),

    #[error("インターフェイスの選択に失敗しました: {0}")]
    InterfaceSelectionError(String),

    #[error("データベース接続エラー: {0}")]
    DatabaseConnectionError(String),

    #[error("タスクの実行処理に失敗しました: {0}")]
    TaskExecutionProcessError(String),
}
