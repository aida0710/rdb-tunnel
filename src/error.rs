use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum InitProcessError {
    #[error("ロガーのセットアップに失敗しました: {0}")]
    LoggerError(String),

    #[error("環境変数ファイルの読み込みに失敗しました: {0}")]
    EnvFileReadError(String),

    #[error("環境変数の取得に失敗しました: {0}")]
    EnvVarError(String),

    #[error("環境変数の解析に失敗しました: {0}")]
    EnvVarParseError(String),

    #[error("データベース接続エラー: {0}")]
    DatabaseConnectionError(String),

    #[error("仮想インターフェースのエラー: {0}")]
    VirtualInterfaceError(String),

    #[error("デバイス選択エラー: {0}")]
    DeviceSelectionError(String),

    #[error("タスクの実行処理に失敗しました: {0}")]
    TaskExecutionProcessError(String),

    #[error("設定エラー: {0}")]
    ConfigurationError(String),

    #[error("システムエラー: {0}")]
    SystemError(String),
}

#[derive(Error, Debug)]
pub enum InterfaceError {
    #[error("インターフェースの初期化に失敗: {0}")]
    InitializationError(String),

    #[error("インターフェースの設定に失敗: {0}")]
    ConfigurationError(String),

    #[error("インターフェースの権限エラー: {0}")]
    PermissionError(String),

    #[error("インターフェースのステータス取得に失敗: {0}")]
    StatusError(String),

    #[error("インターフェースが見つかりません: {0}")]
    NotFoundError(String),

    #[error("インターフェースの操作に失敗: {0}")]
    OperationError(String),
}
