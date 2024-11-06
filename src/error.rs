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
pub enum DatabaseError {
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

#[derive(Error, Debug)]
pub enum PacketAnalysisError {
    #[error("ネットワークエラー: {0}")]
    NetworkError(String),

    #[error("IOエラー: {0}")]
    IoError(#[from] io::Error),

    #[error("インターフェースエラー: {0}")]
    InterfaceError(String),
}