use thiserror::Error;

#[derive(Error, Debug)]
pub enum TaskError {
    #[error("パケット分析エラー: {0}")]
    PacketAnalysisError(String),

    #[error("タスク実行エラー: {0}")]
    TaskExecutionError(String),

    #[error("タスクのシャットダウンに失敗: {0}")]
    TaskShutdownError(String),
    
    #[error("タスクの初期化に失敗: {0}")]
    InitializationError(String),

    #[error("タスクの実行に失敗: {0}")]
    ExecutionError(String),

    #[error("タスクのシャットダウンに失敗: {0}")]
    ShutdownError(String),

    #[error("タスクの状態更新に失敗: {0}")]
    StateUpdateError(String),

    #[error("タスクのタイムアウト: {0}")]
    TimeoutError(String),

    #[error("タスク間通信エラー: {0}")]
    CommunicationError(String),

    #[error("タスクのパニック: {0}")]
    PanicError(String),
}