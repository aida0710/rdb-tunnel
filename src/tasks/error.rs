use thiserror::Error;

#[derive(Error, Debug)]
pub enum TaskError {
    #[error("タスク実行エラー: {0}")]
    TaskExecutionError(String),

    #[error("タスクの実行に失敗: {0}")]
    ExecutionError(String),

    #[error("タスクの状態更新に失敗: {0}")]
    StateUpdateError(String),

    #[error("タスクのタイムアウト: {0}")]
    TimeoutError(String),

    #[error("タスクのパニック: {0}")]
    PanicError(String),
}
