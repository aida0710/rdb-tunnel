use super::task_state::TaskState;
use crate::tasks::error::TaskError;
use log::{debug, error, info};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

const SHUTDOWN_CHECK_INTERVAL: Duration = Duration::from_millis(100);

pub struct TaskMonitor {
    task_state: Arc<Mutex<TaskState>>,
    shutdown_timeout: Duration,
}

impl TaskMonitor {
    pub fn new(task_state: Arc<Mutex<TaskState>>, shutdown_timeout: Duration) -> Self {
        Self { task_state, shutdown_timeout }
    }

    pub async fn monitor_tasks(
        &self,
        reader: JoinHandle<Result<(), String>>,
        writer: JoinHandle<Result<(), String>>,
        analysis: JoinHandle<Result<(), String>>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<(), TaskError> {
        // 初期状態の設定
        self.update_task_state("reader", true).await.map_err(|e| TaskError::TaskExecutionError(e.to_string()))?;
        self.update_task_state("writer", true).await.map_err(|e| TaskError::TaskExecutionError(e.to_string()))?;
        self.update_task_state("analysis", true).await.map_err(|e| TaskError::TaskExecutionError(e.to_string()))?;

        let result = loop {
            tokio::select! {
                result = reader => {
                    if let Err(e) = self.handle_task_result(result, "reader").await {
                        break Err(TaskError::TaskExecutionError(e.to_string()));
                    }
                    break Err(TaskError::TaskExecutionError("Reader task unexpectedly terminated".into()));
                }
                result = writer => {
                    if let Err(e) = self.handle_task_result(result, "writer").await {
                        break Err(TaskError::TaskExecutionError(e.to_string()));
                    }
                    break Err(TaskError::TaskExecutionError("Writer task unexpectedly terminated".into()));
                }
                result = analysis => {
                    if let Err(e) = self.handle_task_result(result, "analysis").await {
                        break Err(TaskError::TaskExecutionError(e.to_string()));
                    }
                    break Err(TaskError::TaskExecutionError("Analysis task unexpectedly terminated".into()));
                }
                _ = shutdown_rx.recv() => {
                    info!("Received shutdown signal");
                    match self.wait_for_shutdown().await {
                        Ok(_) => break Ok(()),
                        Err(e) => break Err(TaskError::TaskExecutionError(e.to_string())),
                    }
                }
            }
        };

        // タスクの状態をクリーンアップ
        self.update_task_state("reader", false).await.map_err(|e| TaskError::TaskExecutionError(e.to_string()))?;
        self.update_task_state("writer", false).await.map_err(|e| TaskError::TaskExecutionError(e.to_string()))?;
        self.update_task_state("analysis", false).await.map_err(|e| TaskError::TaskExecutionError(e.to_string()))?;

        result
    }

    async fn handle_task_result(&self, result: Result<Result<(), String>, tokio::task::JoinError>, task_name: &str) -> Result<(), TaskError> {
        self.update_task_state(task_name, false).await?;

        match result {
            Ok(Ok(_)) => {
                debug!("{} タスクが正常に完了しました", task_name);
                Ok(())
            },
            Ok(Err(e)) => {
                error!("{} タスクがエラーで終了しました: {}", task_name, e);
                Err(TaskError::ExecutionError(format!("{} タスクのエラー: {}", task_name, e)))
            },
            Err(e) => {
                error!("{} タスクがパニックで終了しました: {}", task_name, e);
                Err(TaskError::PanicError(format!("{} タスクがパニックしました", task_name)))
            },
        }
    }

    pub async fn wait_for_shutdown(&self) -> Result<(), TaskError> {
        let start_time = std::time::Instant::now();
        while start_time.elapsed() < self.shutdown_timeout {
            let state = self.task_state.lock().await;
            if state.is_all_inactive() {
                info!("全てのタスクが正常にシャットダウンしました");
                return Ok(());
            }
            drop(state);
            sleep(SHUTDOWN_CHECK_INTERVAL).await;
        }

        error!("タスクのシャットダウンがタイムアウトしました");
        Err(TaskError::TimeoutError("シャットダウンタイムアウト".to_string()))
    }

    async fn update_task_state(&self, task_name: &str, active: bool) -> Result<(), TaskError> {
        let mut state = self.task_state.lock().await;
        match task_name {
            "reader" => state.reader_active = active,
            "writer" => state.writer_active = active,
            "analysis" => state.analysis_active = active,
            _ => return Err(TaskError::StateUpdateError(format!("不明なタスク名が指定されました: {}", task_name))),
        }
        Ok(())
    }
}
