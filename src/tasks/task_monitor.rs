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
    pub fn new(
        task_state: Arc<Mutex<TaskState>>,
        shutdown_timeout: Duration,
    ) -> Self {
        Self {
            task_state,
            shutdown_timeout,
        }
    }

    pub async fn monitor_tasks(
        &self,
        polling: JoinHandle<Result<(), String>>,
        writer: JoinHandle<Result<(), String>>,
        analysis: JoinHandle<Result<(), String>>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<(), TaskError> {
        // 初期状態の設定
        self.update_task_state("ポーリング", true).await.map_err(|e| TaskError::TaskExecutionError(e.to_string()))?;
        self.update_task_state("ライター", true).await.map_err(|e| TaskError::TaskExecutionError(e.to_string()))?;
        self.update_task_state("分析", true).await.map_err(|e| TaskError::TaskExecutionError(e.to_string()))?;

        let result = loop {
            tokio::select! {
                result = polling => {
                    if let Err(e) = self.handle_task_result(result, "ポーリング").await {
                        break Err(TaskError::TaskExecutionError(e.to_string()));
                    }
                    break Err(TaskError::TaskExecutionError("ポーリングタスクが予期せず終了".to_string()));
                }
                result = writer => {
                    if let Err(e) = self.handle_task_result(result, "ライター").await {
                        break Err(TaskError::TaskExecutionError(e.to_string()));
                    }
                    break Err(TaskError::TaskExecutionError("ライタータスクが予期せず終了".to_string()));
                }
                result = analysis => {
                    if let Err(e) = self.handle_task_result(result, "分析").await {
                        break Err(TaskError::TaskExecutionError(e.to_string()));
                    }
                    break Err(TaskError::TaskExecutionError("分析タスクが予期せず終了".to_string()));
                }
                _ = shutdown_rx.recv() => {
                    info!("シャットダウン信号を受信しました");
                    match self.wait_for_shutdown().await {
                        Ok(_) => break Ok(()),
                        Err(e) => break Err(TaskError::TaskExecutionError(e.to_string())),
                    }
                }
            }
        };

        // タスクの状態をクリーンアップ
        self.update_task_state("ポーリング", false).await.map_err(|e| TaskError::TaskExecutionError(e.to_string()))?;
        self.update_task_state("ライター", false).await.map_err(|e| TaskError::TaskExecutionError(e.to_string()))?;
        self.update_task_state("分析", false).await.map_err(|e| TaskError::TaskExecutionError(e.to_string()))?;

        result
    }

    async fn handle_task_result(
        &self,
        result: Result<Result<(), String>, tokio::task::JoinError>,
        task_name: &str,
    ) -> Result<(), TaskError> {
        // タスクの状態を非アクティブに設定
        self.update_task_state(task_name, false).await?;

        match result {
            Ok(Ok(_)) => {
                debug!("{}タスクが正常終了しました", task_name);
                Ok(())
            }
            Ok(Err(e)) => {
                error!("{}タスクがエラーで終了: {}", task_name, e);
                Err(TaskError::ExecutionError(format!("{}エラー: {}", task_name, e)))
            }
            Err(e) => {
                error!("{}タスクがパニックで終了: {}", task_name, e);
                Err(TaskError::PanicError(format!("{}タスクがパニックで終了", task_name)))
            }
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

    pub async fn update_task_state(&self, task_name: &str, active: bool) -> Result<(), TaskError> {
        let mut state = self.task_state.lock().await;
        match task_name {
            "ポーリング" => state.polling_active = active,
            "ライター" => state.writer_active = active,
            "分析" => state.analysis_active = active,
            _ => return Err(TaskError::StateUpdateError(
                format!("不明なタスク名: {}", task_name)
            )),
        }
        Ok(())
    }
}
