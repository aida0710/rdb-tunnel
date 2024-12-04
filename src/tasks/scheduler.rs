use super::TaskState;
use crate::packet::monitor::NetworkMonitor;
use crate::packet::reader::PacketReader;
use crate::packet::writer::PacketWriter;
use crate::tasks::error::TaskError;
use crate::tasks::task_monitor::TaskMonitor;
use log::info;
use pnet::datalink::NetworkInterface;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::Duration;

// タイムアウトを延長
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
// 同時実行数の制限
const MAX_CONCURRENT_TASKS: usize = 3;

struct TaskHandles {
    reader: JoinHandle<Result<(), String>>,
    writer: JoinHandle<Result<(), String>>,
    analysis: JoinHandle<Result<(), String>>,
}

pub struct TaskScheduler {
    task_state: Arc<Mutex<TaskState>>,
    shutdown_tx: broadcast::Sender<()>,
    interface: NetworkInterface,
    semaphore: Arc<Semaphore>,
}

impl TaskScheduler {
    pub fn new(interface: NetworkInterface) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            task_state: Arc::new(Mutex::new(TaskState::new())),
            shutdown_tx,
            interface,
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_TASKS)),
        }
    }

    pub async fn run(&self) -> Result<(), TaskError> {
        info!("タスクスケジューラを起動しています");
        let monitor = TaskMonitor::new(self.task_state.clone(), SHUTDOWN_TIMEOUT);

        let handles = self.spawn_all_tasks().await;

        monitor.monitor_tasks(handles.reader, handles.writer, handles.analysis, self.shutdown_tx.subscribe()).await
    }

    async fn spawn_all_tasks(&self) -> TaskHandles {
        TaskHandles {
            reader: self.spawn_reader_task().await,
            writer: self.spawn_writer_task().await,
            analysis: self.spawn_analysis_task().await,
        }
    }

    async fn spawn_reader_task(&self) -> JoinHandle<Result<(), String>> {
        let interface = self.interface.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let semaphore = Arc::clone(&self.semaphore);

        tokio::spawn(async move {
            let _permit = match semaphore.acquire().await {
                Ok(permit) => permit,
                Err(_) => return Err("セマフォの取得に失敗しました".to_string()),
            };

            tokio::select! {
                result = async move {
                    info!("パケットのデータベース読み取りタスクを起動しました");
                    PacketReader::start(interface).await
                } => {
                    result.map_err(|e| e.to_string())
                }
                _ = shutdown_rx.recv() => {
                    info!("パケットのデータベース読み取りタスクを停止させました");
                    Ok(())
                }
            }
        })
    }

    async fn spawn_writer_task(&self) -> JoinHandle<Result<(), String>> {
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let writer = PacketWriter::default();
        let semaphore = Arc::clone(&self.semaphore);

        tokio::spawn(async move {
            let _permit = match semaphore.acquire().await {
                Ok(permit) => permit,
                Err(_) => return Err("セマフォの取得に失敗しました".to_string()),
            };

            tokio::select! {
                result = async {
                    info!("パケットのデータベース書き込みタスクを起動しました");
                    writer.start().await
                } => {
                    result.map_err(|e| e.to_string())
                }
                _ = shutdown_rx.recv() => {
                    info!("パケットのデータベース書き込みタスクを停止させました");
                    Ok(())
                }
            }
        })
    }

    async fn spawn_analysis_task(&self) -> JoinHandle<Result<(), String>> {
        let interface = self.interface.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let semaphore = Arc::clone(&self.semaphore);

        tokio::spawn(async move {
            let _permit = match semaphore.acquire().await {
                Ok(permit) => permit,
                Err(_) => return Err("セマフォの取得に失敗しました".to_string()),
            };

            tokio::select! {
                result = async {
                    info!("パケットの収集・解析タスクを起動しました");
                    NetworkMonitor::start(interface).await
                } => {
                    result.map_err(|e| e.to_string())
                }
                _ = shutdown_rx.recv() => {
                    info!("パケットの収集・解析タスクを停止させました");
                    Ok(())
                }
            }
        })
    }
}
