use super::TaskState;
use crate::packet::monitor::NetworkMonitor;
use crate::packet::reader::PacketReader;
use crate::packet::writer::PacketWriter;
use crate::tasks::error::TaskError;
use crate::tasks::task_monitor::TaskMonitor;
use log::info;
use pnet::datalink::NetworkInterface;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Duration;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(1000);

struct TaskHandles {
    reader: JoinHandle<Result<(), String>>,
    writer: JoinHandle<Result<(), String>>,
    analysis: JoinHandle<Result<(), String>>,
}

pub struct TaskScheduler {
    task_state: Arc<Mutex<TaskState>>,
    shutdown_tx: broadcast::Sender<()>,
    interface: NetworkInterface,
}

impl TaskScheduler {
    pub fn new(interface: NetworkInterface) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            task_state: Arc::new(Mutex::new(TaskState::new())),
            shutdown_tx,
            interface,
        }
    }

    pub async fn run(&self) -> Result<(), TaskError> {
        info!("タスクスケジューラを起動しています");
        let monitor = TaskMonitor::new(self.task_state.clone(), SHUTDOWN_TIMEOUT);

        let handles = self.spawn_all_tasks();

        monitor.monitor_tasks(handles.reader, handles.writer, handles.analysis, self.shutdown_tx.subscribe()).await
    }

    fn spawn_all_tasks(&self) -> TaskHandles {
        TaskHandles {
            reader: self.spawn_reader_task(),
            writer: self.spawn_writer_task(),
            analysis: self.spawn_analysis_task(),
        }
    }

    fn spawn_reader_task(&self) -> JoinHandle<Result<(), String>> {
        let interface = self.interface.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
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

    fn spawn_writer_task(&self) -> JoinHandle<Result<(), String>> {
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let writer = PacketWriter::default();

        tokio::spawn(async move {
            tokio::select! {
                _ = writer.start() => {
                    info!("パケットのデータベース書き込みタスクを起動しました");
                    Ok(())
                }
                _ = shutdown_rx.recv() => {
                    info!("パケットのデータベース書き込みタスクを停止させました");
                    Ok(())
                }
            }
        })
    }

    fn spawn_analysis_task(&self) -> JoinHandle<Result<(), String>> {
        let interface = self.interface.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            tokio::select! {
                result = {
                    info!("パケットの収集・解析タスクを起動しました");
                    NetworkMonitor::start_monitoring(interface)
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
