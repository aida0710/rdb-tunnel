use super::TaskState;
use crate::error::InitProcessError;
use crate::packet_analysis::packet_analysis;
use crate::packet_reader::inject_packet;
use crate::packet_writer::start_packet_writer;
use crate::tasks::task_monitor::TaskMonitor;
use log::{error, info};
use pnet::datalink::NetworkInterface;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Duration;
use crate::tasks::error::TaskError;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(1000);

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
        info!("タスクスケジューラを開始します");

        let monitor = TaskMonitor::new(
            self.task_state.clone(),
            SHUTDOWN_TIMEOUT,
        );

        let polling_handle = self.spawn_polling_task();
        let writer_handle = self.spawn_writer_task();
        let analysis_handle = self.spawn_analysis_task();

        monitor.monitor_tasks(
            polling_handle,
            writer_handle,
            analysis_handle,
            self.shutdown_tx.subscribe(),
        ).await
    }

    fn spawn_polling_task(&self) -> JoinHandle<Result<(), String>> {
        let interface = self.interface.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            tokio::select! {
                result = inject_packet(interface) => {
                    result.map_err(|e| e.to_string())
                }
                _ = shutdown_rx.recv() => {
                    info!("ポーリングタスクをシャットダウンしています...");
                    Ok(())
                }
            }
        })
    }

    fn spawn_writer_task(&self) -> JoinHandle<Result<(), String>> {
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            tokio::select! {
                _ = start_packet_writer() => {
                    Ok(())
                }
                _ = shutdown_rx.recv() => {
                    info!("ライタータスクをシャットダウンしています...");
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
                result = packet_analysis(interface) => {
                    result.map_err(|e| e.to_string())
                }
                _ = shutdown_rx.recv() => {
                    info!("分析タスクをシャットダウンしています...");
                    Ok(())
                }
            }
        })
    }
}