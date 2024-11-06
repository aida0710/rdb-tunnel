mod select_device;
mod database;
mod error;
mod packet_reader;
mod packet_header;
mod packet_writer;
mod firewall;
mod firewall_packet;
mod virtual_interface;
mod setup_logger;
mod packet_analysis;
mod types;
mod config;
mod tasks;

use crate::config::AppConfig;
use crate::database::database::Database;
use crate::error::InitProcessError;
use crate::select_device::select_device;
use crate::setup_logger::setup_logger;
use crate::tasks::TaskScheduler;
use crate::virtual_interface::setup_interface;
use log::{error, info};
use tun_tap::{Iface, Mode};

#[tokio::main]
async fn main() -> Result<(), InitProcessError> {
    // ロガーのセットアップ
    setup_logger().map_err(|e| InitProcessError::LoggerError(e.to_string()))?;

    // 設定の読み込み
    let config: AppConfig = AppConfig::new()?;

    // データベース接続
    Database::connect(
        &config.database.host,
        config.database.port,
        &config.database.user,
        &config.database.password,
        &config.database.database,
    )
        .await
        .map_err(|e| InitProcessError::DatabaseConnectionError(e.to_string()))?;

    // 仮想インターフェースのセットアップ
    let virtual_interface = Iface::new(&config.network.tap_interface_name, Mode::Tap)
        .map_err(|e| InitProcessError::VirtualInterfaceError(e.to_string()))?;
    info!("仮想NICの作成に成功しました: {}", virtual_interface.name());

    setup_interface(
        &config.network.tap_interface_name,
        &format!("{}/{}", config.network.tap_ip, config.network.tap_mask),
    ).await?;

    // ネットワークインターフェースの選択
    let interface = select_device(config.network.docker_mode, &config.network.docker_interface_name)
        .map_err(|e| InitProcessError::DeviceSelectionError(e.to_string()))?;
    info!("デバイスの選択に成功しました: {}", interface.name);

    // タスクスケジューラの起動
    let scheduler = TaskScheduler::new(interface);
    if let Err(|e| InitProcessError::TaskExecutionProcessError(e)) = scheduler.run().await {
        error!("タスクスケジューラでエラーが発生: {}", e);
        std::process::exit(1);
    }

    info!("アプリケーションを正常終了します");
    Ok(())
}
