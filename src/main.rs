mod config;
mod database;
mod error;
mod interface;
mod logger;
mod packet;
mod tasks;
mod utils;

use crate::config::AppConfig;
use crate::database::Database;
use crate::error::InitProcessError;
use crate::interface::{select_interface, setup_interface};
use crate::logger::setup_logger::setup_logger;
use crate::tasks::TaskScheduler;
use log::{error, info};
use tun_tap::{Iface, Mode};

#[tokio::main]
async fn main() -> Result<(), InitProcessError> {
    // 設定の読み込み
    let config: AppConfig =
        AppConfig::new().map_err(|e| InitProcessError::ConfigurationError(e.to_string()))?;

    // ロガーのセットアップ
    setup_logger(config.logger_config).map_err(|e| InitProcessError::LoggerError(e.to_string()))?;

    info!("loggerが正常にセットアップされました");
    idps_log!("idps logの表示が有効になっています");

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

    if config.network.use_tap_interface {
        // 仮想インターフェースのセットアップ
        let virtual_interface = Iface::new(&config.network.tap_interface_name, Mode::Tap)
            .map_err(|e| InitProcessError::VirtualInterfaceCreateError(e.to_string()))?;
        info!("仮想NICの作成に成功しました: {}", virtual_interface.name());

        setup_interface(
            &config.network.tap_interface_name,
            &format!("{}/{}", config.network.tap_ip, config.network.tap_mask),
        )
        .await
        .map_err(|e| InitProcessError::VirtualInterfaceSetupError(e.to_string()))?;
    }

    // ネットワークインターフェースの選択
    let interface = select_interface(
        config.network.docker_mode,
        &config.network.docker_interface_name,
    )
    .map_err(|e| InitProcessError::InterfaceSelectionError(e.to_string()))?;
    info!("デバイスの選択に成功しました: {}", interface.name);

    // タスクスケジューラの起動
    let scheduler = TaskScheduler::new(interface);
    if let Err(e) = scheduler
        .run()
        .await
        .map_err(|e| InitProcessError::TaskExecutionProcessError(e.to_string()))
    {
        error!("タスクの実行処理に失敗しました: {:?}", e);
        std::process::exit(1);
    }

    info!("アプリケーションを正常終了します");
    Ok(())
}
