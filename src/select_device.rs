use log::info;
use pnet::datalink::{self, NetworkInterface};
use std::io::{self, Write};

pub fn select_device(docker_mode: bool, docker_interface_name: &str) -> Result<NetworkInterface, String> {
    let interfaces = datalink::interfaces();

    if interfaces.is_empty() {
        return Err("利用可能なネットワークインターフェースがありません".to_string());
    }

    // Dockerモードの場合はインターフェイスの自動選択
    if docker_mode {
        info!("Docker Modeが有効な為、{}インターフェイスで自動実行されます。", docker_interface_name);
        return if let Some(interface) = interfaces.iter().find(|interface| interface.name == docker_interface_name) {
            Ok(interface.clone())
        } else {
            Err(format!("指定されたDocker使用時のインターフェース{}が見つかりません", docker_interface_name))
        };
    }

    // 通常モードの場合は対話的に選択
    println!("\n利用可能なネットワークインターフェース:");
    for (idx, interface) in interfaces.iter().enumerate() {
        println!("{}. {} ({})",
                 idx + 1,
                 interface.name,
                 interface.description
        );
    }

    print!("\nインターフェースを選択してください [1-{}]: ", interfaces.len());
    io::stdout().flush().map_err(|e| e.to_string())?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;

    let selection = input.trim().parse::<usize>()
        .map_err(|_| "無効な選択です".to_string())?;

    if selection < 1 || selection > interfaces.len() {
        return Err("選択範囲外です".to_string());
    }

    Ok(interfaces[selection - 1].clone())
}
