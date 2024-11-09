use crate::interface::error::InterfaceError;
use futures::TryStreamExt;
use ipnetwork::{IpNetwork, IpNetworkError};
use rtnetlink::new_connection;

pub async fn setup_interface(tap_interface_name: &str, ip: &str) -> Result<(), InterfaceError> {
    // IPアドレスのパース
    let ip_net: IpNetwork = ip.parse()
        .map_err(|e: IpNetworkError| InterfaceError::PurseIpAddressError(e.to_string()))?;

    // netlinkコネクションの作成
    let (connection, handle, _) =
        new_connection().map_err(|e| InterfaceError::CreateNetlinkConnectionError(e.to_string()))?;
    tokio::spawn(connection);

    // インターフェースIDの取得
    let interface = handle.link().get()
        .match_name(tap_interface_name.to_string())
        .execute()
        .try_next()
        .await
        .map_err(|e| InterfaceError::RetrieveInterfaceInfoError(e.to_string()))?
        .ok_or_else(|| InterfaceError::InterfaceNotFoundError)?;

    let if_index = interface.header.index;

    // IPアドレスの設定
    handle.address().add(
        if_index,
        ip_net.ip(),
        ip_net.prefix(),
    ).execute().await
        .map_err(|e| InterfaceError::SetTapInterfaceAddressError(e.to_string()))?;

    // インターフェースの有効化
    handle.link().set(if_index)
        .up()
        .execute()
        .await
        .map_err(|e| InterfaceError::ActivateTapInterfaceError(e.to_string()))?;

    Ok(())
}