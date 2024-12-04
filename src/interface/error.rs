use thiserror::Error;

#[derive(Error, Debug)]
pub enum InterfaceError {
    // select_device
    #[error("利用可能なネットワークインターフェースがありません")]
    NoAvailableNetworkInterfaceError,

    #[error("指定されたDocker使用時のインターフェースが見つかりません: {0}")]
    DockerInterfaceNotFound(String),

    #[error("標準出力のフラッシュに失敗しました: {0}")]
    StdoutFlushError(String),

    #[error("標準入力の行読み取りに失敗しました: {0}")]
    ReadLineError(String),

    #[error("入力された値は無効なインターフェイス番号です")]
    InvalidInterfaceNumberError(String),

    #[error("入力された値は指定範囲外のインターフェイス番号です")]
    OutOfRangeInterfaceNumberError,
}
