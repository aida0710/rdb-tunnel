use log::error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PacketAnalysisError {
    #[error("インターフェース {0} が見つかりません")]
    InterfaceNotFound(String),

    #[error("Ethernet Frameのサイズが不正です: {0}")]
    InvalidEthernetFrameSize(String),
}