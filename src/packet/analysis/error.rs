use log::error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PacketAnalysisError {
    #[error("インターフェース {0} が見つかりません")]
    InterfaceNotFound(String),

}