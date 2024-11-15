use thiserror::Error;

#[derive(Error, Debug)]
pub enum WriterError {
    #[error("パケットバッファのフラッシュに失敗しました: {0}")]
    PacketBufferFlushError(String),

}
