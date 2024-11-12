use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("環境変数ファイルの読み込みに失敗しました: {0}")]
    EnvFileReadError(String),

    #[error("環境変数の取得に失敗しました: {0}")]
    EnvVarError(String),

    #[error("環境変数の解析に失敗しました: {0}")]
    EnvVarParseError(String),
}
