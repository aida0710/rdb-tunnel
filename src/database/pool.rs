use crate::database::error::DbError;
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use std::sync::OnceLock;
use std::time::Duration;
use tokio_postgres::NoTls;

pub(crate) static DATABASE_POOL: OnceLock<DbPool> = OnceLock::new();

pub struct DbPool {
    pool: Pool<PostgresConnectionManager<NoTls>>,
}

impl DbPool {
    pub async fn new(connection_string: &str) -> Result<Self, DbError> {
        let manager = PostgresConnectionManager::new_from_stringlike(connection_string, NoTls)?;
        let pool = Pool::builder()
            .max_size(50)                    // 並列処理数を増やす
            .min_idle(Some(8))               // アイドル接続を維持
            .connection_timeout(Duration::from_secs(5))  // タイムアウトを短く
            .idle_timeout(Some(Duration::from_secs(60))) // アイドルタイムアウト
            .max_lifetime(Some(Duration::from_secs(3600))) // 接続の最大寿命
            .build(manager)
            .await?;
        Ok(Self { pool })
    }

    pub async fn initialize(
        host: &str,
        port: u16,
        user: &str,
        password: &str,
        database: &str,
    ) -> Result<(), DbError> {
        let connection_string = format!(
            "postgres://{}:{}@{}:{}/{}",
            user, password, host, port, database
        );
        let pool = Self::new(&connection_string).await?;

        // 接続テスト
        let (client, connection) = tokio_postgres::connect(&connection_string, NoTls).await?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("接続エラー: {}", e);
            }
        });

        drop(client);

        DATABASE_POOL.set(pool).map_err(|_| DbError::Initialization)?;
        Ok(())
    }

    pub(crate) fn get_pool() -> &'static DbPool {
        DATABASE_POOL.get().expect("データベースプールが初期化されていません")
    }

    pub(crate) fn inner(&self) -> &Pool<PostgresConnectionManager<NoTls>> {
        &self.pool
    }
}