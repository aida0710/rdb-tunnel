use crate::database::error::DatabaseError;
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use std::sync::OnceLock;
use std::time::Duration;
use tokio_postgres::NoTls;

pub(crate) static DATABASE_POOL: OnceLock<DatabasePool> = OnceLock::new();

#[derive(Debug)]
pub struct DatabasePool {
    pool: Pool<PostgresConnectionManager<NoTls>>,
}

impl DatabasePool {
    pub async fn new(connection_string: &str) -> Result<Self, DatabaseError> {
        let manager = PostgresConnectionManager::new_from_stringlike(connection_string, NoTls).map_err(DatabaseError::ConnectionManagerError)?;
        let pool = Pool::builder()
            .max_size(30)
            .min_idle(Some(10))
            .connection_timeout(Duration::from_secs(10))
            .idle_timeout(Some(Duration::from_secs(60)))
            .max_lifetime(Some(Duration::from_secs(1800)))
            .build(manager)
            .await
            .map_err(|e| DatabaseError::CreatePoolError(e.to_string()))?;

        Ok(Self { pool })
    }

    pub async fn initialize(host: &str, port: u16, user: &str, password: &str, database: &str) -> Result<(), DatabaseError> {
        let connection_string = format!("postgres://{}:{}@{}:{}/{}", user, password, host, port, database);
        let pool = Self::new(&connection_string).await?;

        // 接続テスト
        let (client, connection) = tokio_postgres::connect(&connection_string, NoTls).await.map_err(|e| {
            eprintln!("接続エラー: {:?}", e);
            DatabaseError::InitFailedConnectDatabase(e.to_string())
        })?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("接続エラー: {}", e);
            }
        });

        drop(client);

        DATABASE_POOL.set(pool).map_err(|_| DatabaseError::InitializationError)?;
        Ok(())
    }

    pub fn get_pool() -> Result<&'static DatabasePool, DatabaseError> {
        DATABASE_POOL.get().ok_or(DatabaseError::PoolNotInitialized)
    }

    pub fn inner(&self) -> &Pool<PostgresConnectionManager<NoTls>> {
        &self.pool
    }
}
