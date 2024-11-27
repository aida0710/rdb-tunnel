use crate::database::error::DatabaseError;
use crate::database::pool::DatabasePool;
use async_trait::async_trait;
use std::collections::HashMap;
use tokio_postgres::{Row, Statement};

#[async_trait]
pub trait ExecuteQuery {
    async fn execute(&self, query: &str, params: &[&(dyn tokio_postgres::types::ToSql + Sync)]) -> Result<u64, DatabaseError>;
    async fn query(&self, query: &str, params: &[&(dyn tokio_postgres::types::ToSql + Sync)]) -> Result<Vec<Row>, DatabaseError>;
}

pub struct Database {
    prepared_statements: HashMap<String, Statement>,
}

impl Database {
    pub async fn connect(host: &str, port: u16, user: &str, password: &str, database: &str) -> Result<(), DatabaseError> {
        DatabasePool::initialize(host, port, user, password, database).await
    }

    pub fn get_database() -> &'static Self {
        // DbPoolの存在を確認
        let _ = DatabasePool::get_pool();
        // Databaseはステートレスなので、staticなインスタンスを返す
        static DATABASE: std::sync::OnceLock<Database> = std::sync::OnceLock::new();
        DATABASE.get_or_init(|| Database {
            prepared_statements: HashMap::new(),
        })
    }

    pub async fn transaction<F, T>(&self, f: F) -> Result<T, DatabaseError>
    where
        F: for<'a> FnOnce(&'a mut tokio_postgres::Transaction<'_>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, DatabaseError>> + Send + 'a>>,
    {
        let pool = DatabasePool::get_pool()?;
        let mut client = pool.inner().get().await.map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;
        let mut tx = client.transaction().await.map_err(|e| DatabaseError::TransactionError(e.to_string()))?;

        match f(&mut tx).await {
            Ok(result) => {
                tx.commit().await.map_err(|e| DatabaseError::TransactionError(e.to_string()))?;
                Ok(result)
            },
            Err(e) => {
                tx.rollback().await.map_err(|e| DatabaseError::TransactionError(e.to_string()))?;
                Err(e)
            },
        }
    }
}

#[async_trait]
impl ExecuteQuery for Database {
    async fn execute(&self, query: &str, params: &[&(dyn tokio_postgres::types::ToSql + Sync)]) -> Result<u64, DatabaseError> {
        let pool = DatabasePool::get_pool().map_err(|e| DatabaseError::PoolRetrievalError(e.to_string()))?;
        let client = pool.inner().get().await.map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;

        // プリペアドステートメントのキャッシュを試みる
        let stmt = if let Some(stmt) = self.prepared_statements.get(query) {
            stmt.clone()
        } else {
            client.prepare(query).await.map_err(|e| DatabaseError::QueryPreparationError(e.to_string()))?
        };

        let result = client.execute(&stmt, params).await.map_err(|e| DatabaseError::QueryExecutionError(e.to_string()))?;
        Ok(result)
    }

    async fn query(&self, query: &str, params: &[&(dyn tokio_postgres::types::ToSql + Sync)]) -> Result<Vec<Row>, DatabaseError> {
        let pool = DatabasePool::get_pool().map_err(|e| DatabaseError::PoolRetrievalError(e.to_string()))?;
        let client = pool.inner().get().await.map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;

        // プリペアドステートメントのキャッシュを試みる
        let stmt = if let Some(stmt) = self.prepared_statements.get(query) {
            stmt.clone()
        } else {
            client.prepare(query).await.map_err(|e| DatabaseError::QueryPreparationError(e.to_string()))?
        };

        let rows = client.query(&stmt, params).await.map_err(|e| DatabaseError::QueryExecutionError(e.to_string()))?;
        Ok(rows)
    }
}
