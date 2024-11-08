use crate::database::error::DbError;
use crate::database::pool::DbPool;
use async_trait::async_trait;
use tokio_postgres::Row;

#[async_trait]
pub trait ExecuteQuery {
    async fn execute(&self, query: &str, params: &[&(dyn tokio_postgres::types::ToSql + Sync)]) -> Result<u64, DbError>;
    async fn query(&self, query: &str, params: &[&(dyn tokio_postgres::types::ToSql + Sync)]) -> Result<Vec<Row>, DbError>;
}

pub struct Database;

impl Database {
    pub async fn connect(
        host: &str,
        port: u16,
        user: &str,
        password: &str,
        database: &str,
    ) -> Result<(), DbError> {
        DbPool::initialize(host, port, user, password, database).await
    }

    pub fn get_database() -> &'static Self {
        // DbPoolの存在を確認
        let _ = DbPool::get_pool();
        // Databaseはステートレスなので、staticなインスタンスを返す
        static DATABASE: Database = Database;
        &DATABASE
    }
}

#[async_trait]
impl ExecuteQuery for Database {
    async fn execute(&self, query: &str, params: &[&(dyn tokio_postgres::types::ToSql + Sync)]) -> Result<u64, DbError> {
        let pool = DbPool::get_pool();
        let client = pool.inner().get().await?;
        let stmt = client.prepare(query).await?;
        let result = client.execute(&stmt, params).await?;
        Ok(result)
    }

    async fn query(&self, query: &str, params: &[&(dyn tokio_postgres::types::ToSql + Sync)]) -> Result<Vec<Row>, DbError> {
        let pool = DbPool::get_pool();
        let client = pool.inner().get().await?;
        let stmt = client.prepare(query).await?;
        let rows = client.query(&stmt, params).await?;
        Ok(rows)
    }
}
