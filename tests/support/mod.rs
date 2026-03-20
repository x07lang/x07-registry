use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

pub fn test_database_url() -> String {
    std::env::var("X07_REGISTRY_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55432/postgres".to_string())
}

fn postgres_hint(database_url: &str, err: &sqlx::Error) -> String {
    format!(
        "connect postgres ({database_url}) failed: {err}\n\
hint: run `bash scripts/ci/check_local.sh` or set X07_REGISTRY_TEST_DATABASE_URL"
    )
}

pub async fn create_test_schema() -> (String, String) {
    let database_url = test_database_url();
    let schema = format!("test_{}", Uuid::new_v4().simple());

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&database_url)
        .await
        .unwrap_or_else(|err| panic!("{}", postgres_hint(&database_url, &err)));
    sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&pool)
        .await
        .expect("create schema");

    (database_url, schema)
}

#[allow(dead_code)]
pub async fn connect_test_db(database_url: &str, schema: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .after_connect({
            let schema = schema.to_string();
            move |conn, _meta| {
                let schema = schema.clone();
                Box::pin(async move {
                    let stmt = format!("SET search_path TO \"{schema}\", public");
                    sqlx::query(&stmt).execute(conn).await?;
                    Ok(())
                })
            }
        })
        .connect(database_url)
        .await
        .unwrap_or_else(|err| panic!("{}", postgres_hint(database_url, &err)))
}
