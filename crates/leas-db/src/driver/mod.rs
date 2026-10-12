//! Local-only fork of `toasty-driver-turso`, owned by this crate.
//!
//! Why this exists (see `docs/aegis/specs/2026-10-08-db-adapter-and-migrations-design.md` §12):
//! the published driver routes EVERY statement through the connection's
//! `prepare_cached`, whose map is unbounded and keyed by SQL text. Our bulk
//! writers inline their literals (the engine charges ~0.8 ms per bound
//! parameter), so every window is a new text — a compiled program cached
//! forever. Owning the driver is what lets us route the cache at its
//! boundary, and it pins `turso` directly (0.8) instead of waiting on a
//! toasty release.
//!
//! Vendored from `thirdparty/toasty` (dev `main`, already on `turso = "0.8"`)
//! and reduced to the LOCAL engine only: the sync (`turso::sync`) and
//! serverless (`turso_serverless`) arms are dropped. This crate is a file/
//! in-memory database; nothing here talks to a remote.
//!
//! **This is INTERNAL code, not a tracking fork (decision 2026-10-08).** It is
//! not exposed to any other crate and will never be reused outside
//! `leas-db`, so it is maintained IN-HOUSE against what `turso` actually
//! does — no obligation to mirror upstream's shape, only to keep the nine
//! `toasty_core::driver` trait impls compiling. The consequence to weigh before
//! a `toasty-core` bump: `Driver`/`Connection` are the seam the engine calls, so
//! a bump can break these impls and the fix is ours. `turso` itself is pinned
//! directly (currently 0.8.2) and bumped when we want it.
//!
//! Where a line matches upstream it costs nothing and helps a reader diff a
//! puzzling spot against `thirdparty/toasty`; where our needs differ, ours win.
//!
//! The vendored code owns all NINE required trait methods — `Driver::{url,
//! capability, connect, generate_migration, reset_db}` and
//! `Connection::{exec, push_schema, applied_migrations, apply_migration}`.
//!
//! The pedantic lints below are style preferences this code does not follow
//! (builder methods returning `Self`, bool-flag structs); they are not defects.
#![allow(
    clippy::must_use_candidate,
    clippy::return_self_not_must_use,
    clippy::missing_const_for_fn,
    clippy::struct_excessive_bools,
    clippy::needless_pass_by_ref_mut,
    reason = "vendored driver style; these pedantic lints are not defects"
)]

mod error;
mod value;
pub use turso::EncryptionOpts;

/// The raw-value decode (`turso::Value` → toasty `Value`, by SQLite storage
/// class) for the app's direct reader (`profiles_query`), which bypasses the
/// driver to avoid Toasty's execution layer.
pub(crate) use value::from_turso_infer;

use async_trait::async_trait;
use std::borrow::Cow;
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use toasty_core::{
    Result, Schema,
    driver::{
        Capability, ConnectContext, Driver, ExecResponse, QueryLogConfig,
        log::QueryLog,
        operation::{
            IsolationLevel, Operation, RawSqlRet, Transaction, TransactionMode, TypedValue,
        },
    },
    schema::db::{self, Migration, Table},
    stmt,
};
use toasty_sql::{self as sql};
use tokio::sync::Mutex;
use turso::{Builder, Database, Value as TursoValue};

use error::classify_turso_error;
use value::to_turso;

/// The return shape of a statement, mirroring the driver's internal
/// `SqlReturn`.
enum SqlReturn {
    Count,
    Infer,
    Types(Vec<stmt::Type>),
}

/// Which prepare path a statement takes.
///
/// `Cached` is correct for engine-generated SQL: its text is stable, so the
/// per-connection cache compiles it once. `Uncached` is required for the
/// hand-built, literal-inlined statements (`Operation::RawSql`) — their text
/// is unique per call, so `prepare_cached` would grow the cache without bound
/// (the leak this fork exists to fix).
#[derive(Clone, Copy)]
enum Prepare {
    Cached,
    Uncached,
}

const CREATE_MIGRATIONS_TABLE: &str = "\
CREATE TABLE IF NOT EXISTS __toasty_migrations (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )";

fn create_table_stmts(schema: &db::Schema, table: &Table) -> Vec<String> {
    let serializer = sql::Serializer::sqlite(schema);

    let mut stmts =
        vec![serializer.serialize(&sql::Statement::create_table(table, &Capability::SQLITE))];

    for index in &table.indices {
        if index.primary_key {
            continue;
        }
        stmts.push(serializer.serialize(&sql::Statement::create_index(index)));
    }

    stmts
}

/// Retries an operation while the database reports a retryable conflict
/// (busy write lock, MVCC serialization failure).
async fn retry_while_busy<T, F, Fut>(mut op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    const RETRY_FOR: Duration = Duration::from_secs(10);

    let deadline = Instant::now() + RETRY_FOR;
    let mut delay = Duration::from_millis(10);
    loop {
        match op().await {
            Err(err) if err.is_serialization_failure() && Instant::now() < deadline => {
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_millis(250));
            }
            res => return res,
        }
    }
}

/// Executes parameterized statements atomically inside a `BEGIN IMMEDIATE`
/// transaction. On failure nothing stays applied, so callers may retry.
async fn transactional_batch(
    conn: &turso::Connection,
    stmts: &[(String, Vec<TursoValue>)],
) -> Result<()> {
    conn.execute("BEGIN IMMEDIATE", ())
        .await
        .map_err(classify_turso_error)?;
    for (sql, params) in stmts {
        if let Err(err) = conn.execute(sql.as_str(), params.clone()).await {
            let _ = conn.execute("ROLLBACK", ()).await;
            return Err(classify_turso_error(err));
        }
    }
    if let Err(err) = conn.execute("COMMIT", ()).await {
        let _ = conn.execute("ROLLBACK", ()).await;
        return Err(classify_turso_error(err));
    }
    Ok(())
}

async fn exec_ddl(
    conn: &turso::Connection,
    statements: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<()> {
    let stmts: Vec<(String, Vec<TursoValue>)> = statements
        .into_iter()
        .map(|sql| (sql.as_ref().to_string(), vec![]))
        .collect();

    retry_while_busy(|| transactional_batch(conn, &stmts)).await
}

#[derive(Debug, Clone)]
enum TursoPath {
    File(PathBuf),
    InMemory,
}

/// Opt-in flags for Turso's experimental features. Each field mirrors a
/// `turso::Builder::experimental_*` method and is applied in
/// [`LocalBuilderOptions::apply`] when the driver constructs a fresh
/// [`turso::Builder`] at connection time.
#[derive(Debug, Default, Clone)]
struct LocalBuilderOptions {
    encryption: Option<EncryptionOpts>,
    attach: bool,
    custom_types: bool,
    generated_columns: bool,
    materialized_views: bool,
    vacuum: bool,
    multiprocess_wal: bool,
    without_rowid: bool,
    /// Turso's passive-checkpoint flag. Reachable so a later MVCC
    /// experiment (spec §12, stage S6) can enable `wal_checkpoint(PASSIVE)`
    /// under MVCC.
    mvcc_passive_checkpoint: bool,
}

impl LocalBuilderOptions {
    fn apply(&self, mut b: Builder) -> Builder {
        if let Some(opts) = &self.encryption {
            // Upstream requires *both* the feature flag and the key/cipher
            // to be set; collapse them into a single call so callers can't
            // get into a half-configured state.
            b = b
                .experimental_encryption(true)
                .with_encryption(opts.clone());
        }
        if self.attach {
            b = b.experimental_attach(true);
        }
        if self.custom_types {
            b = b.experimental_custom_types(true);
        }
        if self.generated_columns {
            b = b.experimental_generated_columns(true);
        }
        if self.materialized_views {
            b = b.experimental_materialized_views(true);
        }
        if self.vacuum {
            b = b.experimental_vacuum(true);
        }
        if self.multiprocess_wal {
            b = b.experimental_multiprocess_wal(true);
        }
        if self.without_rowid {
            b = b.experimental_without_rowid(true);
        }
        if self.mvcc_passive_checkpoint {
            b = b.experimental_mvcc_passive_checkpoint(true);
        }
        b
    }
}

#[derive(Debug, Default, Clone)]
struct BuilderOptions {
    index_method: bool,
    transaction_mode: TransactionMode,
    local_options: LocalBuilderOptions,
}

impl BuilderOptions {
    fn apply_local(&self, mut b: Builder) -> Builder {
        b = self.local_options.apply(b);
        if self.index_method {
            b = b.experimental_index_method(true);
        }
        b
    }
}

/// A Turso [`Driver`] that opens connections to a file or in-memory
/// database.
///
/// This is the crate's LOCAL-ONLY fork of `toasty-driver-turso` (see the
/// module docs).
#[derive(Clone)]
pub struct Turso {
    path: TursoPath,
    options: BuilderOptions,
    concurrent_writes: bool,
    /// Shared database handle reused across every `connect()` call so that
    /// all pool slots see the same underlying database (otherwise each
    /// `:memory:` connection would open a fresh empty database). Cleared by
    /// [`Driver::reset_db`] so the next `connect()` starts fresh.
    database: Arc<Mutex<Option<Database>>>,
}

impl Turso {
    /// Create an in-memory Turso database.
    pub fn in_memory() -> Self {
        Self::with_path(TursoPath::InMemory)
    }

    /// Open a Turso database at the specified file path.
    pub fn file<P: AsRef<Path>>(path: P) -> Self {
        Self::with_path(TursoPath::File(path.as_ref().to_path_buf()))
    }

    fn with_path(path: TursoPath) -> Self {
        Self {
            path,
            options: BuilderOptions::default(),
            concurrent_writes: false,
            database: Arc::new(Mutex::new(None)),
        }
    }

    /// Allow transactions to run concurrently instead of serializing on a
    /// single writer.
    ///
    /// When enabled, each new connection switches to Turso's MVCC journal
    /// (`PRAGMA journal_mode = 'mvcc'`) and a transaction started with
    /// [`TransactionMode::Default`] issues `BEGIN CONCURRENT`. This is how
    /// the app's `LEAS_TURSO_CONCURRENT_WRITES` opt-in is wired.
    pub fn concurrent_writes(mut self) -> Self {
        self.concurrent_writes = true;
        self
    }

    /// Set the mode used when a transaction requests
    /// [`TransactionMode::Default`].
    pub fn with_transaction_mode(mut self, mode: TransactionMode) -> Self {
        self.options.transaction_mode = mode;
        self
    }

    /// Enable Turso's experimental index methods. Mirrors
    /// `turso::Builder::experimental_index_method`.
    pub fn experimental_index_method(mut self, on: bool) -> Self {
        self.options.index_method = on;
        self
    }

    /// Enable Turso's experimental encryption with the given cipher and key.
    pub fn experimental_encryption(mut self, opts: EncryptionOpts) -> Self {
        self.options.local_options.encryption = Some(opts);
        self
    }

    /// Enable Turso's experimental `ATTACH DATABASE` support.
    pub fn experimental_attach(mut self, on: bool) -> Self {
        self.options.local_options.attach = on;
        self
    }

    /// Enable Turso's experimental custom types.
    pub fn experimental_custom_types(mut self, on: bool) -> Self {
        self.options.local_options.custom_types = on;
        self
    }

    /// Enable Turso's experimental generated columns.
    pub fn experimental_generated_columns(mut self, on: bool) -> Self {
        self.options.local_options.generated_columns = on;
        self
    }

    /// Enable Turso's experimental materialized views.
    pub fn experimental_materialized_views(mut self, on: bool) -> Self {
        self.options.local_options.materialized_views = on;
        self
    }

    /// Enable Turso's experimental `VACUUM`.
    pub fn experimental_vacuum(mut self, on: bool) -> Self {
        self.options.local_options.vacuum = on;
        self
    }

    /// Enable Turso's experimental multi-process WAL.
    pub fn experimental_multiprocess_wal(mut self, on: bool) -> Self {
        self.options.local_options.multiprocess_wal = on;
        self
    }

    /// Enable Turso's experimental `WITHOUT ROWID` support.
    ///
    /// NB: turso's `WITHOUT ROWID` is insert-only (DELETE/UPDATE are
    /// refused), so no table in this crate uses it — this only mirrors the
    /// builder surface.
    pub fn experimental_without_rowid(mut self, on: bool) -> Self {
        self.options.local_options.without_rowid = on;
        self
    }

    /// Enable Turso's experimental passive-checkpoint mode (required for
    /// `wal_checkpoint(PASSIVE)` under MVCC).
    pub fn experimental_mvcc_passive_checkpoint(mut self, on: bool) -> Self {
        self.options.local_options.mvcc_passive_checkpoint = on;
        self
    }

    fn path_str(&self) -> &str {
        match &self.path {
            TursoPath::File(p) => p.to_str().unwrap_or(":memory:"),
            TursoPath::InMemory => ":memory:",
        }
    }

    /// Returns the cached database handle, opening it on first use.
    async fn database(&self) -> Result<Database> {
        let mut slot = self.database.lock().await;
        if let Some(db) = slot.as_ref() {
            return Ok(db.clone());
        }

        let builder = self
            .options
            .apply_local(Builder::new_local(self.path_str()));
        let db = builder.build().await.map_err(classify_turso_error)?;

        *slot = Some(db.clone());
        Ok(db)
    }
}

impl fmt::Debug for Turso {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Turso")
            .field("path", &self.path)
            .field("concurrent_writes", &self.concurrent_writes)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Driver for Turso {
    fn url(&self) -> Cow<'_, str> {
        match &self.path {
            TursoPath::InMemory => Cow::Borrowed("turso::memory:"),
            TursoPath::File(path) => Cow::Owned(format!("turso:{}", path.display())),
        }
    }

    fn capability(&self) -> &'static Capability {
        &Capability::TURSO
    }

    async fn connect(&self, cx: &ConnectContext) -> Result<Box<dyn toasty_core::Connection>> {
        let conn = self
            .database()
            .await?
            .connect()
            .map_err(classify_turso_error)?;

        if self.concurrent_writes {
            // `PRAGMA journal_mode = ...` returns the new mode as a row;
            // the `execute` path errors with "unexpected row during
            // execution" on any pragma that emits one. Use `pragma_update`
            // so the row is consumed.
            conn.pragma_update("journal_mode", "'mvcc'")
                .await
                .map_err(classify_turso_error)?;
        }

        let default_begin_sql = match self.options.transaction_mode {
            TransactionMode::Default => {
                if self.concurrent_writes {
                    "BEGIN CONCURRENT"
                } else {
                    "BEGIN"
                }
            }
            TransactionMode::Deferred => "BEGIN DEFERRED",
            TransactionMode::Immediate => "BEGIN IMMEDIATE",
            TransactionMode::Exclusive => "BEGIN EXCLUSIVE",
        };

        Ok(Box::new(Connection {
            conn,
            default_begin_sql,
            query_log: cx.query_log,
        }))
    }

    fn generate_migration(&self, schema_diff: &toasty_core::schema::diff::Schema<'_>) -> Migration {
        let statements = sql::MigrationStatement::from_diff(schema_diff, &Capability::SQLITE);

        let sql_strings: Vec<String> = statements
            .iter()
            .map(|stmt| sql::Serializer::sqlite(stmt.schema()).serialize(stmt.statement()))
            .collect();

        Migration::new_sql_with_breakpoints(&sql_strings)
    }

    async fn reset_db(&self) -> Result<()> {
        // Drop the cached Database so subsequent `connect()` calls open a
        // fresh one. For in-memory this is the only way to wipe state;
        // for file-backed databases the file is also removed below.
        self.database.lock().await.take();

        if let TursoPath::File(path) = &self.path
            && path.exists()
        {
            std::fs::remove_file(path).map_err(toasty_core::Error::driver_operation_failed)?;
        }

        Ok(())
    }
}

/// An open connection to a Turso database.
pub struct Connection {
    conn: turso::Connection,
    /// SQL to issue for [`TransactionMode::Default`], resolved from the
    /// driver's configured mode and MVCC default at `connect()` time.
    default_begin_sql: &'static str,
    query_log: QueryLogConfig,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection").finish()
    }
}

impl Connection {
    async fn exec_sql(
        &mut self,
        sql_str: &str,
        typed_params: Vec<TypedValue>,
        ret: SqlReturn,
        prepare: Prepare,
    ) -> Result<ExecResponse> {
        let mut log = QueryLog::sql(
            &self.query_log,
            "turso",
            sql_str,
            typed_params.iter().map(|tv| &tv.value),
        );
        let result = self
            .exec_sql_inner(sql_str, typed_params, ret, prepare, &mut log)
            .await;
        log.finish(&result);
        result
    }

    async fn exec_sql_inner(
        &mut self,
        sql_str: &str,
        typed_params: Vec<TypedValue>,
        ret: SqlReturn,
        prepare: Prepare,
        log: &mut QueryLog<'_>,
    ) -> Result<ExecResponse> {
        let params: Vec<TursoValue> = typed_params.iter().map(|tv| to_turso(&tv.value)).collect();

        let mut stmt = match prepare {
            Prepare::Cached => self.conn.prepare_cached(sql_str).await,
            Prepare::Uncached => self.conn.prepare(sql_str).await,
        }
        .map_err(classify_turso_error)?;

        if matches!(ret, SqlReturn::Count) {
            let count = stmt.execute(params).await.map_err(classify_turso_error)?;

            return Ok(ExecResponse::count(count));
        }

        let mut rows = stmt.query(params).await.map_err(classify_turso_error)?;

        let mut values = vec![];

        while let Some(row) = rows.next().await.map_err(classify_turso_error)? {
            let items = match &ret {
                SqlReturn::Count => unreachable!(),
                SqlReturn::Infer => {
                    let mut items = vec![];
                    for index in 0..row.column_count() {
                        items.push(value::from_turso_infer(
                            row.get_value(index).map_err(classify_turso_error)?,
                        ));
                    }
                    items
                }
                SqlReturn::Types(ret_tys) => {
                    let mut items = Vec::with_capacity(ret_tys.len());
                    for (index, ret_ty) in ret_tys.iter().enumerate() {
                        items.push(value::from_turso(
                            row.get_value(index).map_err(classify_turso_error)?,
                            ret_ty,
                        ));
                    }
                    items
                }
            };

            values.push(stmt::ValueRecord::from_vec(items).into());
        }

        log.rows(values.len() as u64);
        Ok(ExecResponse::value_stream(stmt::ValueStream::from_vec(
            values,
        )))
    }
}

#[async_trait]
impl toasty_core::driver::Connection for Connection {
    async fn exec(&mut self, schema: &Arc<Schema>, op: Operation) -> Result<ExecResponse> {
        tracing::trace!(driver = "turso", op = %op.name(), "driver exec");

        let (sql, typed_params, ret_tys, prepare) = match op {
            Operation::Insert(op) => (
                sql::Statement::from(op.stmt),
                op.params,
                op.ret,
                Prepare::Cached,
            ),
            Operation::QuerySql(op) => (
                sql::Statement::from(op.stmt),
                op.params,
                op.ret,
                Prepare::Cached,
            ),
            Operation::RawSql(op) => {
                let ret = match op.ret {
                    RawSqlRet::None => SqlReturn::Count,
                    RawSqlRet::Infer => SqlReturn::Infer,
                    RawSqlRet::Types(types) => SqlReturn::Types(types),
                };
                // Hand-built, literal-inlined SQL: its text is unique per
                // call, so it must NOT go through the per-connection cache.
                return self
                    .exec_sql(&op.sql, op.params, ret, Prepare::Uncached)
                    .await;
            }
            Operation::Transaction(op) => {
                if let Transaction::Start { isolation, .. } = &op
                    && !matches!(isolation, Some(IsolationLevel::Serializable) | None)
                {
                    return Err(toasty_core::Error::unsupported_feature(
                        "Turso only supports Serializable isolation",
                    ));
                }
                // `default_begin_sql` is the connection's "no opinion" BEGIN
                // — `BEGIN` for classic mode, `BEGIN CONCURRENT` for MVCC —
                // and the serializer maps the other `TransactionMode`s to
                // standard SQLite SQL.
                let sql_str =
                    sql::Serializer::sqlite_with_default_begin(&schema.db, self.default_begin_sql)
                        .serialize_transaction(&op);
                self.conn
                    .execute(&sql_str, ())
                    .await
                    .map_err(classify_turso_error)?;
                return Ok(ExecResponse::count(0));
            }
            _ => todo!("op={op:#?}"),
        };

        let ret = if sql.returning_len().is_some() {
            SqlReturn::Types(ret_tys.unwrap())
        } else {
            SqlReturn::Count
        };

        let sql_str = sql::Serializer::sqlite(&schema.db).serialize(&sql);
        self.exec_sql(&sql_str, typed_params, ret, prepare).await
    }

    async fn push_schema(&mut self, schema: &Schema) -> Result<()> {
        let mut statements = vec![];
        for table in &schema.db.tables {
            tracing::debug!(table = %table.name, "creating table");
            statements.extend(create_table_stmts(&schema.db, table));
        }

        exec_ddl(&self.conn, &statements).await
    }

    async fn applied_migrations(
        &mut self,
    ) -> Result<Vec<toasty_core::schema::db::AppliedMigration>> {
        exec_ddl(&self.conn, [CREATE_MIGRATIONS_TABLE]).await?;

        let mut rows = self
            .conn
            .query("SELECT id FROM __toasty_migrations ORDER BY applied_at", ())
            .await
            .map_err(classify_turso_error)?;

        let mut migrations = vec![];
        while let Some(row) = rows.next().await.map_err(classify_turso_error)? {
            if let TursoValue::Integer(id) = row.get_value(0).map_err(classify_turso_error)? {
                migrations.push(toasty_core::schema::db::AppliedMigration::new(
                    id.cast_unsigned(),
                ));
            }
        }

        Ok(migrations)
    }

    async fn apply_migration(
        &mut self,
        id: u64,
        name: &str,
        migration: &toasty_core::schema::db::Migration,
    ) -> Result<()> {
        tracing::info!(id = id, name = %name, "applying migration");

        // The whole migration — DDL plus the parameterized bookkeeping
        // INSERT — is one atomic transactional batch.
        let mut stmts: Vec<(String, Vec<TursoValue>)> =
            vec![(CREATE_MIGRATIONS_TABLE.to_string(), vec![])];
        for statement in migration.statements() {
            stmts.push((statement.to_string(), vec![]));
        }
        stmts.push((
            "INSERT INTO __toasty_migrations (id, name, applied_at) VALUES (?1, ?2, datetime('now'))"
                .to_string(),
            vec![TursoValue::Integer(id.cast_signed()), TursoValue::Text(name.to_string())],
        ));

        retry_while_busy(|| transactional_batch(&self.conn, &stmts)).await
    }
}
