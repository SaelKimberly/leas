#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("toasty error: {0}")]
    Toasty(#[from] toasty::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("uuid error: {0}")]
    Uuid(#[from] uuid::Error),
    #[error("{0}")]
    Generic(String),
    /// The database's migration cursor names a schema this build does not
    /// know — a pre-migration or foreign file. Carries that cursor value. The
    /// caller applies its documented recovery (the pre-alpha answer is a wipe);
    /// this is never raised for an older SUPPORTED version, which migrates
    /// instead.
    #[error("incompatible database schema (cursor {0})")]
    IncompatibleSchema(i64),
}

pub type Result<T, E = DatabaseError> = std::result::Result<T, E>;
