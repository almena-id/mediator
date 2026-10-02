//! Almena ID mediator (DIDComm Messaging v2.0).

pub mod config;
pub mod dispatch;
pub mod home;
pub mod identity;
pub mod metrics;
pub mod oob;
pub mod push;
pub mod routes;
pub mod store;
#[cfg(test)]
mod testing;
pub mod transport;

pub use config::Config;

/// The mediator's version: `ALMENA_VERSION` when the build sets it (the
/// Docker image's `year.month.sequence`, see `.github/workflows/docker.yml`),
/// else the crate version.
pub const VERSION: &str = match option_env!("ALMENA_VERSION") {
    Some(version) if !version.is_empty() => version,
    _ => env!("CARGO_PKG_VERSION"),
};
pub use routes::{AppState, router};
