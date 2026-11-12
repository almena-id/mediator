//! What the mediator can still take (SPEC.md §11): the mediations held are
//! counted in the background, for `/health` and the metrics. The ceiling
//! itself is checked when granting, in the store.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::metrics::METRICS;
use crate::store::Store;

/// How often the store is sampled.
const SAMPLE_EVERY: Duration = Duration::from_secs(5);

#[derive(Default)]
pub struct Capacity {
    /// Mediations held at the last sample.
    mediations: AtomicU64,
}

impl Capacity {
    /// Mediations held at the last sample.
    pub fn mediations(&self) -> u64 {
        self.mediations.load(Ordering::Relaxed)
    }

    /// Samples the store once. A failed sample keeps what the last one said.
    pub async fn sample(&self, store: &dyn Store) {
        match store.mediation_count().await {
            Ok(count) => {
                self.mediations.store(count, Ordering::Relaxed);
                METRICS.mediations(count);
            }
            Err(err) => {
                METRICS.store_error();
                tracing::warn!(error = %format!("{err:#}"), "mediation count failed");
            }
        }
    }

    /// Samples the store every few seconds in the background, first at once.
    pub fn watch(self: &Arc<Self>, store: Arc<dyn Store>) {
        let capacity = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SAMPLE_EVERY);
            loop {
                tick.tick().await;
                capacity.sample(store.as_ref()).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn counts_the_mediations_held() {
        let store = crate::store::SqliteStore::memory().unwrap();
        store.grant_mediation("did:peer:a", 1, 0).await.unwrap();
        let capacity = Capacity::default();
        capacity.sample(&store).await;
        assert_eq!(capacity.mediations(), 1);
    }
}
