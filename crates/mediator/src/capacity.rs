//! What the mediator can still take (SPEC.md §11). The store's memory is
//! sampled in the background against its ceiling (Redis `maxmemory`); past
//! the high water no new mediation and no new message is taken, while the
//! mediations already held keep picking up and acknowledging, which only
//! frees room. The mediation count is checked when granting, in the store.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use crate::metrics::METRICS;
use crate::store::{Store, StoreMemory};

/// How often the store is sampled.
const SAMPLE_EVERY: Duration = Duration::from_secs(5);

pub struct Capacity {
    /// Per cent of the store's memory ceiling at which it counts as full.
    high_water: u8,
    store_full: AtomicBool,
    /// Mediations held at the last sample.
    mediations: AtomicU64,
}

impl Capacity {
    pub fn new(high_water: u8) -> Self {
        Self {
            high_water,
            store_full: AtomicBool::new(false),
            mediations: AtomicU64::new(0),
        }
    }

    /// The store is at its high water: no new mediation or message.
    pub fn store_full(&self) -> bool {
        self.store_full.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn set_store_full(&self, full: bool) {
        self.store_full.store(full, Ordering::Relaxed);
    }

    /// Mediations held at the last sample.
    pub fn mediations(&self) -> u64 {
        self.mediations.load(Ordering::Relaxed)
    }

    fn is_full(&self, memory: Option<StoreMemory>) -> bool {
        memory.is_some_and(|m| {
            u128::from(m.used) * 100 >= u128::from(m.max) * u128::from(self.high_water)
        })
    }

    /// Samples the store once. A failed sample keeps what the last one said.
    pub async fn sample(&self, store: &dyn Store) {
        match store.memory().await {
            Ok(memory) => {
                let full = self.is_full(memory);
                if self.store_full.swap(full, Ordering::Relaxed) != full {
                    if full {
                        tracing::warn!(
                            high_water = self.high_water,
                            "store at its high water: new mediations and messages refused"
                        );
                    } else {
                        tracing::info!("store below its high water again");
                    }
                }
                METRICS.store_memory(memory, full);
            }
            Err(err) => {
                METRICS.store_error();
                tracing::warn!(error = %format!("{err:#}"), "store memory sample failed");
            }
        }
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

    #[test]
    fn full_from_the_high_water_on() {
        let capacity = Capacity::new(90);
        let at = |used| Some(StoreMemory { used, max: 1000 });
        assert!(!capacity.is_full(None));
        assert!(!capacity.is_full(at(899)));
        assert!(capacity.is_full(at(900)));
        assert!(capacity.is_full(at(1200)));
        assert!(Capacity::new(100).is_full(at(1000)));
        assert!(!Capacity::new(100).is_full(at(999)));
    }

    #[tokio::test]
    async fn a_store_without_a_ceiling_is_never_full() {
        let store = crate::store::MemoryStore::new();
        store.grant_mediation("did:peer:a", 1, 0).await.unwrap();
        let capacity = Capacity::new(1);
        capacity.sample(&store).await;
        assert!(!capacity.store_full());
        assert_eq!(capacity.mediations(), 1);
    }
}
