use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use parking_lot::Mutex;
use warp_link_core::{CoordinationError, SessionCoordinator, SessionLease};

#[derive(Clone, Default)]
pub struct InMemoryCoordinator {
    inner: Arc<Mutex<HashMap<String, LeaseEntry>>>,
}

#[derive(Clone)]
struct LeaseEntry {
    owner: String,
    epoch: u64,
    expires_at_unix_secs: i64,
}

impl InMemoryCoordinator {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SessionCoordinator for InMemoryCoordinator {
    async fn acquire(
        &self,
        key: &str,
        owner: &str,
        ttl_secs: u64,
    ) -> Result<SessionLease, CoordinationError> {
        let now = unix_now_secs();
        let expires_at = now.saturating_add(ttl_secs as i64);
        let mut guard = self.inner.lock();
        let lease = if let Some(existing) = guard.get(key) {
            if existing.expires_at_unix_secs > now
                && existing.owner != owner
                && !existing.owner.is_empty()
            {
                return Err(CoordinationError::Conflict(format!(
                    "key={key} owner={} epoch={}",
                    existing.owner, existing.epoch
                )));
            }
            LeaseEntry {
                owner: owner.to_string(),
                epoch: existing.epoch.saturating_add(1).max(1),
                expires_at_unix_secs: expires_at,
            }
        } else {
            LeaseEntry {
                owner: owner.to_string(),
                epoch: 1,
                expires_at_unix_secs: expires_at,
            }
        };
        guard.insert(key.to_string(), lease.clone());
        Ok(SessionLease {
            key: key.to_string(),
            owner: lease.owner,
            epoch: lease.epoch,
            expires_at_unix_secs: lease.expires_at_unix_secs,
        })
    }

    async fn renew(
        &self,
        key: &str,
        owner: &str,
        epoch: u64,
        ttl_secs: u64,
    ) -> Result<SessionLease, CoordinationError> {
        let now = unix_now_secs();
        let expires_at = now.saturating_add(ttl_secs as i64);
        let mut guard = self.inner.lock();
        let Some(existing) = guard.get_mut(key) else {
            return Err(CoordinationError::Conflict(format!(
                "key={key} no_active_lease"
            )));
        };
        if existing.owner != owner || existing.epoch != epoch {
            return Err(CoordinationError::Conflict(format!(
                "key={key} owner={} epoch={}",
                existing.owner, existing.epoch
            )));
        }
        existing.expires_at_unix_secs = expires_at;
        Ok(SessionLease {
            key: key.to_string(),
            owner: existing.owner.clone(),
            epoch: existing.epoch,
            expires_at_unix_secs: existing.expires_at_unix_secs,
        })
    }

    async fn release(&self, key: &str, owner: &str, epoch: u64) -> Result<(), CoordinationError> {
        let mut guard = self.inner.lock();
        let Some(existing) = guard.get_mut(key) else {
            return Ok(());
        };
        if existing.owner != owner || existing.epoch != epoch {
            return Err(CoordinationError::Conflict(format!(
                "key={key} owner={} epoch={}",
                existing.owner, existing.epoch
            )));
        }
        existing.owner.clear();
        existing.expires_at_unix_secs = 0;
        Ok(())
    }
}

fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
