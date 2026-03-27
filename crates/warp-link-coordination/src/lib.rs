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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn acquire_renew_release_happy_path() {
        let coord = InMemoryCoordinator::new();
        let lease = coord
            .acquire("device-1", "owner-a", 30)
            .await
            .expect("acquire should succeed");
        assert_eq!(lease.epoch, 1);
        assert_eq!(lease.owner, "owner-a");

        let renewed = coord
            .renew("device-1", "owner-a", lease.epoch, 45)
            .await
            .expect("renew should succeed");
        assert_eq!(renewed.epoch, lease.epoch);
        assert!(renewed.expires_at_unix_secs >= lease.expires_at_unix_secs);

        coord
            .release("device-1", "owner-a", lease.epoch)
            .await
            .expect("release should succeed");

        let next = coord
            .acquire("device-1", "owner-b", 30)
            .await
            .expect("next owner should acquire after release");
        assert_eq!(next.owner, "owner-b");
        assert!(next.epoch >= 2);
    }

    #[tokio::test]
    async fn acquire_conflicts_with_active_other_owner() {
        let coord = InMemoryCoordinator::new();
        coord
            .acquire("device-2", "owner-a", 30)
            .await
            .expect("first acquire should succeed");

        let error = coord
            .acquire("device-2", "owner-b", 30)
            .await
            .expect_err("second acquire should conflict");
        assert!(matches!(error, CoordinationError::Conflict(_)));
    }

    #[tokio::test]
    async fn renew_and_release_require_matching_owner_and_epoch() {
        let coord = InMemoryCoordinator::new();
        let lease = coord
            .acquire("device-3", "owner-a", 30)
            .await
            .expect("acquire should succeed");

        let renew_error = coord
            .renew("device-3", "owner-a", lease.epoch + 1, 30)
            .await
            .expect_err("wrong epoch should fail");
        assert!(matches!(renew_error, CoordinationError::Conflict(_)));

        let release_error = coord
            .release("device-3", "owner-b", lease.epoch)
            .await
            .expect_err("wrong owner should fail");
        assert!(matches!(release_error, CoordinationError::Conflict(_)));
    }
}
