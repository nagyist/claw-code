use std::collections::hash_map::DefaultHasher;
use std::env;
use std::hash::{Hash, Hasher};
use std::process;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

static BOOT_SESSION_ID: OnceLock<String> = OnceLock::new();
static BOOT_SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);
static ACTIVE_SESSION: AtomicBool = AtomicBool::new(false);

#[must_use]
pub fn current_boot_session_id() -> &'static str {
    BOOT_SESSION_ID.get_or_init(resolve_boot_session_id)
}

pub fn begin_session() {
    ACTIVE_SESSION.store(true, Ordering::SeqCst);
}

pub fn end_session() {
    ACTIVE_SESSION.store(false, Ordering::SeqCst);
}

#[must_use]
pub fn is_active_session() -> bool {
    ACTIVE_SESSION.load(Ordering::SeqCst)
}

fn resolve_boot_session_id() -> String {
    match env::var("CLAW_SESSION_ID") {
        Ok(value) if !value.trim().is_empty() => value,
        _ => generate_boot_session_id(),
    }
}

fn generate_boot_session_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = BOOT_SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = DefaultHasher::new();
    process::id().hash(&mut hasher);
    nanos.hash(&mut hasher);
    counter.hash(&mut hasher);
    format!("boot-{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::{begin_session, current_boot_session_id, end_session, is_active_session};

    #[test]
    fn given_current_boot_session_id_when_called_twice_then_it_is_stable() {
        let first = current_boot_session_id();
        let second = current_boot_session_id();

        assert_eq!(first, second);
        assert!(first.starts_with("boot-"));
    }

    #[test]
    fn given_current_boot_session_id_when_inspected_then_it_is_opaque_and_non_empty() {
        let session_id = current_boot_session_id();

        assert!(!session_id.trim().is_empty());
        assert_eq!(session_id.len(), 21);
        assert!(!session_id.contains(' '));
    }

    #[test]
    fn given_begin_and_end_session_when_checked_then_active_state_toggles() {
        end_session();
        assert!(!is_active_session());

        begin_session();
        assert!(is_active_session());

        end_session();
        assert!(!is_active_session());
    }
}
