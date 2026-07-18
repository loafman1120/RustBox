use std::collections::BTreeMap;
use std::sync::RwLock;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleSetStatus {
    pub tag: String,
    pub source: String,
    pub state: RuleSetState,
    pub last_attempt_unix_ms: Option<i64>,
    pub last_success_unix_ms: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSetState {
    Idle,
    Updating,
    Ready,
    Failed,
}

#[derive(Default, Debug)]
pub struct RuleSetRegistry {
    entries: RwLock<BTreeMap<String, RuleSetStatus>>,
}

impl RuleSetRegistry {
    pub fn configure(&self, tag: impl Into<String>, source: impl Into<String>) {
        let tag = tag.into();
        if let Ok(mut entries) = self.entries.write() {
            entries.entry(tag.clone()).or_insert(RuleSetStatus {
                tag,
                source: source.into(),
                state: RuleSetState::Idle,
                last_attempt_unix_ms: None,
                last_success_unix_ms: None,
                last_error: None,
            });
        }
    }

    pub fn updating(&self, tag: &str) {
        if let Ok(mut entries) = self.entries.write()
            && let Some(status) = entries.get_mut(tag)
        {
            status.state = RuleSetState::Updating;
            status.last_attempt_unix_ms = Some(now_unix_ms());
            status.last_error = None;
        }
    }

    pub fn succeeded(&self, tag: &str) {
        if let Ok(mut entries) = self.entries.write()
            && let Some(status) = entries.get_mut(tag)
        {
            let now = now_unix_ms();
            status.state = RuleSetState::Ready;
            status.last_attempt_unix_ms = Some(now);
            status.last_success_unix_ms = Some(now);
            status.last_error = None;
        }
    }

    pub fn failed(&self, tag: &str, error: impl Into<String>) {
        if let Ok(mut entries) = self.entries.write()
            && let Some(status) = entries.get_mut(tag)
        {
            status.state = RuleSetState::Failed;
            status.last_attempt_unix_ms = Some(now_unix_ms());
            status.last_error = Some(error.into());
        }
    }

    pub fn list(&self) -> Vec<RuleSetStatus> {
        self.entries
            .read()
            .map(|entries| entries.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn contains(&self, tag: &str) -> bool {
        self.entries
            .read()
            .is_ok_and(|entries| entries.contains_key(tag))
    }
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
