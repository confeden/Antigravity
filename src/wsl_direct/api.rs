//! Shared GUI/controller values. These carry observations, never installation
//! authority or a second persisted settings store.

use serde::{Deserialize, Serialize};

/// Wanted configuration. An absent enclosing Settings field means migration
/// is unresolved; it must not be replaced with an implicit disabled choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WslPreferences {
    pub enabled: bool,
    pub distros: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationState { Unknown, Present, Absent }

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RegistrationFreshness { #[default] Unobserved, Current, Stale }

/// Exact registration name plus separately observed availability and intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredDistro {
    pub name: String,
    pub registration: RegistrationState,
    pub selected: bool,
    /// None when registration exists but running state was not established.
    pub running: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WslTargetState {
    Unconfirmed,
    NotApplied,
    Preparing,
    /// Preparation only; this does not claim a running server or model reply.
    ReadyToOpen,
    Blocked,
    /// Actual owned work or resource retirement has not completed.
    Pending,
    Failed,
    /// Cancellation was received and the owned operation actually settled.
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetApplyResult {
    pub name: String,
    pub state: WslTargetState,
    /// Redacted user-facing reason, never command arguments or credentials.
    pub detail: Option<String>,
    /// Privacy-qualified technical failure, forwarded once at completion.
    pub diagnostic: Option<String>,
}

/// Ordinary snapshot carried by ops::Status and its existing event channel.
/// The controller owns work; the Settings owner supplies acknowledged intent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WslStatus {
    pub preferences: Option<WslPreferences>,
    pub registration_freshness: RegistrationFreshness,
    pub loading: bool,
    pub error: Option<String>,
    pub distributions: Vec<RegisteredDistro>,
    pub results: Vec<TargetApplyResult>,
    pub pending: bool,
}

impl WslStatus {
    pub fn can_set_distro(&self, name: &str, selected: bool) -> bool {
        if self.pending || self.loading { return false; }
        let Some(row) = self.distributions.iter().find(|row| row.name == name) else { return false; };
        if !selected { return row.selected; }
        !row.selected && self.preferences.as_ref().is_some_and(|p| p.enabled)
            && self.registration_freshness == RegistrationFreshness::Current
            && row.registration == RegistrationState::Present
    }
}
