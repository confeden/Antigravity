//! One concrete GUI WSL operation at a time. The existing ops worker owns this
//! controller and keeps polling/handling cancellation while its job owns work.
use crate::settings::Settings;
use crate::wsl_api::{RegisteredDistro, TargetApplyResult, WslPreferences, WslStatus, WslTargetState, RegistrationState, RegistrationFreshness};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread::{self, JoinHandle};

enum Completed {
    Discovery { values: Vec<RegisteredDistro>, error: Option<String> },
    Apply(crate::wsl_runtime::SelectionPreparation),
}
#[cfg(windows)]
fn discovery_completion(observation: crate::windows_coordinator::DiscoveryObservation) -> Completed {
    Completed::Discovery {
        values: observation.registrations.into_iter().map(|value| RegisteredDistro {
            name: value.name, registration: RegistrationState::Present, selected: false, running: value.running,
        }).collect(),
        error: observation.error.map(|error| format!("Не удалось определить состояние запущенных дистрибутивов WSL: {error}")),
    }
}

struct OwnedOperation {
    cancellation: Arc<AtomicBool>,
    discovery: bool,
    task: JoinHandle<Result<Completed, String>>,
}

#[derive(Default)]
pub(crate) struct WslController {
    distributions: Vec<RegisteredDistro>,
    registration_freshness: RegistrationFreshness,
    results: Vec<TargetApplyResult>,
    operation: Option<OwnedOperation>,
    error: Option<String>,
    unsettled: bool,
    needs_elevation: bool,
}
impl WslController {
    fn begin_discovery(&mut self) {
        if self.registration_freshness == RegistrationFreshness::Current {
            self.registration_freshness = RegistrationFreshness::Stale;
        }
    }
    pub(crate) fn request_discovery(&mut self) -> Result<(), String> {
        if self.is_pending() { return Err("Предыдущая операция WSL ещё не завершена.".into()); }
        let cancellation = Arc::new(AtomicBool::new(false));
        let cancel = cancellation.clone();
        let task = thread::Builder::new().name("wsl-discovery".into()).spawn(move || {
            #[cfg(windows)]
            return crate::windows_coordinator::observe_registered_distributions(cancel).map(discovery_completion);
            #[cfg(not(windows))]
            { let _ = cancel; Err("WSL доступен только в Windows.".into()) }
        }).map_err(|error| format!("Не удалось начать поиск WSL: {error}"))?;
        self.error = None;
        self.begin_discovery();
        self.operation = Some(OwnedOperation { cancellation, discovery: true, task });
        Ok(())
    }

    pub(crate) fn request_apply(&mut self, #[cfg(windows)] plan: Arc<crate::ops::AllTargetApplyPlan>,
        #[cfg(not(windows))] settings: Settings) -> Result<(), String> {
        if self.is_pending() { return Err("Предыдущая операция WSL ещё не завершена.".into()); }
        #[cfg(windows)]
        let settings = plan.wanted();
        let selected = settings.wsl.as_ref().filter(|p| p.enabled)
            .map(|p| p.distros.clone()).unwrap_or_default();
        let cancellation = Arc::new(AtomicBool::new(false));
        let cancel = cancellation.clone();
        let task = thread::Builder::new().name("wsl-apply".into()).spawn(move || {
            crate::wsl_runtime::prepare_selected(#[cfg(windows)] plan, #[cfg(not(windows))] settings, cancel).map(Completed::Apply)
        }).map_err(|error| format!("Не удалось начать применение WSL: {error}"))?;
        self.results = selected.iter().map(|name| TargetApplyResult { name: name.clone(),
            state: WslTargetState::Preparing, detail: None }).collect();
        self.error = None;
        self.needs_elevation = false;
        self.operation = Some(OwnedOperation { cancellation, discovery: false, task });
        Ok(())
    }

    pub(crate) fn poll(&mut self) -> bool {
        if !self.operation.as_ref().is_some_and(|operation| operation.task.is_finished()) { return false; }
        let operation = self.operation.take().expect("finished operation is retained");
        match operation.task.join() {
            Ok(Ok(Completed::Discovery { values, error })) => { self.distributions = values; self.registration_freshness = RegistrationFreshness::Current; self.error = error; },
            Ok(Ok(Completed::Apply(values))) => {
                self.results = values.results;
                self.needs_elevation = values.needs_elevation;
            },
            Ok(Err(error)) => {
                self.error = Some(error);
                if !operation.discovery {
                    for value in &mut self.results {
                        value.state = WslTargetState::Failed;
                        value.detail = Some("Операция завершилась с ошибкой; результат не подтверждён.".into());
                    }
                }
            }
            Err(_) => {
                self.unsettled = true;
                self.error = Some("Наблюдение операции прервано; состояние требует восстановления.".into());
                for value in &mut self.results { value.state = WslTargetState::Pending; }
            }
        }
        true
    }

    pub(crate) fn request_cancel(&self) {
        if let Some(operation) = &self.operation { operation.cancellation.store(true, Ordering::SeqCst); }
    }
    pub(crate) fn distributions(&self) -> &[RegisteredDistro] { &self.distributions }
    pub(crate) fn results(&self) -> &[TargetApplyResult] { &self.results }
    pub(crate) fn is_pending(&self) -> bool { self.operation.is_some() || self.unsettled }
    pub(crate) fn take_elevation_request(&mut self) -> bool {
        std::mem::take(&mut self.needs_elevation)
    }
    pub(crate) fn is_applying(&self) -> bool { self.unsettled || self.operation.as_ref().is_some_and(|operation| !operation.discovery) }
    pub(crate) fn cancelled_before_apply(&mut self, preferences: Option<&WslPreferences>) {
        self.results = preferences.filter(|p| p.enabled).map(|p| p.distros.iter().map(|name| TargetApplyResult {
            name: name.clone(), state: WslTargetState::Cancelled, detail: Some("Подготовка WSL не начиналась.".into()),
        }).collect()).unwrap_or_default();
    }
    pub(crate) fn snapshot(&self, preferences: Option<WslPreferences>) -> WslStatus {
        let mut distributions = self.distributions.clone();
        if self.registration_freshness != RegistrationFreshness::Current {
            for row in &mut distributions { row.registration = RegistrationState::Unknown; row.running = None; }
        }
        if let Some(wanted) = &preferences {
            for row in &mut distributions { row.selected = wanted.distros.contains(&row.name); }
            for name in &wanted.distros {
                if !distributions.iter().any(|row| row.name == *name) {
                    distributions.push(RegisteredDistro { name: name.clone(), registration: if self.registration_freshness == RegistrationFreshness::Current { RegistrationState::Absent } else { RegistrationState::Unknown },
                        selected: true, running: None });
                }
            }
        }
        WslStatus { preferences, registration_freshness: self.registration_freshness, distributions, results: self.results.clone(),
            loading: self.operation.as_ref().is_some_and(|operation| operation.discovery),
            error: self.error.clone(), pending: self.is_pending() }
    }
}

#[cfg(all(test, windows))]
pub(crate) fn test_receive_observation(controller: &mut WslController, observation: crate::windows_coordinator::DiscoveryObservation) {
    let task = thread::spawn(move || Ok(discovery_completion(observation)));
    controller.operation = Some(OwnedOperation { cancellation: Arc::new(AtomicBool::new(false)), discovery: true, task });
    while !controller.poll() { thread::yield_now(); }
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    fn complete(controller: &mut WslController, result: Result<Completed, String>) {
        controller.begin_discovery();
        let task = thread::spawn(move || result);
        controller.operation = Some(OwnedOperation { cancellation: Arc::new(AtomicBool::new(false)), discovery: true, task });
        while !controller.poll() { thread::yield_now(); }
    }
    fn preferences(enabled: bool) -> Option<WslPreferences> {
        Some(WslPreferences { enabled, distros: vec!["Ubuntu".into()] })
    }
    fn row(name: &str) -> RegisteredDistro {
        RegisteredDistro { name: name.into(), registration: RegistrationState::Present, selected: false, running: Some(false) }
    }
    #[test]
    fn observation_transitions_distinguish_unknown_stale_absent_and_secondary_error() {
        let mut controller = WslController::default();
        let snapshot = controller.snapshot(preferences(true));
        assert_eq!(snapshot.registration_freshness, RegistrationFreshness::Unobserved);
        assert_eq!(snapshot.distributions[0].registration, RegistrationState::Unknown);
        complete(&mut controller, Ok(Completed::Discovery { values: vec![row("Ubuntu"), row("Debian")], error: None }));
        let snapshot = controller.snapshot(preferences(true));
        assert_eq!(snapshot.registration_freshness, RegistrationFreshness::Current);
        assert_eq!(snapshot.distributions.len(), 2);
        complete(&mut controller, Err("primary query failed".into()));
        let snapshot = controller.snapshot(preferences(true));
        assert_eq!(snapshot.registration_freshness, RegistrationFreshness::Stale);
        assert!(snapshot.distributions.iter().all(|r| r.registration == RegistrationState::Unknown && r.running.is_none()));
        assert_eq!(snapshot.error.as_deref(), Some("primary query failed"));
        let mut ubuntu = row("Ubuntu"); ubuntu.running = None;
        complete(&mut controller, Ok(Completed::Discovery { values: vec![ubuntu], error: Some("running query failed".into()) }));
        let snapshot = controller.snapshot(preferences(true));
        assert_eq!(snapshot.registration_freshness, RegistrationFreshness::Current);
        assert_eq!(snapshot.distributions[0].registration, RegistrationState::Present);
        assert_eq!(snapshot.distributions[0].running, None);
        assert_eq!(snapshot.error.as_deref(), Some("running query failed"));
        complete(&mut controller, Ok(Completed::Discovery { values: vec![row("Debian")], error: None }));
        assert_eq!(controller.snapshot(preferences(true)).distributions.iter().find(|r| r.name == "Ubuntu").unwrap().registration, RegistrationState::Absent);
    }
    #[test]
    fn saved_target_can_be_removed_when_unknown_or_absent_but_not_selected_when_unknown_or_busy() {
        let mut controller = WslController::default();
        let snapshot = controller.snapshot(preferences(false));
        assert!(snapshot.can_set_distro("Ubuntu", false));
        assert!(!snapshot.can_set_distro("Ubuntu", true));
        complete(&mut controller, Ok(Completed::Discovery { values: vec![], error: None }));
        let mut snapshot = controller.snapshot(preferences(false));
        assert!(snapshot.can_set_distro("Ubuntu", false));
        snapshot.pending = true;
        assert!(!snapshot.can_set_distro("Ubuntu", false));
        let unknown = controller.snapshot(Some(WslPreferences { enabled: true, distros: vec![] }));
        assert!(!unknown.can_set_distro("unknown", true));
    }
}
