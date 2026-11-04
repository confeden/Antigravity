//! Main-host composition for GUI preparation and selected vendor admission.
use crate::settings::Settings;
use crate::wsl_api::{TargetApplyResult, WslTargetState};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
#[cfg(windows)]
pub(crate) use crate::windows_coordinator::OWNER_OBSERVATION_CADENCE;

#[cfg(windows)]
#[path = "runtime_types.rs"]
mod runtime_types;
#[cfg(windows)]
pub(crate) use runtime_types::{VendorAdmission, RuntimePreparationInput, RuntimeRecipe, passthrough_command};

#[cfg(windows)]
pub(crate) fn receive_vendor(launch: crate::windows_coordinator::vendor_launch::VendorWslLaunch,
    wanted: Settings, cancelled: &AtomicBool) -> Result<VendorAdmission, String> {
    use crate::windows_coordinator::{self, windows_installation as owner};
    if cancelled.load(Ordering::SeqCst) { return Err("vendor launch cancelled before admission".into()); }
    let preferences = wanted.wsl.as_ref().ok_or("WSL selection is unconfirmed; use the ordinary GUI Apply action")?;
    let transport = wants_transport(&wanted);
    let vendor = windows_coordinator::process_identity::ProcessIdentity::open(launch.vendor_pid)?;
    let lane = owner::admit_vendor_lane(vendor, &launch.desktop)?;
    if cancelled.load(Ordering::SeqCst) { return Err("vendor launch cancelled during lane receiving".into()); }
    if !preferences.enabled || !preferences.distros.contains(&launch.distro) || (!wanted.client_patch && !transport) {
        let program = windows_coordinator::system_wsl_program()?;
        if cancelled.load(Ordering::SeqCst) { return Err("vendor launch cancelled before passthrough".into()); }
        return Ok(VendorAdmission::PassThrough { program, launch, lane });
    }
    let mut bound = owner::BoundInstallation::open(&launch.desktop)?;
    if cancelled.load(Ordering::SeqCst) { return Err("vendor launch cancelled during installation receiving".into()); }
    if let Some(context) = windows_coordinator::receive_saved_context(&bound)? { bound.attach_ancestor_context(context)?; }
    if cancelled.load(Ordering::SeqCst) { return Err("vendor launch cancelled before runtime read".into()); }
    let read = owner::admit_runtime_read(bound, "wsl-gui-v2")?;
    if read.server_version()? != launch.server_version { return Err("vendor server version differs from the bound producer".into()); }
    let actual = owner::CheckedPath::open(&std::env::current_exe().map_err(|e| format!("runtime image: {e}"))?,
        owner::PathKind::File, owner::PathPurpose::Executable)?;
    if actual.native_id() != read.host().native_id() { return Err("actual runtime host native identity differs".into()); }
    if cancelled.load(Ordering::SeqCst) { return Err("vendor launch cancelled before lane admission".into()); }
    let preparation = RuntimePreparationInput { launch, settings: wanted,
        host_path: read.host().as_path().to_owned(), host_native_id: read.host().native_id(),
        host_sha256: read.host_sha256().to_owned(), revision: read.revision() };
    Ok(VendorAdmission::Selected { read, lane, preparation })
}

pub(crate) struct SelectionPreparation {
    pub(crate) results: Vec<TargetApplyResult>,
    pub(crate) needs_elevation: bool,
}

pub(crate) fn prepare_selected(#[cfg(windows)] plan: Arc<crate::ops::AllTargetApplyPlan>,
    #[cfg(not(windows))] settings: Settings, cancellation: Arc<AtomicBool>) -> Result<SelectionPreparation, String> {
    #[cfg(windows)]
    return prepare_windows_selection(plan, cancellation);
    #[cfg(not(windows))]
    {
        if let Some(result) = selection_without_effects(&settings)? { return Ok(result); }
        let _ = cancellation;
        Err("WSL доступен только в Windows.".into())
    }
}

fn selection_without_effects(settings: &Settings) -> Result<Option<SelectionPreparation>, String> {
    let preferences = settings.wsl.as_ref().ok_or("Выбор WSL ещё не подтверждён.")?;
    if !preferences.enabled {
        return Ok(Some(SelectionPreparation { results: preferences.distros.iter().map(|name| TargetApplyResult { name: name.clone(),
            state: WslTargetState::NotApplied, detail: Some("WSL выключен.".into()) }).collect(), needs_elevation: false }));
    }
    if preferences.distros.is_empty() { return Err("Выберите дистрибутив WSL.".into()); }
    if !settings.client_patch && !wants_transport(&settings) {
        return Ok(Some(SelectionPreparation { results: preferences.distros.iter().map(|name| TargetApplyResult {
            name: name.clone(), state: WslTargetState::NotApplied,
            detail: Some("Для WSL не выбраны изменения; запуск остаётся обычным.".into()),
        }).collect(), needs_elevation: false }));
    }
    Ok(None)
}

fn wants_transport(settings: &Settings) -> bool {
    settings.dns || settings.local_proxy || settings.own_proxy_enabled || settings.group_proxy || settings.builtin_exits
}

#[cfg(windows)]
fn vendor_background_lease() -> Result<crate::windows_coordinator::windows_installation::BackgroundLease, String> {
    use crate::windows_coordinator::{self as coordinator, windows_installation as owner};
    let locations = owner::background_locations()?;
    let inputs = owner::background_inputs(locations.managed_root(), locations.managed_directory(), None,
        &crate::dns_forwarder::log_dir())?;
    let context = coordinator::receive_for_background(&inputs)?;
    owner::background_lease(inputs, context)
}

/// One owner route for both a GUI-qualified package and automatic reuse.
#[cfg(windows)]
pub(crate) fn apply_vendor_update(
    bound: crate::windows_coordinator::windows_installation::BoundInstallation,
    expected: &crate::windows_coordinator::windows_installation::VendorUpdateObservation,
    input: crate::windows_coordinator::windows_installation::VendorRuntimeInput<'_>,
    settings: &Settings,
    automatic: bool,
    cancellation: &AtomicBool,
) -> std::result::Result<crate::windows_coordinator::windows_installation::VendorUpdateCompletion,
    crate::windows_coordinator::windows_installation::gateway_rules::GatewayRuleError> {
    use crate::windows_coordinator::{self as coordinator, windows_installation as owner};
    use owner::gateway_rules::{GatewayRuleError, GatewayRuleRunner};
    if automatic && !automatic_vendor_update_wanted(settings) {
        return Err(GatewayRuleError::Invalid("automatic WSL update is not positively requested".into()));
    }
    if selection_without_effects(settings).map_err(GatewayRuleError::from)?.is_some() {
        return Err(GatewayRuleError::Invalid("WSL update has no selected effect".into()));
    }
    let saved = crate::settings::saved_intent_sha256(settings).map_err(GatewayRuleError::from)?;
    let preferences = settings.wsl.as_ref().ok_or_else(|| GatewayRuleError::Invalid("WSL selection missing".into()))?;
    let registered = coordinator::registered_distributions_with_cancel(cancellation).map_err(GatewayRuleError::from)?;
    if !preferences.distros.iter().all(|name| registered.iter().any(|row| row.name == *name)) {
        return Err(GatewayRuleError::Invalid("selected WSL distribution is no longer registered".into()));
    }
    let _background = vendor_background_lease().map_err(GatewayRuleError::from)?;
    if owner::observe_vendor_update(&bound)? != *expected {
        return Err(GatewayRuleError::RecoveryRequired("vendor prerequisite changed before maintenance".into()));
    }
    let desktop = bound.executable().as_path().to_owned();
    let powershell = coordinator::system_powershell_program().map_err(GatewayRuleError::from)?;
    let mut window = VendorMaintenance { inner: GuiMaintenance { desktop: &desktop, powershell, cancellation },
        settings, saved };
    let qualified = matches!(&input, owner::VendorRuntimeInput::QualifiedPackage { .. });
    let mut runner = if qualified { Some(coordinator::gateway_native::WindowsGatewayRuleRunner::new(owner::new_request_id)?) } else { None };
    let prepared = owner::prepare_vendor_update(&hex::encode(expected.prior_current_sha256), bound, None, input,
        runner.as_mut().map(|value| value as &mut dyn GatewayRuleRunner), cancellation, &mut window)?;
    prepared.execute(runner.as_mut().map(|value| value as &mut dyn GatewayRuleRunner), cancellation).map_err(GatewayRuleError::from)
}

#[cfg(windows)]
struct VendorMaintenance<'a> {
    inner: GuiMaintenance<'a>,
    settings: &'a Settings,
    saved: [u8; 32],
}
#[cfg(windows)]
impl crate::windows_coordinator::windows_installation::MaintenanceWindow for VendorMaintenance<'_> {
    fn ensure_held(&mut self) -> Result<(), String> {
        if crate::settings::saved_intent_sha256(self.settings)? != self.saved {
            return Err("Cancelled: saved WSL intent changed".into());
        }
        let selected = self.settings.wsl.as_ref().ok_or("WSL selection missing")?;
        let registered = crate::windows_coordinator::registered_distributions_with_cancel(self.inner.cancellation)?;
        if !selected.enabled || selected.distros.is_empty()
            || !selected.distros.iter().all(|name| registered.iter().any(|row| row.name == *name)) {
            return Err("Cancelled: selected WSL registration changed".into());
        }
        crate::windows_coordinator::windows_installation::MaintenanceWindow::ensure_held(&mut self.inner)
    }
}

/// Automatic callers never invent a package; only a previously received host
/// can be reused, and every real mutation still goes through the same owner.
#[cfg(windows)]
pub(crate) fn automatic_vendor_update(root: &std::path::Path, settings: &Settings,
    cancellation: &AtomicBool) -> Result<bool, String> {
    use crate::windows_coordinator::{self as coordinator, windows_installation as owner};
    if !automatic_vendor_update_wanted(settings) { return Ok(false); }
    let layout = crate::receive_installation_layout(root)?;
    if layout.kind != crate::InstallationKind::Desktop { return Ok(false); }
    let mut bound = owner::BoundInstallation::open(&layout.anchor)?;
    if let Some(context) = coordinator::receive_saved_context(&bound)? { bound.attach_ancestor_context(context)?; }
    match owner::observe_apply_current(&bound)? {
        owner::ApplyCurrentObservation::VendorReplacement(expected) => {
            use sha2::{Digest, Sha256};
            let source = owner::CheckedPath::open(&std::env::current_exe().map_err(|e| format!("runtime image: {e}"))?,
                owner::PathKind::File, owner::PathPurpose::Executable)?;
            let source_sha256 = hex::encode(Sha256::digest(source.read_snapshot()?));
            apply_vendor_update(bound, &expected, owner::VendorRuntimeInput::ReuseReceivedRuntime { source: &source, source_sha256: &source_sha256 },
                settings, true, cancellation).map_err(|error| error.to_string())?;
            Ok(true)
        }
        owner::ApplyCurrentObservation::Absent | owner::ApplyCurrentObservation::Settled { .. } => Ok(false),
        owner::ApplyCurrentObservation::GatewayPending(_) => Err("RecoveryRequired: gateway operation is Pending".into()),
    }
}

/// Intent only: actual registration, target identity and the maintenance gate
/// are received independently before the automatic writer may run.
pub(crate) fn automatic_vendor_update_wanted(settings: &Settings) -> bool {
    settings.auto_patch_wanted()
        && settings.wsl.as_ref().is_some_and(|wsl| wsl.enabled && !wsl.distros.is_empty())
        && (settings.client_patch || wants_transport(settings))
}

#[cfg(windows)]
pub(crate) enum WslApplyPreparation {
    NotSelected(Vec<TargetApplyResult>),
    Selected(WslSelectedPreparation),
}
#[cfg(windows)]
pub(crate) struct WslSelectedPreparation {
    source: crate::windows_coordinator::windows_installation::CheckedPath,
    source_sha256: String,
    assets: crate::windows_coordinator::windows_installation::PackageAssets,
    needs_elevation: bool,
}
#[cfg(windows)]
impl WslApplyPreparation {
    pub(crate) fn requires_elevation(&self) -> bool {
        matches!(self, Self::Selected(selected) if selected.needs_elevation)
    }
}

/// Settle the acknowledged vendor prerequisites before ordinary native Apply.
#[cfg(windows)]
pub(crate) fn apply_vendor_prerequisites(plan: &crate::ops::AllTargetApplyPlan, cancellation: &AtomicBool)
    -> Result<Vec<(String, [u8; 32])>, String> {
    use crate::windows_coordinator::windows_installation as owner;
    let selected = match plan.wsl()? {
        WslApplyPreparation::Selected(value) => value,
        WslApplyPreparation::NotSelected(_) => return Err("UpdatePending: WSL vendor update is not selected".into()),
    };
    let mut completed = Vec::new();
    for target in plan.wsl_desktops().filter(|target| target.is_vendor_update()) {
        let operation = (|| -> Result<(String, [u8; 32]), String> {
            if cancellation.load(Ordering::SeqCst) { return Err("Cancelled: vendor update not started".into()); }
            target.recheck_desktop_current()?;
            let bound = target.desktop_binding()?;
            let expected = match owner::observe_apply_current(&bound)? {
                owner::ApplyCurrentObservation::VendorReplacement(value) => value,
                _ => return Err("UpdatePending: vendor prerequisite changed".into()),
            };
            let received = apply_vendor_update(bound, &expected, owner::VendorRuntimeInput::QualifiedPackage {
                source: &selected.source, expected_host_sha256: &selected.source_sha256, assets: &selected.assets,
                selection: plan.retirement_for(&expected)?,
            }, plan.wanted(), false, cancellation).map_err(|error| error.to_string())?;
            if received.slot_id != expected.slot_id { return Err("vendor result slot differs".into()); }
            Ok((received.slot_id, received.current_sha256))
        })();
        match operation {
            Ok(slot) => completed.push(slot),
            Err(error) => return Err(format!("{error}; completed vendor slots: {completed:?}")),
        }
    }
    Ok(completed)
}

#[cfg(windows)]
pub(crate) fn inspect_selection(plan: &crate::ops::AllTargetApplyPlan, cancellation: &AtomicBool)
    -> Result<WslApplyPreparation, String> {
    use crate::windows_coordinator::{self as coordinator, windows_installation as owner};
    use owner::gateway_rules::{self, GatewayHostInput, GatewayRequirementNamespaces, GatewayRuleEffect};
    use sha2::{Digest, Sha256};
    let settings = plan.wanted();
    // No positive WSL request is part of this AllTarget action. Preserve the
    // unresolved preference itself; do not manufacture a disabled setting.
    if settings.wsl.is_none() { return Ok(WslApplyPreparation::NotSelected(Vec::new())); }
    if let Some(result) = selection_without_effects(settings)? { return Ok(WslApplyPreparation::NotSelected(result.results)); }
    let preferences = settings.wsl.as_ref().ok_or("WSL selection missing")?;
    let registered = coordinator::registered_distributions_with_cancel(cancellation)?;
    for name in &preferences.distros {
        if !registered.iter().any(|row| row.name == *name) { return Err("selected WSL distribution is no longer registered".into()); }
    }
    let source = owner::CheckedPath::open(&std::env::current_exe().map_err(|error| format!("host package: {error}"))?,
        owner::PathKind::File, owner::PathPurpose::Executable)?;
    let source_sha256 = hex::encode(Sha256::digest(source.read_snapshot()?));
    let assets = owner::PackageAssets::receive(&source, option_env!("AG_WSL_EXPECTED_HELPER_SHA256"))?;
    let mut namespaces = Vec::new();
    let mut active_profiles = None;
    if wants_transport(settings) {
        let wsl = coordinator::system_wsl_program()?;
        let ps = coordinator::system_powershell_program()?;
        for name in &preferences.distros {
            if cancellation.load(Ordering::SeqCst) { return Err("WSL requirement collection cancelled".into()); }
            let context = coordinator::discover_runtime_context(&wsl, &ps, name, cancellation)?;
            let namespace = gateway_namespace(&context);
            if !namespaces.contains(&namespace) { namespaces.push(namespace); }
        }
        active_profiles = Some(coordinator::active_firewall_profiles(&ps, cancellation)?);
    }
    let mut needs_elevation = false;
    let mut desktops = 0;
    for target in plan.wsl_desktops() {
        desktops += 1;
        if cancellation.load(Ordering::SeqCst) { return Err("WSL requirement collection cancelled".into()); }
        let bound = target.desktop_binding()?;
        let observation = owner::observe_apply_current(&bound)?;
        let vendor = matches!(&observation, owner::ApplyCurrentObservation::VendorReplacement(_));
        let host = match observation {
            owner::ApplyCurrentObservation::VendorReplacement(ref expected) =>
                GatewayHostInput::vendor_prerequisite(&bound, &source, &source_sha256, expected,
                    plan.retirement_for(expected)?, plan.saved_sha256()),
            _ => GatewayHostInput::receive(&bound, &source, &source_sha256),
        }.map_err(|error| error.to_string())?;
        let wanted = match active_profiles {
            Some(active_profiles) => GatewayRequirementNamespaces::TransportWanted { namespaces: &namespaces,
                active_profiles, administrator: crate::utils::is_admin() },
            None => GatewayRequirementNamespaces::TransportNotWanted,
        };
        let mut runner = coordinator::gateway_native::WindowsGatewayRuleRunner::new(owner::new_request_id)?;
        let requirements = gateway_rules::inspect_requirements(&bound, host, wanted, &mut runner, cancellation)
            .map_err(|error| error.to_string())?;
        needs_elevation |= matches!(requirements.rules, GatewayRuleEffect::NativeWriteRequired { administrator: false });
        // A new host's transport demand does not discharge old-host custody.
        // Retirement preparation is read-only and also covers transport off.
        if !vendor && owner::runtime_installed(&bound)? {
            let read = owner::admit_runtime_read(target.desktop_binding()?, "wsl-gui-v2")?;
            if read.host_sha256() != source_sha256 {
                let old_host = checked_runtime_host(&read)?;
                drop(read);
                match gateway_rules::prepare_gateway_rule_retirement(&bound, &old_host, &[], &mut runner, cancellation) {
                    Ok(prepared) => drop(prepared),
                    Err(gateway_rules::GatewayRuleError::NeedsElevation) => needs_elevation = true,
                    Err(error) => return Err(error.to_string()),
                }
            }
        }
    }
    if desktops == 0 { return Err("Для выбранного WSL не найдена доступная установка Desktop.".into()); }
    Ok(WslApplyPreparation::Selected(WslSelectedPreparation { source, source_sha256, assets, needs_elevation }))
}

#[cfg(windows)]
pub(crate) fn prepare_runtime(input: RuntimePreparationInput, cancellation: Arc<AtomicBool>) -> Result<RuntimeRecipe, String> {
    use crate::windows_coordinator::{self as coordinator, windows_installation as owner, session};
    use sha2::{Digest, Sha256};
    if cancellation.load(Ordering::SeqCst) { return Err("runtime preparation cancelled".into()); }
    let host = owner::CheckedPath::open(&input.host_path, owner::PathKind::File, owner::PathPurpose::Executable)?;
    if host.native_id() != input.host_native_id || hex::encode(Sha256::digest(host.read_snapshot()?)) != input.host_sha256 {
        return Err("runtime preparation host incarnation differs".into());
    }
    let assets = owner::PackageAssets::receive(&host, option_env!("AG_WSL_EXPECTED_HELPER_SHA256"))?;
    let program = coordinator::system_wsl_program()?;
    let transport = wants_transport(&input.settings);
    let mut gateway = None;
    let architecture;
    if transport {
        let ps = coordinator::system_powershell_program()?;
        let context = coordinator::discover_runtime_context(&program, &ps, &input.launch.distro, &cancellation)?;
        // The retained owner already holds its admitted reader. This receiving
        // thread independently requalifies the same canonical revision before
        // consulting its immutable rule receipts; it cannot create rules.
        let mut bound = owner::BoundInstallation::open(&input.launch.desktop)?;
        if let Some(saved) = coordinator::receive_saved_context(&bound)? { bound.attach_ancestor_context(saved)?; }
        let read = owner::admit_runtime_read(bound, "wsl-gui-v2")?;
        if read.revision() != input.revision || read.host().native_id() != input.host_native_id
            || read.host_sha256() != input.host_sha256 {
            return Err("runtime rule receiving canonical incarnation differs".into());
        }
        receive_gateway_rule(&read, &context, &cancellation)?;
        architecture = context.architecture.clone();
        gateway = Some(session::SessionSpec {
            program: session::GatewayProgramRef::receive(host.as_path(), &host.native_id(), &input.host_sha256)?,
            selected_distro: input.launch.distro.clone(), selected_user: context.user,
            // Existing package operational budgets; no established stream duration limit.
            gateway: session::GatewayConfig { bind: context.bind, source: context.source, opening_ms: 15_000,
                header_bytes: 16_384, max_active: 16, poll_ms: OWNER_OBSERVATION_CADENCE.as_millis() as u64 },
            expected_policy: session::PolicyStatus::Received,
            startup_budget: std::time::Duration::from_secs(15), stop_observation_budget: std::time::Duration::from_secs(15),
            status_line_bytes: 16_384,
        });
    } else {
        architecture = coordinator::discover_runtime_identity(&program, &input.launch.distro, &cancellation)?.architecture;
    }
    let launcher = coordinator::provision_runtime_helper(&program, &input.launch.distro, &assets, &architecture, &cancellation)?;
    if cancellation.load(Ordering::SeqCst) { return Err("runtime preparation cancelled after helper retirement".into()); }
    host.recheck()?;
    Ok(RuntimeRecipe { gateway, program, launch: input.launch, launcher,
        eligibility: input.settings.client_patch, transport, automatic: input.settings.auto_patch })
}

#[cfg(windows)]
fn prepare_windows_selection(plan: Arc<crate::ops::AllTargetApplyPlan>, cancellation: Arc<AtomicBool>) -> Result<SelectionPreparation, String> {
    use crate::windows_coordinator::{self as coordinator, windows_installation as owner};
    let settings = plan.wanted();
    let selected = match plan.wsl()? {
        WslApplyPreparation::NotSelected(results) => return Ok(SelectionPreparation { results: results.clone(), needs_elevation: false }),
        WslApplyPreparation::Selected(selected) => selected,
    };
    let source = &selected.source;
    let source_sha256 = &selected.source_sha256;
    let assets = &selected.assets;
    source.recheck()?;
    assets.recheck()?;
    let wanted = settings.wsl.as_ref().ok_or("WSL selection missing")?;
    let registered = coordinator::registered_distributions(cancellation.clone())?;
    let desktops: Vec<_> = plan.wsl_desktops().collect();
    let mut begun = vec![false; desktops.len()];
    let mut results = Vec::new();
    for name in &wanted.distros {
        if cancellation.load(Ordering::SeqCst) {
            results.push(TargetApplyResult { name: name.clone(), state: WslTargetState::Cancelled, detail: None });
            continue;
        }
        if !registered.iter().any(|row| row.name == *name) {
            results.push(TargetApplyResult { name: name.clone(), state: WslTargetState::Blocked,
                detail: Some("Дистрибутив больше не зарегистрирован.".into()) });
            continue;
        }
        for (index, target) in desktops.iter().enumerate() {
            let desktop = target.anchor();
            let mut needs_elevation = false;
            let operation = (|| -> Result<(), String> {
                if !begun[index] { target.recheck_desktop_current()?; }
                let mut bound = target.desktop_binding()?;
                if matches!(owner::observe_apply_current(&bound)?, owner::ApplyCurrentObservation::VendorReplacement(_)) {
                    return Err("UpdatePending: Desktop changed after the acknowledged Apply plan".into());
                }
                if !owner::runtime_installed(&bound)? {
                    let ps = coordinator::system_powershell_program()?;
                    let mut window = GuiMaintenance { desktop, powershell: ps, cancellation: &cancellation };
                    owner::upgrade_runtime(bound, source, source_sha256, assets, None, &mut window)?;
                    begun[index] = true;
                    bound = target.desktop_binding()?;
                }
                let mut read = owner::admit_runtime_read(bound, "wsl-gui-v2")?;
                begun[index] = true;
                if read.host_sha256() != source_sha256.as_str() {
                    let old_host = checked_runtime_host(&read)?;
                    drop(read); // Never request the runtime writer while owning its reader.
                    let ps = coordinator::system_powershell_program()?;
                    let mut window = GuiMaintenance { desktop, powershell: ps, cancellation: &cancellation };
                    run_runtime_host_refresh(&cancellation, |stage| {
                        match stage {
                            RuntimeHostRefreshStage::RetireOldRules => {
                                owner::MaintenanceWindow::ensure_held(&mut window)?;
                                let bound = target.desktop_binding()?;
                                let mut runner = coordinator::gateway_native::WindowsGatewayRuleRunner::new(owner::new_request_id)?;
                                let prepared = match owner::gateway_rules::prepare_gateway_rule_retirement(&bound, &old_host, &[], &mut runner, &cancellation) {
                                    Ok(prepared) => prepared,
                                    Err(owner::gateway_rules::GatewayRuleError::NeedsElevation) => {
                                        needs_elevation = true;
                                        return Err("Для обновления сети WSL требуется подтверждение администратора.".into());
                                    },
                                    Err(error) => return Err(error.to_string()),
                                };
                                // The owner may publish Pending before returning an error.
                                begun[index] = true;
                                match owner::gateway_rules::retire_gateway_rules(prepared, &mut runner, &mut window, &cancellation) {
                                    Ok(()) => Ok(()),
                                    Err(owner::gateway_rules::GatewayRuleError::NeedsElevation) => {
                                        needs_elevation = true;
                                        Err("Для обновления сети WSL требуется подтверждение администратора.".into())
                                    },
                                    Err(error) => Err(error.to_string()),
                                }
                            },
                            RuntimeHostRefreshStage::RevertArchive => {
                                let bound = target.desktop_binding()?;
                                owner::prepare_revert(bound, None, &mut window)?.execute()
                            },
                            RuntimeHostRefreshStage::InstallNewHost => {
                                let bound = target.desktop_binding()?;
                                owner::upgrade_runtime(bound, source, source_sha256, assets, None, &mut window)
                            },
                        }
                    })?;
                    read = owner::admit_runtime_read(target.desktop_binding()?, "wsl-gui-v2")?;
                    if read.host_sha256() != source_sha256.as_str() {
                        return Err("UpdatePending: refreshed runtime host did not receive the selected package".into());
                    }
                }
                let program = coordinator::system_wsl_program()?;
                let identity = coordinator::discover_runtime_identity(&program, name, &cancellation)?;
                let launcher = coordinator::provision_runtime_helper(&program, name, assets, &identity.architecture, &cancellation)?;
                prepare_private_copy(&program, name, &launcher, &read.server_version()?, &settings,
                    assets.helper_digest(), &cancellation)?;
                if wants_transport(&settings) {
                    let ps = coordinator::system_powershell_program()?;
                    let context = coordinator::discover_runtime_context(&program, &ps, name, &cancellation)?;
                    let host = owner::CheckedPath::open(read.host().as_path(), owner::PathKind::File, owner::PathPurpose::Executable)?;
                    let bound = target.desktop_binding()?;
                    drop(read);
                    let mut runner = coordinator::gateway_native::WindowsGatewayRuleRunner::new(owner::new_request_id)?;
                    let prepared = match owner::gateway_rules::prepare_gateway_rules(&bound, &host,
                        &[gateway_namespace(&context)], &mut runner, &cancellation) {
                        Ok(prepared) => prepared,
                        Err(owner::gateway_rules::GatewayRuleError::NeedsElevation) => {
                            needs_elevation = true;
                            return Err("Для настройки сети WSL требуется подтверждение администратора.".into());
                        },
                        Err(error) => return Err(error.to_string()),
                    };
                    let mut window = GuiMaintenance { desktop, powershell: ps, cancellation: &cancellation };
                    match owner::gateway_rules::ensure_gateway_rules(prepared, &mut runner, &mut window, &cancellation) {
                        Ok(()) => {},
                        Err(owner::gateway_rules::GatewayRuleError::NeedsElevation) => {
                            needs_elevation = true;
                            return Err("Для настройки сети WSL требуется подтверждение администратора.".into());
                        },
                        Err(error) => return Err(error.to_string()),
                    }
                    let read = owner::admit_runtime_read(bound, "wsl-gui-v2")?;
                    receive_gateway_rule(&read, &context, &cancellation)?;
                }
                if cancellation.load(Ordering::SeqCst) { return Err("Cancelled: preparation settled after cancellation".into()); }
                Ok(())
            })();
            merge_target_result(&mut results, match operation {
                Ok(()) => TargetApplyResult { name: name.clone(), state: WslTargetState::ReadyToOpen,
                    detail: Some("Подготовка проверена. Откройте WSL в Antigravity.".into()) },
                Err(error) => TargetApplyResult { name: name.clone(), state: if error.starts_with("Cancelled:") { WslTargetState::Cancelled }
                    else if error.contains("RecoveryRequired:") || error.contains("PreparationIncomplete:") { WslTargetState::Pending }
                    else { WslTargetState::Blocked }, detail: Some(error) },
            });
            if needs_elevation { return Ok(SelectionPreparation { results, needs_elevation: true }); }
        }
    }
    Ok(SelectionPreparation { results, needs_elevation: false })
}

#[cfg(windows)]
fn checked_runtime_host(read: &crate::windows_coordinator::windows_installation::RuntimeRead)
    -> Result<crate::windows_coordinator::windows_installation::CheckedPath, String> {
    use crate::windows_coordinator::windows_installation as owner;
    use sha2::{Digest, Sha256};
    let host = owner::CheckedPath::open(read.host().as_path(), owner::PathKind::File, owner::PathPurpose::Executable)?;
    if host.native_id() != read.host().native_id()
        || hex::encode(Sha256::digest(host.read_snapshot()?)) != read.host_sha256() {
        return Err("UpdatePending: received old runtime host incarnation changed".into());
    }
    Ok(host)
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeHostRefreshStage { RetireOldRules, RevertArchive, InstallNewHost }

#[cfg(windows)]
fn run_runtime_host_refresh(cancel: &AtomicBool,
    mut run: impl FnMut(RuntimeHostRefreshStage) -> Result<(), String>) -> Result<(), String> {
    let mut completed = Vec::new();
    for stage in [RuntimeHostRefreshStage::RetireOldRules, RuntimeHostRefreshStage::RevertArchive,
        RuntimeHostRefreshStage::InstallNewHost] {
        if cancel.load(Ordering::SeqCst) {
            return Err(format!("Cancelled: runtime package refresh; completed owner stages: {completed:?}"));
        }
        run(stage).map_err(|error| format!("{error}; runtime package refresh stage {stage:?}; completed owner stages: {completed:?}"))?;
        completed.push(stage);
    }
    Ok(())
}

#[cfg(windows)]
fn merge_target_result(results: &mut Vec<TargetApplyResult>, next: TargetApplyResult) {
    let Some(current) = results.iter_mut().find(|current| current.name == next.name) else { results.push(next); return; };
    let priority = |state| match state {
        WslTargetState::Pending => 7, WslTargetState::Failed => 6, WslTargetState::Blocked => 5,
        WslTargetState::Cancelled => 4, WslTargetState::ReadyToOpen => 3, WslTargetState::NotApplied => 2,
        WslTargetState::Preparing => 1, WslTargetState::Unconfirmed => 0,
    };
    if priority(next.state) > priority(current.state) { current.state = next.state; }
    if let Some(detail) = next.detail {
        if current.detail.as_ref() != Some(&detail) {
            current.detail = Some(match current.detail.take() { Some(prior) => format!("{prior}; {detail}"), None => detail });
        }
    }
}

#[cfg(windows)]
struct GuiMaintenance<'a> {
    desktop: &'a std::path::Path,
    powershell: crate::windows_coordinator::windows_installation::CheckedPath,
    cancellation: &'a AtomicBool,
}
/// Positive Apply composition only. The observation is data; the generic owner
/// revalidates the exact operation after its first writer/slot owner is dropped.
#[cfg(windows)]
pub(crate) fn recover_apply_gateway(bound: crate::windows_coordinator::windows_installation::BoundInstallation,
    target: &crate::instances::GuiReplacementTarget,
    expected: &crate::windows_coordinator::windows_installation::GatewayPendingObservation,
    cancel: &AtomicBool) -> Result<String, String> {
    use crate::windows_coordinator::{self as coordinator, windows_installation as owner};
    if cancel.load(Ordering::SeqCst) { return Err("Cancelled: Apply gateway recovery not started".into()); }
    if target.kind != crate::instances::GuiTargetKind::Desktop || bound.native_root_id() != target.native_root_id
        || bound.native_executable_id() != target.anchor_native_id {
        return Err("RecoveryRequired: selected gateway target anchor changed".into());
    }
    if owner::observe_apply_current(&bound)? != owner::ApplyCurrentObservation::GatewayPending(expected.clone()) {
        return Err("RecoveryRequired: Apply gateway prerequisite snapshot changed".into());
    }
    let powershell = coordinator::system_powershell_program()?;
    let mut window = GuiMaintenance { desktop: &target.anchor_path, powershell, cancellation: cancel };
    let mut runner = coordinator::gateway_native::WindowsGatewayRuleRunner::new(owner::new_request_id)?;
    let result = owner::recover(bound, &expected.operation_id, &hex::encode(expected.current_sha256),
        Some(owner::GatewayRecoveryContext { runner: &mut runner, cancel }), &mut window);
    let current = (|| -> Result<owner::BoundInstallation, String> {
        let mut current = owner::BoundInstallation::open(&target.anchor_path)?;
        if let Some(context) = coordinator::receive_saved_context(&current)? { current.attach_ancestor_context(context)?; }
        Ok(current)
    })();
    receive_apply_gateway_outcome(target, expected, result, current)
}
/// Read-only outcome receiving is unconditional, including error/cancellation
/// after a persisted custody outcome. It supplies no mutation capability.
#[cfg(windows)]
pub(crate) fn receive_apply_gateway_outcome(target: &crate::instances::GuiReplacementTarget,
    expected: &crate::windows_coordinator::windows_installation::GatewayPendingObservation,
    result: Result<String, String>,
    current: Result<crate::windows_coordinator::windows_installation::BoundInstallation, String>) -> Result<String, String> {
    use crate::windows_coordinator::windows_installation as owner;
    // Err is not proof of zero changes: finish can publish custody and only
    // then deny fresh readiness. Receive actual Current on both return paths.
    let observed = current.and_then(|current| {
        if target.kind != crate::instances::GuiTargetKind::Desktop || current.native_root_id() != target.native_root_id || current.native_executable_id() != target.anchor_native_id {
            return Err("recovery outcome target anchor changed".into());
        }
        owner::observe_apply_current(&current)
    });
    let evidence = format!("recovery scope slot={} operation={} priorCurrent={}; actualCurrent={observed:?}",
        expected.slot_id, expected.operation_id, hex::encode(expected.current_sha256));
    let settled = matches!(&observed, Ok(owner::ApplyCurrentObservation::Settled { slot_id, .. }) if slot_id == &expected.slot_id);
    match result {
        Ok(outcome) if settled => Ok(format!("{outcome}; {evidence}")),
        Ok(outcome) => Err(format!("recovery owner completed but fresh selected Current remains held; ownerOutcome={outcome}; {evidence}")),
        Err(error) => Err(format!("{error}; {evidence}")),
    }
}
#[cfg(windows)]
impl crate::windows_coordinator::windows_installation::MaintenanceWindow for GuiMaintenance<'_> {
    fn ensure_held(&mut self) -> Result<(), String> {
        crate::windows_coordinator::desktop_absent_runtime(&self.powershell, self.desktop, self.cancellation)
    }
}

#[cfg(windows)]
fn prepare_private_copy(program: &crate::windows_coordinator::windows_installation::CheckedPath, distro: &str,
    launcher: &str, version: &str, settings: &Settings, expected_helper: &str, cancel: &AtomicBool) -> Result<(), String> {
    let mut command = std::process::Command::new(program.as_path());
    command.args(["-d", distro, "--exec", "sh", "-c",
        r#"agLauncher=$1; agEligibility=$2; agTransport=$3; agVersion=$4; exec "$agLauncher" --prepare-only --profile "$agEligibility" "$agTransport" "$HOME/.antigravity-server/bin/$agVersion/language_server""#,
        "sh", launcher, if settings.client_patch { "1" } else { "0" }, if wants_transport(settings) { "1" } else { "0" }, version]);
    let output = crate::windows_coordinator::runtime_metadata(program, command, cancel, true)?;
    receive_private_copy_manifest(&output, settings, expected_helper)
}

#[cfg(windows)]
fn receive_private_copy_manifest(output: &str, settings: &Settings, expected_helper: &str) -> Result<(), String> {
    let manifest: serde_json::Value = serde_json::from_str(output.trim()).map_err(|_| "private-copy preparation receipt invalid")?;
    let expected_profile = if settings.client_patch && wants_transport(settings) { "wsl-profile-v1".to_owned() }
        else { format!("wsl-profile-v2-e{}-t{}", u8::from(settings.client_patch), u8::from(wants_transport(settings))) };
    if manifest.as_object().map(|value| value.len()) != Some(8)
        || manifest.get("schema").and_then(|value| value.as_u64()) != Some(1)
        || manifest.get("profile").and_then(|value| value.as_str()) != Some(expected_profile.as_str())
        || manifest.get("helper_sha256").and_then(|value| value.as_str()) != Some(expected_helper)
        || manifest.get("cache_hit").and_then(|value| value.as_bool()).is_none() {
        return Err("private-copy preparation receipt profile/helper identity differs".into());
    }
    for field in ["source_sha256", "output_sha256", "helper_sha256", "association_sha256", "cache_identity"] {
        let digest = manifest.get(field).and_then(|value| value.as_str()).ok_or("private-copy preparation receipt missing identity")?;
        if digest.len() != 64 || !digest.bytes().all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value)) {
            return Err("private-copy preparation receipt digest encoding".into());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn gateway_namespace(context: &crate::windows_coordinator::Context)
    -> crate::windows_coordinator::windows_installation::gateway_rules::GatewayNamespace {
    crate::windows_coordinator::windows_installation::gateway_rules::GatewayNamespace {
        interface_index: context.interface, interface_alias: context.interface_alias.clone(),
        local_address: context.bind, source_address: context.source,
    }
}

#[cfg(windows)]
fn receive_gateway_rule(read: &crate::windows_coordinator::windows_installation::RuntimeRead,
    context: &crate::windows_coordinator::Context, cancel: &AtomicBool) -> Result<String, String> {
    use crate::windows_coordinator::{gateway_native::WindowsGatewayRuleRunner, windows_installation as owner};
    let mut runner = WindowsGatewayRuleRunner::new(owner::new_request_id)?;
    owner::gateway_rules::receive_gateway_rule(read, &gateway_namespace(context), &mut runner, cancel)
        .map_err(|error| error.to_string())
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn runtime_host_refresh_orders_owners_and_stops_on_failure_or_cancel() {
        use RuntimeHostRefreshStage::*;
        let cancel = AtomicBool::new(false);
        let mut stages = Vec::new();
        let error = run_runtime_host_refresh(&cancel, |stage| {
            stages.push(stage);
            if stage == RevertArchive { Err("RecoveryRequired: actual revert pending".into()) } else { Ok(()) }
        }).unwrap_err();
        assert_eq!(stages, [RetireOldRules, RevertArchive]);
        assert!(error.starts_with("RecoveryRequired:") && error.contains("completed owner stages: [RetireOldRules]"));
        stages.clear();
        let error = run_runtime_host_refresh(&cancel, |stage| {
            stages.push(stage); cancel.store(true, Ordering::SeqCst); Ok(())
        }).unwrap_err();
        assert_eq!(stages, [RetireOldRules]);
        assert!(error.starts_with("Cancelled:") && error.contains("RetireOldRules"));
        cancel.store(false, Ordering::SeqCst);
        stages.clear();
        run_runtime_host_refresh(&cancel, |stage| { stages.push(stage); Ok(()) }).unwrap();
        assert_eq!(stages, [RetireOldRules, RevertArchive, InstallNewHost]);
    }

    use super::*;

    #[test]
    fn automatic_vendor_update_requires_positive_wsl_and_effect_intent() {
        let mut settings = Settings::default();
        settings.auto_patch = true;
        settings.patch_declined = false;
        settings.client_patch = false;
        settings.dns = false;
        settings.local_proxy = false;
        settings.own_proxy_enabled = false;
        settings.group_proxy = false;
        settings.builtin_exits = false;
        settings.wsl = None;
        assert!(!automatic_vendor_update_wanted(&settings));
        settings.wsl = Some(crate::wsl_api::WslPreferences { enabled: true, distros: vec!["fixture".into()] });
        assert!(!automatic_vendor_update_wanted(&settings));
        settings.client_patch = true;
        assert!(automatic_vendor_update_wanted(&settings));
        settings.patch_declined = true;
        assert!(!automatic_vendor_update_wanted(&settings));
        settings.patch_declined = false;
        settings.wsl.as_mut().unwrap().distros.clear();
        assert!(!automatic_vendor_update_wanted(&settings));
        settings.wsl.as_mut().unwrap().distros.push("fixture".into());
        settings.wsl.as_mut().unwrap().enabled = false;
        assert!(!automatic_vendor_update_wanted(&settings));
    }

    #[test]
    fn private_copy_receiving_rejects_missing_or_changed_profile_identity() {
        let mut settings = Settings::default();
        settings.client_patch = true;
        settings.dns = false;
        settings.local_proxy = false;
        settings.own_proxy_enabled = false;
        settings.group_proxy = false;
        settings.builtin_exits = false;
        let digest = "a".repeat(64);
        let receipt = serde_json::json!({ "schema": 1, "profile": "wsl-profile-v2-e1-t0",
            "source_sha256": digest, "output_sha256": digest, "helper_sha256": digest,
            "association_sha256": digest, "cache_identity": digest, "cache_hit": false });
        assert!(receive_private_copy_manifest(&receipt.to_string(), &settings, &digest).is_ok());
        for field in ["source_sha256", "output_sha256", "helper_sha256", "association_sha256", "cache_identity", "profile", "cache_hit"] {
            let mut missing = receipt.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(receive_private_copy_manifest(&missing.to_string(), &settings, &digest).is_err());
        }
        let mut malformed = receipt.clone();
        malformed["source_sha256"] = "".into();
        assert!(receive_private_copy_manifest(&malformed.to_string(), &settings, &digest).is_err());
        assert!(receive_private_copy_manifest(&receipt.to_string(), &settings, &"b".repeat(64)).is_err());
        settings.dns = true;
        assert!(receive_private_copy_manifest(&receipt.to_string(), &settings, &digest).is_err());
    }

    #[test]
    fn disabled_or_empty_effect_selection_never_requires_a_host_package() {
        let mut settings = Settings::default();
        assert!(selection_without_effects(&settings).is_err());
        settings.wsl = Some(crate::wsl_api::WslPreferences { enabled: false, distros: vec!["unregistered fixture".into()] });
        let result = selection_without_effects(&settings).unwrap().unwrap();
        assert!(!result.needs_elevation);
        assert!(result.results.iter().all(|value| value.state == WslTargetState::NotApplied));
        settings.wsl.as_mut().unwrap().enabled = true;
        settings.client_patch = false;
        settings.dns = false;
        settings.local_proxy = false;
        settings.own_proxy_enabled = false;
        settings.group_proxy = false;
        settings.builtin_exits = false;
        let result = selection_without_effects(&settings).unwrap().unwrap();
        assert!(!result.needs_elevation);
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].state, WslTargetState::NotApplied);
    }
}
