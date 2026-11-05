// The existing Background owner's thread-confined Task Scheduler adapter.
// Public Microsoft-generated interfaces own every COM reference and ABI.
use super::{BackgroundDesired, TaskReceipt, FORWARDER_FLAG, WATCHDOG_FLAG, TASK_NAME, WATCHDOG_TASK_NAME};
use crate::windows_coordinator::{process_identity::ProcessIdentity, windows_installation::{self, CheckedPath, LegacyBackgroundInput}};
use serde::Serialize;
use std::{os::windows::ffi::OsStrExt, path::{Path, PathBuf}, thread, time::Duration};
use windows::{core::{BSTR, Interface, HRESULT}, Win32::{Foundation::VARIANT_BOOL,
    System::{Com::{CoCreateInstance, CoInitializeEx, CoUninitialize, IErrorInfo, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED},
        TaskScheduler::*, Variant::VARIANT}}};

type Result<T> = std::result::Result<T, String>;
fn err(stage: &str, error: windows::core::Error) -> String { format!("{stage}: {error}") }
fn text(value: BSTR) -> Result<String> { String::from_utf16(&value).map_err(|_| "Task Scheduler invalid UTF-16".into()) }
fn out<T: Default>(call: impl FnOnce(*mut T) -> windows::core::Result<()>) -> Result<T> {
    let mut value = T::default(); call(&mut value).map_err(|error| err("Task Scheduler property", error))?; Ok(value)
}
fn bstr(call: impl FnOnce(*mut BSTR) -> windows::core::Result<()>) -> Result<String> { text(out(call)?) }

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub(crate) enum Origin { Legacy, Managed }
#[derive(Clone, Debug, Serialize)]
pub(crate) enum ErrorInfo {
    NotQueried,
    NoInfo { hresult: i32 },
    Present { hresult: i32, source: Result<String>, description: Result<String> },
    CaptureFailure { hresult: i32, pointer_returned: bool },
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Call {
    pub operation: &'static str,
    pub role: String,
    pub instance: Option<String>,
    pub returned_hresult: Option<i32>,
    pub output_returned: bool,
    pub error_info: ErrorInfo,
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct InstanceView { pub guid: String, pub path: String, pub action_name: Result<String>, pub state: i32, pub image: &'static str }
#[derive(Clone, Debug, Serialize)]
pub(crate) struct DefinitionView {
    pub role: String, pub program: PathBuf, pub origin: Origin, pub xml: String, pub security: String,
    pub principal: String, pub logon: i32, pub instances: Vec<InstanceView>,
}
#[derive(Clone, Debug, Serialize)]
pub(crate) enum Event { Call(Call), Definition(DefinitionView), DefinitionsReadyForRetirement, InstanceRetired(InstanceView), RoleRunning { role: String, instance: InstanceView } }
pub(crate) trait Receiving {
    fn check_cancel(&mut self) -> Result<()>;
    fn before_retirement(&mut self, participants: &TransitionParticipants<'_>) -> Result<()>;
    fn receive(&mut self, event: Event) -> Result<()>;
}

fn clear_error_info() -> Result<()> {
    let hr = unsafe { windows_sys::Win32::System::Com::SetErrorInfo(0, std::ptr::null_mut()) };
    if hr == 0 { Ok(()) } else { Err(format!("clear prior COM ErrorInfo: 0x{hr:08x}")) }
}
fn capture_error_info() -> ErrorInfo {
    let mut raw = std::ptr::null_mut();
    // This is the first COM call after the raw mutating interface call.
    let hr = unsafe { windows_sys::Win32::System::Com::GetErrorInfo(0, &mut raw) };
    if hr == 1 && raw.is_null() { return ErrorInfo::NoInfo { hresult: hr }; }
    if hr == 0 && !raw.is_null() {
        let info = unsafe { IErrorInfo::from_raw(raw) };
        let source = unsafe { info.GetSource() }.map_err(|error| err("ErrorInfo source", error)).and_then(text);
        let description = unsafe { info.GetDescription() }.map_err(|error| err("ErrorInfo description", error)).and_then(text);
        return ErrorInfo::Present { hresult: hr, source, description };
    }
    let pointer_returned = !raw.is_null();
    if pointer_returned { drop(unsafe { windows::core::IUnknown::from_raw(raw) }); }
    ErrorInfo::CaptureFailure { hresult: hr, pointer_returned }
}
fn require_clean(call: &Call) -> Result<()> {
    if call.returned_hresult == Some(0) && matches!(call.error_info, ErrorInfo::NoInfo { hresult: 1 }) { return Ok(()); }
    Err(format!("{} {} returned HRESULT {:?}/ErrorInfo {:?}; no readiness or next retirement grant", call.operation, call.role, call.returned_hresult, call.error_info))
}
fn invoke<T>(receiving: &mut impl Receiving, operation: &'static str, role: &str, instance: Option<String>,
    participants: Option<&TransitionParticipants<'_>>, action: impl FnOnce() -> (HRESULT, T, bool)) -> Result<T> {
    receiving.check_cancel()?;
    let pending = Call { operation, role: role.into(), instance, returned_hresult: None, output_returned: false, error_info: ErrorInfo::NotQueried };
    receiving.receive(Event::Call(pending.clone()))?;
    if let Some(participants) = participants { receiving.before_retirement(participants)?; }
    clear_error_info()?;
    let (hr, output, output_returned) = action();
    let info = capture_error_info();
    let actual = Call { returned_hresult: Some(hr.0), output_returned, error_info: info, ..pending };
    // Retain actual HRESULT/output before interpretation or another COM call.
    receiving.receive(Event::Call(actual.clone()))?;
    require_clean(&actual)?;
    Ok(output)
}

struct Apartment;
impl Drop for Apartment { fn drop(&mut self) { unsafe { CoUninitialize() }; } }
pub(crate) struct Scheduler {
    folder: ITaskFolder,
    service: ITaskService,
    sid: String,
    _apartment: Apartment,
}
pub(crate) struct Programs<'a> { pub managed: Option<&'a CheckedPath>, pub legacy: Option<&'a LegacyBackgroundInput> }
impl Programs<'_> {
    pub(crate) fn revalidate(&self) -> Result<()> {
        if let Some(value) = self.managed { value.recheck()?; }
        if let Some(value) = self.legacy { value.revalidate()?; }
        Ok(())
    }
    fn classify(&self, path: &Path) -> Result<Origin> {
        if let Some(program) = self.managed {
            if windows_installation::same_windows_path(path, program.as_path())? { return Ok(Origin::Managed); }
        }
        if let Some(program) = self.legacy {
            if windows_installation::same_windows_path(path, program.path())? { return Ok(Origin::Legacy); }
        }
        Err("OwnershipRequired: program association is neither received Legacy nor Managed".into())
    }
}
struct Instance { native: IRunningTask, view: InstanceView }
struct Qualified {
    native: IRegisteredTask, definition: ITaskDefinition, original: DefinitionView, view: DefinitionView,
    update_acknowledged: bool, retained: Vec<Instance>,
}
pub(crate) struct TaskSet<'a> { scheduler: &'a Scheduler, tasks: Vec<Qualified>, migration_ready: bool }
pub(crate) struct TransitionParticipants<'a> { tasks: &'a [Qualified] }
fn transition_association_paths<'a>(associations: impl Iterator<Item = (&'a DefinitionView, &'a DefinitionView)>)
    -> impl Iterator<Item = &'a Path> {
    associations.flat_map(|(original, current)| [original.program.as_path(), current.program.as_path()])
}
impl TransitionParticipants<'_> {
    pub(crate) fn program_paths(&self) -> impl Iterator<Item = &Path> {
        transition_association_paths(self.tasks.iter().map(|task| (&task.original, &task.view)))
    }
}
/// Only a current independently qualified Managed definition can construct
/// this occupied-program binding. A path, ACL or matching bytes cannot.
pub(crate) struct ManagedBinding<'a> {
    scheduler: &'a Scheduler,
    program: &'a CheckedPath,
    definitions: Vec<(IRegisteredTask, DefinitionView)>,
}
pub(crate) struct PreparedRestore { definitions: Vec<DefinitionView> }
pub(crate) struct ManagedRestore<'a> { program: Option<&'a CheckedPath>, roles: PreparedRestore }
impl ManagedRestore<'_> {
    pub(crate) fn prepared_roles(&self) -> &PreparedRestore { &self.roles }
}
impl ManagedBinding<'_> {
    pub(crate) fn native_id(&self) -> windows_installation::NativeObjectId { self.program.native_id() }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.program.recheck()?;
        let programs = Programs { managed: Some(self.program), legacy: None };
        for (native, before) in &self.definitions {
            let current = self.scheduler.qualify(&before.role, native.clone(), &programs)?;
            if current.view.xml != before.xml || current.view.security != before.security || current.view.origin != Origin::Managed {
                return Err("OwnershipRequired: current managed task/program binding changed".into());
            }
        }
        Ok(())
    }
}

fn role_name(role: &str) -> Result<(&'static str, &'static str)> {
    match role { "relay" => Ok((TASK_NAME, FORWARDER_FLAG)), "watchdog" => Ok((WATCHDOG_TASK_NAME, WATCHDOG_FLAG)), _ => Err("unknown background role".into()) }
}
impl Scheduler {
    pub(crate) fn connect() -> Result<Self> {
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if hr.is_err() { return Err(format!("Task Scheduler COM apartment: 0x{:08x}", hr.0)); }
        let apartment = Apartment;
        let service: ITaskService = unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }.map_err(|error| err("Task Scheduler create", error))?;
        let empty = VARIANT::default();
        unsafe { service.Connect(&empty, &empty, &empty, &empty) }.map_err(|error| err("Task Scheduler connect", error))?;
        let folder = unsafe { service.GetFolder(&BSTR::from("\\")) }.map_err(|error| err("Task Scheduler root", error))?;
        let sid = ProcessIdentity::current()?.sid().to_owned();
        Ok(Self { folder, service, sid, _apartment: apartment })
    }
    fn find(&self, name: &str) -> Result<Option<IRegisteredTask>> {
        let tasks = unsafe { self.folder.GetTasks(1) }.map_err(|error| err("enumerate selected task namespace", error))?;
        let count = unsafe { tasks.Count() }.map_err(|error| err("task count", error))?;
        let mut found = None;
        for index in 1..=count {
            let task = unsafe { tasks.get_Item(&VARIANT::from(index)) }.map_err(|error| err("task item", error))?;
            let actual = text(unsafe { task.Name() }.map_err(|error| err("task name", error))?)?;
            if actual.eq_ignore_ascii_case(name) {
                if actual != name || found.is_some() { return Err("OwnershipRequired: selected task spelling/identity ambiguous".into()); }
                found = Some(task);
            }
        }
        Ok(found)
    }
    pub(crate) fn presence(&self) -> Result<(bool, bool)> { Ok((self.find(TASK_NAME)?.is_some(), self.find(WATCHDOG_TASK_NAME)?.is_some())) }
    /// Candidate locations only; no ownership/Stop/Run credit is returned.
    pub(crate) fn references_program(&self, legacy_path: &Path) -> Result<bool> {
        for name in [TASK_NAME, WATCHDOG_TASK_NAME] {
            if let Some(task) = self.find(name)? {
                let def = unsafe { task.Definition() }.map_err(|error| err("candidate definition", error))?;
                let actions = unsafe { def.Actions() }.map_err(|error| err("candidate actions", error))?;
                let count = out(|value| unsafe { actions.Count(value) })?;
                if count != 1 { return Err("OwnershipRequired: selected task does not have one role action".into()); }
                let action: IExecAction = unsafe { actions.get_Item(1) }.map_err(|error| err("candidate action", error))?.cast().map_err(|error| err("candidate Exec action", error))?;
                if windows_installation::same_windows_path(Path::new(&bstr(|value| unsafe { action.Path(value) })?), legacy_path)? { return Ok(true); }
            }
        }
        Ok(false)
    }
    pub(crate) fn receive<'a>(&'a self, roles: &[&str], programs: &Programs<'_>, receiving: &mut impl Receiving) -> Result<TaskSet<'a>> {
        programs.revalidate()?;
        let mut tasks = Vec::new();
        for role in roles {
            receiving.check_cancel()?;
            if let Some(task) = self.find(role_name(role)?.0)? {
                let qualified = self.qualify(role, task, programs)?;
                receiving.receive(Event::Definition(qualified.view.clone()))?;
                tasks.push(qualified);
            }
        }
        Ok(TaskSet { scheduler: self, tasks, migration_ready: false })
    }
    fn qualify(&self, role: &str, task: IRegisteredTask, programs: &Programs<'_>) -> Result<Qualified> {
        let (name, flag) = role_name(role)?;
        if text(unsafe { task.Path() }.map_err(|error| err("task path", error))?)? != format!("\\{name}") { return Err("OwnershipRequired: task path differs".into()); }
        let definition = unsafe { task.Definition() }.map_err(|error| err("task definition", error))?;
        let principal = unsafe { definition.Principal() }.map_err(|error| err("task principal", error))?;
        let user = bstr(|value| unsafe { principal.UserId(value) })?;
        if resolve_account_sid(&user)? != self.sid { return Err("OwnershipRequired: task principal differs".into()); }
        let logon = out(|value| unsafe { principal.LogonType(value) })?;
        let level = out(|value| unsafe { principal.RunLevel(value) })?;
        if logon != TASK_LOGON_S4U || level != TASK_RUNLEVEL_LUA { return Err("OwnershipRequired: unsupported task principal/logon".into()); }
        let actions = unsafe { definition.Actions() }.map_err(|error| err("task actions", error))?;
        if out(|value| unsafe { actions.Count(value) })? != 1 { return Err("OwnershipRequired: expected one Exec action".into()); }
        let base = unsafe { actions.get_Item(1) }.map_err(|error| err("task action", error))?;
        if out(|value| unsafe { base.Type(value) })? != TASK_ACTION_EXEC { return Err("OwnershipRequired: task action is not Exec".into()); }
        let action: IExecAction = base.cast().map_err(|error| err("task Exec", error))?;
        if bstr(|value| unsafe { action.Arguments(value) })? != flag { return Err("OwnershipRequired: role arguments differ".into()); }
        let program = PathBuf::from(bstr(|value| unsafe { action.Path(value) })?);
        let origin = programs.classify(&program)?;
        let settings = unsafe { definition.Settings() }.map_err(|error| err("task settings", error))?;
        if !unsafe { task.Enabled() }.map_err(|error| err("task enabled", error))?.as_bool()
            || bstr(|value| unsafe { settings.ExecutionTimeLimit(value) })? != "PT0S"
            || out(|value| unsafe { settings.DisallowStartIfOnBatteries(value) })?.as_bool()
            || out(|value| unsafe { settings.StopIfGoingOnBatteries(value) })?.as_bool()
            || out(|value| unsafe { settings.MultipleInstances(value) })? != TASK_INSTANCES_IGNORE_NEW {
            return Err("OwnershipRequired: unsupported selected task settings".into());
        }
        let triggers = unsafe { definition.Triggers() }.map_err(|error| err("task triggers", error))?;
        for index in 1..=out(|value| unsafe { triggers.Count(value) })? {
            let trigger = unsafe { triggers.get_Item(index) }.map_err(|error| err("task trigger", error))?;
            let kind = out(|value| unsafe { trigger.Type(value) })?;
            if kind != TASK_TRIGGER_LOGON && kind != TASK_TRIGGER_REGISTRATION { return Err("OwnershipRequired: due-time/unsupported trigger shape is not migration-ready".into()); }
            let repetition = unsafe { trigger.Repetition() }.map_err(|error| err("trigger repetition", error))?;
            if !bstr(|value| unsafe { repetition.Interval(value) })?.is_empty() {
                return Err("OwnershipRequired: due-time trigger repetition is unsupported".into());
            }
            if kind == TASK_TRIGGER_LOGON {
                let logon: ILogonTrigger = trigger.cast().map_err(|error| err("logon trigger", error))?;
                let delay = bstr(|value| unsafe { logon.Delay(value) })?;
                if !delay.is_empty() && delay != "PT0S" { return Err("OwnershipRequired: delayed logon trigger is not ready for migration".into()); }
            }
        }
        let security = text(unsafe { task.GetSecurityDescriptor(7) }.map_err(|error| err("task security", error))?)?;
        qualify_security(&security, &self.sid)?;
        let xml = bstr(|value| unsafe { definition.XmlText(value) })?;
        let mut retained = Vec::new();
        for instance in running(&task)? {
            let view = instance_view(&instance, name)?;
            retained.push(Instance { native: instance, view });
        }
        let view = DefinitionView { role: role.into(), program, origin, xml, security, principal: user, logon: logon.0,
            instances: retained.iter().map(|instance| instance.view.clone()).collect() };
        Ok(Qualified { native: task, definition, original: view.clone(), view, update_acknowledged: false, retained })
    }
    fn register(&self, role: &str, definition: &ITaskDefinition, flags: i32, principal: &str, logon: TASK_LOGON_TYPE,
        security: &str, receiving: &mut impl Receiving) -> Result<IRegisteredTask> {
        let name = BSTR::from(role_name(role)?.0);
        let user = VARIANT::from(principal);
        let password = VARIANT::default();
        let sddl = VARIANT::from(security);
        let task = invoke(receiving, "RegisterTaskDefinition", role, None, None, || {
            let mut raw = std::ptr::null_mut();
            let hr = unsafe { (Interface::vtable(&self.folder).RegisterTaskDefinition)(
                Interface::as_raw(&self.folder), name.as_ptr().cast_mut().cast(), Interface::as_raw(definition), flags,
                std::mem::transmute_copy(&user), std::mem::transmute_copy(&password), logon,
                std::mem::transmute_copy(&sddl), &mut raw) };
            let present = !raw.is_null();
            // Receiving an already-returned interface pointer is not a COM
            // call. It is owned before immediate thread ErrorInfo capture.
            let task = if present { Some(unsafe { IRegisteredTask::from_raw(raw) }) } else { None };
            (hr, task, present)
        })?;
        task.ok_or_else(|| "Task Scheduler returned success without registered task output".into())
    }
    pub(crate) fn ensure(&self, role: &str, programs: &Programs<'_>, create: bool, receiving: &mut impl Receiving) -> Result<TaskReceipt> {
        programs.revalidate()?;
        let found = self.find(role_name(role)?.0)?;
        let created = found.is_none();
        let task = match found {
            Some(task) => task,
            None if create => {
                let program = programs.managed.ok_or("OwnershipRequired: fresh creation requires received managed program")?;
                let definition = unsafe { self.service.NewTask(0) }.map_err(|error| err("fresh task definition", error))?;
                self.initialize_definition(role, &definition, program.as_path(), receiving)?;
                let security = format!("O:{}D:P(A;;FA;;;{})(A;;FA;;;SY)(A;;FA;;;BA)", self.sid, self.sid);
                self.register(role, &definition, TASK_CREATE.0 | TASK_DONT_ADD_PRINCIPAL_ACE.0 | TASK_IGNORE_REGISTRATION_TRIGGERS.0,
                    &self.sid, TASK_LOGON_S4U, &security, receiving)?
            }
            None => return Ok(empty_receipt()),
        };
        let qualified = self.qualify(role, task, programs)?;
        receiving.receive(Event::Definition(qualified.view.clone()))?;
        let started = if qualified.retained.is_empty() { Some(self.run(&qualified, programs, receiving)?.guid) } else { None };
        let fresh = self.qualify(role, self.find(role_name(role)?.0)?.ok_or("selected task disappeared after Run")?, programs)?;
        let instances = fresh.view.instances.iter().filter(|instance| instance.state == TASK_STATE_RUNNING.0).map(|instance| instance.guid.clone()).collect::<Vec<_>>();
        if let Some(guid) = &started { if !instances.contains(guid) { return Err("PreparationIncomplete: actual Run instance retired before receiving".into()); } }
        Ok(TaskReceipt { present: true, compatible: true, instances, created, started, retired: Vec::new(), roles_present: Vec::new() })
    }
    fn run(&self, task: &Qualified, programs: &Programs<'_>, receiving: &mut impl Receiving) -> Result<InstanceView> {
        programs.revalidate()?;
        let current = self.qualify(&task.view.role, self.find(role_name(&task.view.role)?.0)?.ok_or("selected definition absent before Run")?, programs)?;
        if current.view.xml != task.view.xml || current.view.security != task.view.security { return Err("OwnershipRequired: selected definition changed before Run".into()); }
        if !current.retained.is_empty() { return Err("OwnershipRequired: Run requires positive zero-instance receiving".into()); }
        let parameters = VARIANT::default();
        let instance = invoke(receiving, "Run", &task.view.role, None, None, || {
            let mut raw = std::ptr::null_mut();
            let hr = unsafe { (Interface::vtable(&current.native).Run)(Interface::as_raw(&current.native), std::mem::transmute_copy(&parameters), &mut raw) };
            let present = !raw.is_null();
            (hr, if present { Some(unsafe { IRunningTask::from_raw(raw) }) } else { None }, present)
        })?.ok_or("Task Scheduler Run returned no instance")?;
        let guid = text(unsafe { instance.InstanceGuid() }.map_err(|error| err("Run instance GUID", error))?)?;
        loop {
            unsafe { instance.Refresh() }.map_err(|error| err("refresh Run instance", error))?;
            let state = unsafe { instance.State() }.map_err(|error| err("Run instance state", error))?;
            if state != TASK_STATE_QUEUED { break; }
            receiving.check_cancel()?;
            thread::park_timeout(Duration::from_millis(100));
        }
        let view = instance_view(&instance, role_name(&task.view.role)?.0)?;
        if view.guid != guid { return Err("Run instance GUID changed during receiving".into()); }
        receiving.receive(Event::RoleRunning { role: task.view.role.clone(), instance: view.clone() })?;
        Ok(view)
    }
    fn initialize_definition(&self, role: &str, definition: &ITaskDefinition, program: &Path, receiving: &mut impl Receiving) -> Result<()> {
        macro_rules! set { ($object:expr,$method:ident,$value:expr) => {{
            let object = &$object; let value = $value;
            invoke(receiving, stringify!($method), role, None, None, || {
                let hr = unsafe { (Interface::vtable(object).$method)(Interface::as_raw(object), value) }; (hr, (), false)
            })?;
        }}; }
        macro_rules! set_text { ($object:expr,$method:ident,$value:expr) => {{
            let value = BSTR::from($value); set!($object,$method,value.as_ptr().cast_mut().cast());
        }}; }
        let principal = unsafe { definition.Principal() }.map_err(|error| err("fresh principal", error))?;
        set_text!(principal, SetUserId, self.sid.as_str());
        set!(principal, SetLogonType, TASK_LOGON_S4U);
        set!(principal, SetRunLevel, TASK_RUNLEVEL_LUA);
        let settings = unsafe { definition.Settings() }.map_err(|error| err("fresh settings", error))?;
        set!(settings, SetEnabled, VARIANT_BOOL::from(true));
        set!(settings, SetDisallowStartIfOnBatteries, VARIANT_BOOL::from(false));
        set!(settings, SetStopIfGoingOnBatteries, VARIANT_BOOL::from(false));
        set!(settings, SetMultipleInstances, TASK_INSTANCES_IGNORE_NEW);
        set_text!(settings, SetExecutionTimeLimit, "PT0S");
        set!(settings, SetRestartCount, 3);
        set_text!(settings, SetRestartInterval, "PT1M");
        let triggers = unsafe { definition.Triggers() }.map_err(|error| err("fresh triggers", error))?;
        let trigger = invoke(receiving, "CreateLogonTrigger", role, None, None, || {
            let mut raw = std::ptr::null_mut();
            let hr = unsafe { (Interface::vtable(&triggers).Create)(Interface::as_raw(&triggers), TASK_TRIGGER_LOGON, &mut raw) };
            let present = !raw.is_null(); (hr, if present { Some(unsafe { ITrigger::from_raw(raw) }) } else { None }, present)
        })?.ok_or("fresh logon trigger output absent")?;
        set!(trigger, SetEnabled, VARIANT_BOOL::from(true));
        let actions = unsafe { definition.Actions() }.map_err(|error| err("fresh actions", error))?;
        let action = invoke(receiving, "CreateExecAction", role, None, None, || {
            let mut raw = std::ptr::null_mut();
            let hr = unsafe { (Interface::vtable(&actions).Create)(Interface::as_raw(&actions), TASK_ACTION_EXEC, &mut raw) };
            let present = !raw.is_null(); (hr, if present { Some(unsafe { IAction::from_raw(raw) }) } else { None }, present)
        })?.ok_or("fresh Exec action output absent")?;
        let action: IExecAction = action.cast().map_err(|error| err("fresh Exec interface", error))?;
        let path = BSTR::from_wide(&program.as_os_str().encode_wide().collect::<Vec<_>>());
        set!(action, SetPath, path.as_ptr().cast_mut().cast());
        set_text!(action, SetArguments, role_name(role)?.1);
        Ok(())
    }
}

impl TaskSet<'_> {
    pub(crate) fn transition_participants<'a>(&'a self, programs: &Programs<'_>) -> Result<TransitionParticipants<'a>> {
        revalidate_selected_instances(self.scheduler, &self.tasks, programs)?;
        for task in &self.tasks {
            if programs.classify(&task.original.program)? != task.original.origin ||
                programs.classify(&task.view.program)? != task.view.origin ||
                task.original.role != task.view.role || task.original.security != task.view.security ||
                task.original.principal != task.view.principal || task.original.logon != task.view.logon {
                return Err("OwnershipRequired: transition participant association changed".into());
            }
            if !task.update_acknowledged && (task.original.xml != task.view.xml || task.original.origin != task.view.origin) {
                return Err("OwnershipRequired: transition definition changed without acknowledged update".into());
            }
            if task.update_acknowledged && (task.original.origin != Origin::Legacy || task.view.origin != Origin::Managed) {
                return Err("OwnershipRequired: acknowledged transition origins differ".into());
            }
            for instance in &task.original.instances {
                if !task.retained.iter().any(|held| held.view.guid == instance.guid && held.view.path == instance.path) {
                    return Err("OwnershipRequired: original task instance association changed".into());
                }
            }
        }
        Ok(TransitionParticipants { tasks: &self.tasks })
    }
    pub(crate) fn managed_binding<'a>(&'a self, program: &'a CheckedPath) -> Result<Option<ManagedBinding<'a>>> {
        let mut definitions = Vec::new();
        for task in &self.tasks {
            if task.view.origin == Origin::Managed && windows_installation::same_windows_path(&task.view.program, program.as_path())? {
                definitions.push((task.native.clone(), task.view.clone()));
            }
        }
        if definitions.is_empty() { return Ok(None); }
        let binding = ManagedBinding { scheduler: self.scheduler, program, definitions };
        binding.revalidate()?;
        Ok(Some(binding))
    }
    pub(crate) fn receipt(&self) -> TaskReceipt {
        TaskReceipt { present: !self.tasks.is_empty(), compatible: true,
            instances: self.tasks.iter().flat_map(|task| task.view.instances.iter().filter(|instance| instance.state == TASK_STATE_RUNNING.0).map(|instance| instance.guid.clone())).collect(),
            created: false, started: None, retired: Vec::new(), roles_present: self.roles_present() }
    }
    pub(crate) fn quiescent(&self, programs: &Programs<'_>) -> Result<()> {
        self.revalidate_instances(programs)?;
        for task in &self.tasks { if !running(&task.native)?.is_empty() { return Err("UpdatePending: selected instance appeared before program replacement".into()); } }
        Ok(())
    }
    pub(crate) fn has_legacy(&self) -> bool { self.tasks.iter().any(|task| task.view.origin == Origin::Legacy) }
    pub(crate) fn prepare_managed_restore<'a>(&self, desired: BackgroundDesired, programs: &'a Programs<'_>) -> Result<ManagedRestore<'a>> {
        let has_duty = self.tasks.iter().any(|task| (task.view.role == "relay" && desired.relay) || (task.view.role == "watchdog" && desired.watchdog));
        let program = if has_duty { Some(programs.managed.ok_or("NeedsMigration: no received Managed restoration program; zero Stop/primary")?) } else { None };
        if let Some(program) = program { program.recheck()?; }
        let roles = self.prepare_restoration(desired, programs)?;
        Ok(ManagedRestore { program, roles })
    }
    /// Shared pre-Stop prerequisite for temporary suspension and generation
    /// replacement. Definition receipts survive replacement; they do not pin or
    /// authorize a different executable. Restoration receives that actual image.
    pub(crate) fn prepare_restoration(&self, desired: BackgroundDesired, programs: &Programs<'_>) -> Result<PreparedRestore> {
        programs.revalidate()?;
        let definitions = self.tasks.iter().map(|task| task.view.clone()).collect::<Vec<_>>();
        receive_restore_prerequisites(&definitions, desired, |expected| {
            let current = self.scheduler.qualify(&expected.role,
                self.scheduler.find(role_name(&expected.role)?.0)?.ok_or("restoration definition absent before Stop")?, programs)?;
            let settings = unsafe { current.definition.Settings() }.map_err(|error| err("restore eligibility settings", error))?;
            require_run_conditions(out(|value| unsafe { settings.AllowDemandStart(value) })?.as_bool(),
                out(|value| unsafe { settings.RunOnlyIfIdle(value) })?.as_bool(),
                out(|value| unsafe { settings.RunOnlyIfNetworkAvailable(value) })?.as_bool())?;
            Ok(current.view)
        })
    }
    pub(crate) fn restore_prepared(&self, capability: &ManagedRestore<'_>, desired: BackgroundDesired,
        programs: &Programs<'_>, receiving: &mut impl Receiving) -> Result<()> {
        self.restore_prepared_mode(capability, desired, programs, false, receiving)
    }
    pub(crate) fn restore_migrated(&self, capability: &ManagedRestore<'_>, desired: BackgroundDesired,
        programs: &Programs<'_>, receiving: &mut impl Receiving) -> Result<()> {
        self.restore_prepared_mode(capability, desired, programs, true, receiving)
    }
    fn restore_prepared_mode(&self, capability: &ManagedRestore<'_>, desired: BackgroundDesired,
        programs: &Programs<'_>, migration: bool, receiving: &mut impl Receiving) -> Result<()> {
        if let Some(program) = capability.program {
            program.recheck()?;
            let actual = programs.managed.ok_or("managed restoration input disappeared")?;
            if program.native_id() != actual.native_id() { return Err("managed restoration image identity changed".into()); }
        }
        self.restore_received(&capability.roles, desired, programs, migration, receiving)
    }
    /// Used after the same owner's guarded replacement has received the current
    /// image. The retained definitions still need individual fresh validation.
    pub(crate) fn restore_replaced(&self, roles: &PreparedRestore, desired: BackgroundDesired,
        programs: &Programs<'_>, migration: bool, receiving: &mut impl Receiving) -> Result<()> {
        programs.managed.ok_or("managed replacement restoration image absent")?.recheck()?;
        self.restore_received(roles, desired, programs, migration, receiving)
    }
    fn restore_received(&self, roles: &PreparedRestore, desired: BackgroundDesired,
        programs: &Programs<'_>, migration: bool, receiving: &mut impl Receiving) -> Result<()> {
        // Only Managed execution is owed. A no-longer-used legacy input cannot
        // veto independent safe Managed restoration after retirement.
        let programs = Programs { managed: programs.managed, legacy: None };
        receive_prepared_restoration(roles, desired, migration, |role, expected| {
            match self.scheduler.find(role_name(role)?.0)? {
                Some(task) => {
                    let current = self.scheduler.qualify(role, task, &programs)?;
                    if let Some(expected) = expected { require_restore_definition(expected, &current.view)?; }
                    if current.view.origin != Origin::Managed { return Err("NeedsMigration: no legacy executable Run authority".into()); }
                    if migration && !current.retained.is_empty() {
                        return Err("RuntimeImageUnknown: preexisting native instance cannot be credited as a new managed Run; no duplicate Run".into());
                    }
                }
                None if expected.is_some() => return Err("OwnershipRequired: received definition disappeared during restoration".into()),
                None if !migration => return Err("OwnershipRequired: original role absent during restoration".into()),
                None => {}
            }
            let receipt = self.scheduler.ensure(role, &programs, migration, receiving)?;
            super::require_running(&receipt, role)
        })
    }
    pub(crate) fn roles_present(&self) -> Vec<String> { self.tasks.iter().map(|task| role_name(&task.view.role).unwrap().0.to_owned()).collect() }
    pub(crate) fn update_paths(&mut self, programs: &Programs<'_>, receiving: &mut impl Receiving) -> Result<()> {
        let target = programs.managed.ok_or("managed image must be prepared before task updates")?;
        programs.revalidate()?;
        let scheduler = self.scheduler;
        receive_task_update_batch(&mut self.tasks, receiving, |task, receiving| {
            let current = scheduler.qualify(&task.view.role, scheduler.find(role_name(&task.view.role)?.0)?.ok_or("selected definition disappeared before update")?, programs)?;
            if current.view.xml != task.view.xml || current.view.security != task.view.security { return Err("OwnershipRequired: definition changed before selected update".into()); }
            if task.view.origin == Origin::Legacy {
                let expected_xml = prepare_action_update(&task.definition, target.as_path(), &task.view.security, &task.view.role, receiving)?;
                // Preserve principal, arguments, triggers, settings and actual
                // SD. The detached XML now explicitly includes the SAME SD
                // separately supplied to the native registration call.
                scheduler.register(&task.view.role, &task.definition,
                    TASK_UPDATE.0 | TASK_DONT_ADD_PRINCIPAL_ACE.0 | TASK_IGNORE_REGISTRATION_TRIGGERS.0,
                    &task.view.principal, TASK_LOGON_TYPE(task.view.logon), &task.view.security, receiving)?;
                let after = scheduler.qualify(&task.view.role, scheduler.find(role_name(&task.view.role)?.0)?.ok_or("updated definition absent")?, programs)?;
                receiving.receive(Event::Definition(after.view.clone()))?;
                if after.view.xml != expected_xml || after.view.security != task.view.security || after.view.origin != Origin::Managed {
                    return Err("PreparationIncomplete: full action-only update/SD readback differs; zero Stop granted".into());
                }
                task.native = after.native;
                task.definition = after.definition;
                // Preserve the OLD retained instances and their original
                // image association; only registered definition facts change.
                task.view = DefinitionView { instances: task.retained.iter().map(|instance| instance.view.clone()).collect(), ..after.view };
                task.update_acknowledged = true;
            }
            Ok(())
        }, |tasks| revalidate_selected_instances(scheduler, tasks, programs))?;
        self.migration_ready = true;
        Ok(())
    }
    fn revalidate_instances(&self, programs: &Programs<'_>) -> Result<()> {
        revalidate_selected_instances(self.scheduler, &self.tasks, programs)
    }
    pub(crate) fn retire(&mut self, programs: &Programs<'_>, migration: bool, receiving: &mut impl Receiving) -> Result<Vec<String>> {
        if migration && !self.migration_ready { return Err("OwnershipRequired: all definitions have not reached ReadyForRetirement".into()); }
        self.revalidate_instances(programs)?;
        // Re-receive all native task-owned instances. CurrentAction is only an
        // action-name observation; it cannot select or exempt an image.
        for task in &mut self.tasks {
            for native in running(&task.native)? {
                let view = instance_view(&native, role_name(&task.view.role)?.0)?;
                if !task.retained.iter().any(|held| held.view.guid == view.guid) { task.retained.push(Instance { native, view }); }
            }
        }
        let mut retired = Vec::new();
        for task in &self.tasks {
            for old in &task.retained {
                let active = running(&task.native)?.into_iter().map(|instance|
                    text(unsafe { instance.InstanceGuid() }.map_err(|error| err("retained instance lookup", error))?))
                    .collect::<Result<Vec<_>>>()?.contains(&old.view.guid);
                if !active { receiving.receive(Event::InstanceRetired(old.view.clone()))?; continue; }
                unsafe { old.native.Refresh() }.map_err(|error| err("refresh retained old instance", error))?;
                let observed = instance_view(&old.native, role_name(&task.view.role)?.0)?;
                if observed.guid != old.view.guid || observed.path != old.view.path { return Err("OwnershipRequired: retained native task-instance identity changed".into()); }
                let participants = self.transition_participants(programs)?;
                invoke(receiving, "StopExactInstance", &task.view.role, Some(old.view.guid.clone()), Some(&participants), || {
                    let hr = unsafe { (Interface::vtable(&old.native).Stop)(Interface::as_raw(&old.native)) }; (hr, (), false)
                })?;
                loop {
                    let active = running(&task.native)?.into_iter().map(|instance| text(unsafe { instance.InstanceGuid() }.map_err(|error| err("retirement GUID", error))?)).collect::<Result<Vec<_>>>()?;
                    if !active.contains(&old.view.guid) { break; }
                    receiving.check_cancel()?;
                    thread::park_timeout(Duration::from_millis(100));
                }
                retired.push(old.view.guid.clone());
                receiving.receive(Event::InstanceRetired(old.view.clone()))?;
            }
        }
        Ok(retired)
    }
    pub(crate) fn remove(self, programs: &Programs<'_>, receiving: &mut impl Receiving) -> Result<TaskReceipt> {
        let mut this = self;
        let retired = this.retire(programs, false, receiving)?;
        for task in &this.tasks {
            let current = this.scheduler.qualify(&task.view.role, this.scheduler.find(role_name(&task.view.role)?.0)?.ok_or("definition absent before removal")?, programs)?;
            if current.view.xml != task.view.xml || current.view.security != task.view.security || !current.retained.is_empty() { return Err("OwnershipRequired: changed/running task before removal".into()); }
            let name = BSTR::from(role_name(&task.view.role)?.0);
            invoke(receiving, "DeleteQualifiedTask", &task.view.role, None, None, || {
                let hr = unsafe { (Interface::vtable(&this.scheduler.folder).DeleteTask)(Interface::as_raw(&this.scheduler.folder), name.as_ptr().cast_mut().cast(), 0) }; (hr, (), false)
            })?;
            if this.scheduler.find(role_name(&task.view.role)?.0)?.is_some() { return Err("PreparationIncomplete: removed task still exists".into()); }
        }
        Ok(TaskReceipt { present: !this.tasks.is_empty(), compatible: true, instances: Vec::new(), created: false, started: None, retired, roles_present: this.roles_present() })
    }
}

fn prepare_action_update(definition: &ITaskDefinition, target: &Path, security: &str,
    role: &str, receiving: &mut impl Receiving) -> Result<String> {
    let actions = unsafe { definition.Actions() }.map_err(|error| err("update actions", error))?;
    let action: IExecAction = unsafe { actions.get_Item(1) }.map_err(|error| err("update Exec", error))?.cast().map_err(|error| err("update Exec interface", error))?;
    let path = BSTR::from_wide(&target.as_os_str().encode_wide().collect::<Vec<_>>());
    invoke(receiving, "SetDetachedActionPath", role, None, None, || {
        let hr = unsafe { (Interface::vtable(&action).SetPath)(Interface::as_raw(&action), path.as_ptr().cast_mut().cast()) }; (hr, (), false)
    })?;
    let registration = unsafe { definition.RegistrationInfo() }.map_err(|error| err("update registration info", error))?;
    let descriptor = VARIANT::from(security);
    invoke(receiving, "SetDetachedRegistrationSecurityDescriptor", role, None, None, || {
        let hr = unsafe { (Interface::vtable(&registration).SetSecurityDescriptor)(Interface::as_raw(&registration), std::mem::transmute_copy(&descriptor)) }; (hr, (), false)
    })?;
    bstr(|value| unsafe { definition.XmlText(value) })
}

/// One ordering gate for the actual SDK updates and their independent complete
/// readbacks. It grants Ready only after every selected item and final native
/// association recheck. The injected closures are the bounded unit-test seam,
/// not a second task policy or a persistent transition protocol.
fn receive_task_update_batch<T, R: Receiving>(tasks: &mut [T], receiving: &mut R,
    mut update_and_readback: impl FnMut(&mut T, &mut R) -> Result<()>,
    receive_associations: impl FnOnce(&[T]) -> Result<()>) -> Result<()> {
    for task in tasks.iter_mut() {
        receiving.check_cancel()?;
        update_and_readback(task, receiving)?;
    }
    receive_associations(tasks)?;
    receiving.check_cancel()?;
    receiving.receive(Event::DefinitionsReadyForRetirement)
}
fn revalidate_selected_instances(scheduler: &Scheduler, tasks: &[Qualified], programs: &Programs<'_>) -> Result<()> {
    programs.revalidate()?;
    for task in tasks {
        let current = scheduler.qualify(&task.view.role, scheduler.find(role_name(&task.view.role)?.0)?.ok_or("definition absent before retirement")?, programs)?;
        if current.view.xml != task.view.xml || current.view.security != task.view.security { return Err("OwnershipRequired: current definition changed after update".into()); }
        // Every current instance came from this freshly qualified task's native
        // GetInstances collection. Its image/generation remains Unknown.
    }
    Ok(())
}

fn empty_receipt() -> TaskReceipt { TaskReceipt { present: false, compatible: false, instances: Vec::new(), created: false, started: None, retired: Vec::new(), roles_present: Vec::new() } }

fn running(task: &IRegisteredTask) -> Result<Vec<IRunningTask>> {
    let collection = unsafe { task.GetInstances(0) }.map_err(|error| err("task instances", error))?;
    let count = unsafe { collection.Count() }.map_err(|error| err("instance count", error))?;
    (1..=count).map(|index| unsafe { collection.get_Item(&VARIANT::from(index)) }.map_err(|error| err("instance item", error))).collect()
}
fn instance_view(instance: &IRunningTask, name: &str) -> Result<InstanceView> {
    let guid = text(unsafe { instance.InstanceGuid() }.map_err(|error| err("instance GUID", error))?)?;
    let path = text(unsafe { instance.Path() }.map_err(|error| err("instance task path", error))?)?;
    let action_name = unsafe { instance.CurrentAction() }.map_err(|error| err("instance action name", error)).and_then(text);
    let state = unsafe { instance.State() }.map_err(|error| err("instance state", error))?.0;
    task_instance_observation(guid, path, action_name, state, name)
}
fn task_instance_observation(guid: String, path: String, action_name: Result<String>, state: i32, name: &str) -> Result<InstanceView> {
    if guid.is_empty() { return Err("OwnershipRequired: empty native instance GUID".into()); }
    if path != format!("\\{name}") { return Err("OwnershipRequired: native instance task path differs".into()); }
    if state != TASK_STATE_RUNNING.0 && state != TASK_STATE_QUEUED.0 { return Err("OwnershipRequired: terminal/unknown native task instance".into()); }
    Ok(InstanceView { guid, path, action_name, state, image: "Unknown" })
}
fn require_managed_restore_origin(origin: Origin, wanted: bool) -> Result<()> {
    if wanted && origin != Origin::Managed { Err("NeedsMigration: wanted role has no Managed restore definition; zero Stop/primary".into()) }
    else { Ok(()) }
}
fn require_run_conditions(allow_demand_start: bool, idle_only: bool, network_only: bool) -> Result<()> {
    if !allow_demand_start || idle_only || network_only {
        Err("NeedsManagedRestore: unsupported native Run conditions; zero Stop/primary".into())
    } else { Ok(()) }
}
fn require_restore_definition(expected: &DefinitionView, current: &DefinitionView) -> Result<()> {
    if current.role != expected.role || current.xml != expected.xml || current.security != expected.security || current.origin != Origin::Managed {
        Err("managed restoration capability changed".into())
    } else { Ok(()) }
}
fn receive_restore_prerequisites(definitions: &[DefinitionView], desired: BackgroundDesired,
    mut qualify_run: impl FnMut(&DefinitionView) -> Result<DefinitionView>) -> Result<PreparedRestore> {
    let mut prepared = Vec::new();
    for expected in definitions {
        let wanted = match expected.role.as_str() { "relay" => desired.relay, "watchdog" => desired.watchdog, _ => false };
        require_managed_restore_origin(expected.origin, wanted)?;
        if wanted {
            let current = qualify_run(expected)?;
            require_restore_definition(expected, &current)?;
            prepared.push(current);
        }
    }
    Ok(PreparedRestore { definitions: prepared })
}
/// One changed role cannot veto another already-owed, independently safe role.
/// The native closure performs its own complete qualification and Run receiving.
fn receive_prepared_restoration(roles: &PreparedRestore, desired: BackgroundDesired, migration: bool,
    mut restore_role: impl FnMut(&str, Option<&DefinitionView>) -> Result<()>) -> Result<()> {
    let mut errors = Vec::new();
    for (wanted, role) in [(desired.watchdog, "watchdog"), (desired.relay, "relay")] {
        if !wanted { continue; }
        let expected = roles.definitions.iter().find(|definition| definition.role == role);
        if expected.is_none() && !migration { continue; }
        if let Err(error) = restore_role(role, expected) { errors.push(format!("{role}: {error}")); }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

struct LocalMemory(*mut core::ffi::c_void);
impl Drop for LocalMemory { fn drop(&mut self) { unsafe { windows_sys::Win32::Foundation::LocalFree(self.0) }; } }
fn sid_text(sid: *mut core::ffi::c_void) -> Result<String> {
    use windows_sys::Win32::Security::{Authorization::ConvertSidToStringSidW, IsValidSid};
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 { return Err("Task Scheduler SID invalid".into()); }
    let mut raw = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 { return Err(format!("task SID: {}", std::io::Error::last_os_error())); }
    let _owned = LocalMemory(raw.cast());
    let mut size = 0;
    unsafe { while *raw.add(size) != 0 { size += 1; } }
    String::from_utf16(unsafe { std::slice::from_raw_parts(raw, size) }).map_err(|_| "task SID encoding".into())
}
fn resolve_account_sid(account: &str) -> Result<String> {
    use windows_sys::Win32::Security::LookupAccountNameW;
    if account.starts_with("S-1-") { return Ok(account.to_owned()); }
    let name = account.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut sid_size = 0;
    let mut domain_size = 0;
    let mut kind = 0;
    unsafe { LookupAccountNameW(std::ptr::null(), name.as_ptr(), std::ptr::null_mut(), &mut sid_size, std::ptr::null_mut(), &mut domain_size, &mut kind) };
    if sid_size == 0 { return Err(format!("task principal receiving: {}", std::io::Error::last_os_error())); }
    let mut sid = vec![0u8; sid_size as usize];
    let mut domain = vec![0u16; domain_size as usize];
    if unsafe { LookupAccountNameW(std::ptr::null(), name.as_ptr(), sid.as_mut_ptr().cast(), &mut sid_size, domain.as_mut_ptr(), &mut domain_size, &mut kind) } == 0 {
        return Err(format!("task principal receiving: {}", std::io::Error::last_os_error()));
    }
    sid_text(sid.as_mut_ptr().cast())
}
fn qualify_security(sddl: &str, current: &str) -> Result<()> {
    use windows_sys::Win32::Security::{Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityDescriptorOwner, GetSecurityDescriptorDacl, GetAce, ACL, ACE_HEADER, ACCESS_ALLOWED_ACE, INHERIT_ONLY_ACE};
    let wide = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut raw = std::ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide.as_ptr(), 1, &mut raw, std::ptr::null_mut()) } == 0 {
        return Err(format!("task descriptor: {}", std::io::Error::last_os_error()));
    }
    let _owned = LocalMemory(raw);
    let mut owner = std::ptr::null_mut();
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(raw, &mut owner, &mut defaulted) } == 0 { return Err("task descriptor owner unavailable".into()); }
    let trusted = |sid: &str| sid == current || sid == "S-1-5-18" || sid == "S-1-5-32-544";
    if !trusted(&sid_text(owner)?) { return Err("OwnershipRequired: task descriptor owner differs".into()); }
    let mut present = 0;
    let mut acl: *mut ACL = std::ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(raw, &mut present, &mut acl, &mut defaulted) } == 0 || present == 0 || acl.is_null() {
        return Err("OwnershipRequired: task DACL absent/null".into());
    }
    for index in 0..unsafe { (*acl).AceCount as u32 } {
        let mut ace = std::ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut ace) } == 0 || ace.is_null() { return Err("task ACE unavailable".into()); }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        // WinNT.h ACE type protocol values: ACCESS_ALLOWED=0, DENIED=1.
        if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 || header.AceType == 1 { continue; }
        if header.AceType != 0 || (header.AceSize as usize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>() {
            return Err("OwnershipRequired: unsupported task security ACE".into());
        }
        let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
        let sid = unsafe { std::ptr::addr_of!((*allowed).SidStart).cast_mut().cast() };
        if !trusted(&sid_text(sid)?) { return Err("OwnershipRequired: task descriptor grants another principal".into()); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn positive_hresult_warning_and_error_info_are_not_success() {
        let mut value = Call { operation: "syntheticRegister", role: "synthetic".into(), instance: None,
            returned_hresult: Some(0), output_returned: true, error_info: ErrorInfo::NoInfo { hresult: 1 } };
        assert!(require_clean(&value).is_ok());
        value.returned_hresult = Some(0x0004_131b);
        assert!(require_clean(&value).is_err());
        value.returned_hresult = Some(0);
        value.error_info = ErrorInfo::Present { hresult: 0, source: Ok("TaskUpdateWarnings".into()), description: Ok("synthetic native warning".into()) };
        assert!(require_clean(&value).is_err());
        value.error_info = ErrorInfo::CaptureFailure { hresult: 0, pointer_returned: false };
        assert!(require_clean(&value).is_err());
    }
    #[test]
    fn action_names_never_classify_instance_images_or_exempt_quiescence() {
        for action in ["", "NamedAction", r"C:\ProgramData\AGUnlocker\ag_dns.exe", r"C:\Program Files\AGUnlocker\ag_dns.exe"] {
            let observed = task_instance_observation("synthetic-guid".into(), format!("\\{TASK_NAME}"), Ok(action.into()), 4, TASK_NAME).unwrap();
            assert_eq!(observed.action_name.as_deref(), Ok(action));
            assert_eq!(observed.image, "Unknown");
            assert_eq!(observed.guid, "synthetic-guid");
        }
        assert!(task_instance_observation("synthetic".into(), "\\foreign".into(), Ok("NamedAction".into()), 4, TASK_NAME).is_err());
        assert_eq!(task_instance_observation("synthetic".into(), format!("\\{TASK_NAME}"), Err("native action-name diagnostic unavailable".into()), 4, TASK_NAME).unwrap().image, "Unknown");
    }
    #[test]
    fn legacy_temporary_restore_is_not_a_run_capability() {
        let mut stops = 0;
        let preflight = require_managed_restore_origin(Origin::Legacy, true);
        if preflight.is_ok() { stops += 1; }
        assert!(preflight.is_err());
        assert_eq!(stops, 0);
        assert!(require_managed_restore_origin(Origin::Managed, true).is_ok());
        assert!(require_managed_restore_origin(Origin::Legacy, false).is_ok(), "Off needs no legacy execute capability");
    }
    #[test]
    fn common_restoration_preflight_and_role_failure_receiving() {
        fn definition(role: &str) -> DefinitionView {
            DefinitionView { role: role.into(), program: PathBuf::from("synthetic-managed-program"), origin: Origin::Managed,
                xml: format!("synthetic-{role}-full-definition"), security: "synthetic-owned-security".into(),
                principal: "synthetic-owner".into(), logon: TASK_LOGON_S4U.0, instances: Vec::new() }
        }
        let definitions = [definition("watchdog"), definition("relay")];
        let desired = BackgroundDesired { relay: true, watchdog: true };
        // Both real callers use this exact prerequisite before they can reach
        // their retained TaskSet's Stop. No COM objects or product tasks exist.
        for unsupported in [(false, false, false), (true, true, false), (true, false, true)] {
            let mut stops = 0;
            let mut primary_calls = 0;
            let prepared = receive_restore_prerequisites(&definitions, desired, |expected| {
                require_run_conditions(unsupported.0, unsupported.1, unsupported.2)?;
                Ok(expected.clone())
            });
            if prepared.is_ok() { stops += 1; primary_calls += 1; }
            assert!(prepared.err().unwrap().contains("zero Stop/primary"));
            assert_eq!((stops, primary_calls), (0, 0));
        }
        let prepared = receive_restore_prerequisites(&definitions, desired, |expected| {
            require_run_conditions(true, false, false)?;
            Ok(expected.clone())
        }).unwrap();
        let mut attempted = Vec::new();
        let mut running_received = Vec::new();
        // Inject drift AFTER the common preflight/retirement boundary into the
        // exact production restoration wrapper. Only the unsafe role is held.
        let result = receive_prepared_restoration(&prepared, desired, false, |role, expected| {
            attempted.push(role.to_owned());
            let expected = expected.unwrap();
            let mut actual = expected.clone();
            if role == "watchdog" { actual.xml.push_str("-changed-after-retirement"); }
            require_restore_definition(expected, &actual)?;
            let guid = format!("synthetic-{role}-Run-guid");
            let instance = task_instance_observation(guid.clone(), format!("\\{}", role_name(role)?.0),
                Ok("NamedAction".into()), TASK_STATE_RUNNING.0, role_name(role)?.0)?;
            let receipt = TaskReceipt { present: true, compatible: true, instances: vec![guid.clone()], created: false,
                started: Some(guid), retired: Vec::new(), roles_present: Vec::new() };
            super::super::require_running(&receipt, role)?;
            running_received.push(Event::RoleRunning { role: role.into(), instance });
            Ok(())
        });
        assert_eq!(attempted, ["watchdog", "relay"]);
        let error = result.unwrap_err();
        assert!(error.contains("watchdog: managed restoration capability changed"));
        assert!(!error.contains("relay:"));
        assert!(matches!(running_received.as_slice(), [Event::RoleRunning { role, instance }]
            if role == "relay" && instance.guid == "synthetic-relay-Run-guid" && instance.state == TASK_STATE_RUNNING.0));
    }
    #[test]
    fn migration_updates_readbacks_and_associations_precede_first_stop() {
        use std::{cell::RefCell, rc::Rc};
        struct Fixture { cancelled: bool, ready: bool, stops: usize, trace: Rc<RefCell<Vec<String>>> }
        impl Receiving for Fixture {
            fn check_cancel(&mut self) -> Result<()> { if self.cancelled { Err("synthetic cancellation".into()) } else { Ok(()) } }
            fn before_retirement(&mut self, _: &TransitionParticipants<'_>) -> Result<()> {
                if !self.ready { return Err("not ReadyForRetirement".into()); }
                self.stops += 1;
                self.trace.borrow_mut().push("stop".into());
                Ok(())
            }
            fn receive(&mut self, event: Event) -> Result<()> {
                if matches!(event, Event::DefinitionsReadyForRetirement) {
                    self.ready = true;
                    self.trace.borrow_mut().push("ready".into());
                }
                Ok(())
            }
        }
        for case in ["first-error", "second-error", "positive-warning", "readback-mismatch", "cancel-between", "association-mismatch", "success"] {
            let trace = Rc::new(RefCell::new(Vec::<String>::new()));
            let mut fixture = Fixture { cancelled: false, ready: false, stops: 0, trace: trace.clone() };
            let mut roles = ["relay", "watchdog"];
            let mut callbacks = [0, 0];
            let result = receive_task_update_batch(&mut roles, &mut fixture, |role, receiving| {
                let index = usize::from(*role == "watchdog");
                callbacks[index] += 1;
                trace.borrow_mut().push(format!("update:{role}"));
                if (case == "first-error" && index == 0) || (case == "second-error" && index == 1) {
                    return Err("synthetic native update failure".into());
                }
                if case == "positive-warning" && index == 1 {
                    let call = Call { operation: "syntheticRegister", role: role.to_string(), instance: None,
                        returned_hresult: Some(0x0004_131b), output_returned: true, error_info: ErrorInfo::NoInfo { hresult: 1 } };
                    require_clean(&call)?;
                }
                trace.borrow_mut().push(format!("readback:{role}"));
                if case == "readback-mismatch" && index == 1 { return Err("synthetic full definition/SD mismatch".into()); }
                if case == "cancel-between" && index == 0 { receiving.cancelled = true; }
                Ok(())
            }, |_| {
                trace.borrow_mut().push("associations".into());
                if case == "association-mismatch" { Err("synthetic old-instance association changed".into()) } else { Ok(()) }
            });
            assert!(callbacks.iter().all(|count| *count <= 1), "one update/readback callback per selected role");
            if result.is_ok() { fixture.before_retirement(&TransitionParticipants { tasks: &[] }).unwrap(); }
            if case == "success" {
                assert_eq!(callbacks, [1, 1]);
                assert_eq!(&*trace.borrow(), &["update:relay", "readback:relay", "update:watchdog", "readback:watchdog", "associations", "ready", "stop"]);
                assert_eq!(fixture.stops, 1);
            } else {
                assert!(result.is_err(), "{case}");
                assert!(!fixture.ready, "{case}: incomplete update batch cannot authorize retirement");
                assert_eq!(fixture.stops, 0, "{case}: zero Stop");
                assert!(fixture.before_retirement(&TransitionParticipants { tasks: &[] }).is_err(), "{case}: native retirement guard remains closed");
            }
            if case == "first-error" || case == "cancel-between" { assert_eq!(callbacks, [1, 0]); }
        }
        // Pure common-owner projection: real task qualification and native Stop
        // are intentionally outside this fixture's authority.
        let original = DefinitionView { role: "relay".into(), program: PathBuf::from("synthetic-legacy-A"), origin: Origin::Legacy,
            xml: "legacy-definition".into(), security: "same-security".into(), principal: "same-principal".into(),
            logon: TASK_LOGON_S4U.0, instances: vec![task_instance_observation("synthetic-guid".into(),
                format!("\\{TASK_NAME}"), Ok("action".into()), TASK_STATE_RUNNING.0, TASK_NAME).unwrap()] };
        let mut current = [original.clone()];
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut fixture = Fixture { cancelled: false, ready: false, stops: 0, trace: trace.clone() };
        receive_task_update_batch(&mut current, &mut fixture, |view, _| {
            trace.borrow_mut().push("update".into());
            view.program = PathBuf::from("synthetic-managed-B");
            view.origin = Origin::Managed;
            view.xml = "received-managed-definition".into();
            trace.borrow_mut().push("readback".into());
            Ok(())
        }, |_| { trace.borrow_mut().push("associations".into()); Ok(()) }).unwrap();
        assert_eq!(current[0].origin, Origin::Managed);
        assert_eq!(original.instances[0].image, "Unknown");
        let report = crate::gate::Report { at: u64::MAX, version: crate::dns_forwarder::RELAY_VERSION + 1,
            exe: "synthetic-legacy-A".into(), ..Default::default() };
        let metadata = Ok(Some(crate::dns_forwarder::RELAY_VERSION));
        let projection = || transition_association_paths(std::iter::once((&original, &current[0])));
        assert_eq!(projection().collect::<Vec<_>>(), [original.program.as_path(), current[0].program.as_path()]);
        let guard = super::super::selected_retirement_decision(projection(), Some(&report), &metadata, |_| Ok(()));
        if guard.is_ok() { fixture.before_retirement(&TransitionParticipants { tasks: &[] }).unwrap(); }
        assert!(guard.unwrap_err().contains("newer"));
        assert_eq!(fixture.stops, 0);
        assert_eq!(&*trace.borrow(), &["update", "readback", "associations", "ready"]);
        let mut replaced = original.clone();
        replaced.program = PathBuf::from("different-original");
        let lost_original = transition_association_paths(std::iter::once((&replaced, &current[0])));
        assert!(super::super::selected_retirement_decision(lost_original, Some(&report), &metadata, |_| Ok(())).is_ok(),
            "the countercase shows that replacing the original loses the newer veto");
        // A freshly admitted Managed definition carries no Legacy history. This
        // countercase would miss the veto, demonstrating why the retained pair matters.
        let fresh = || transition_association_paths(std::iter::once((&current[0], &current[0])));
        assert!(!fresh().any(|path| path == original.program.as_path()));
        assert!(super::super::selected_retirement_decision(fresh(), Some(&report), &metadata, |_| Ok(())).is_ok());
        for prior_stops in [0, 1] {
            let mut effects = Vec::new();
            let mut primary_calls = 0;
            let fresh_check = super::super::selected_retirement_decision(projection(), Some(&report), &metadata,
                |effect| { effects.push(effect); Ok(()) });
            if fresh_check.is_ok() { primary_calls += 1; }
            assert!(fresh_check.unwrap_err().contains("newer"));
            assert_eq!(primary_calls, 0, "{prior_stops} earlier Stops must not grant primary");
            assert!(matches!(effects.as_slice(), [super::super::BackgroundEffect::GenerationObserved { metadata: Ok(Some(value)), runtime: Some(runtime) }]
                if *value == crate::dns_forwarder::RELAY_VERSION && *runtime == crate::dns_forwarder::RELAY_VERSION + 1));
        }
        let failed_retention = super::super::selected_retirement_decision(projection(), Some(&report), &metadata,
            |_| Err("synthetic evidence retention failure".into()));
        assert_eq!(failed_retention.unwrap_err(), "synthetic evidence retention failure");
    }
    #[test]
    #[ignore = "controlled in-memory native SDK definitions only; never registers/runs/stops a task or writes task files"]
    fn native_detached_update_materializes_captured_security_before_xml() {
        #[derive(Default)]
        struct Capture { events: Vec<Event> }
        impl Receiving for Capture {
            fn check_cancel(&mut self) -> Result<()> { Ok(()) }
            fn before_retirement(&mut self, _: &TransitionParticipants<'_>) -> Result<()> { panic!("detached definition fixture cannot grant Stop") }
            fn receive(&mut self, event: Event) -> Result<()> { self.events.push(event); Ok(()) }
        }
        let scheduler = Scheduler::connect().unwrap();
        let mut capture = Capture::default();
        // Synthetic paths are only BSTR input to detached COM objects. No file
        // is opened, created, replaced or executed at either location.
        let old = Path::new(r"C:\synthetic-background-legacy\ag_dns.exe");
        let target = Path::new(r"C:\synthetic-background-managed\ag_dns.exe");
        let captured_security = "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";
        let mut prepared_xml = Vec::new();
        for embedded in [false, true] {
            let definition = invoke(&mut capture, "FixtureNewDetachedDefinition", "relay", None, None, || {
                let mut raw = std::ptr::null_mut();
                let hr = unsafe { (Interface::vtable(&scheduler.service).NewTask)(Interface::as_raw(&scheduler.service), 0, &mut raw) };
                let present = !raw.is_null();
                (hr, if present { Some(unsafe { ITaskDefinition::from_raw(raw) }) } else { None }, present)
            }).unwrap().expect("native detached definition output required");
            scheduler.initialize_definition("relay", &definition, old, &mut capture).unwrap();
            let registration = unsafe { definition.RegistrationInfo() }.unwrap();
            if embedded {
                let descriptor = VARIANT::from(captured_security);
                invoke(&mut capture, "FixtureEmbedCapturedSecurityDescriptor", "relay", None, None, || {
                    let hr = unsafe { (Interface::vtable(&registration).SetSecurityDescriptor)(Interface::as_raw(&registration), std::mem::transmute_copy(&descriptor)) };
                    (hr, (), false)
                }).unwrap();
            }
            let before = bstr(|value| unsafe { definition.XmlText(value) }).unwrap();
            assert_eq!(before.contains("<SecurityDescriptor>"), embedded);
            let prepared = prepare_action_update(&definition, target, captured_security, "relay", &mut capture).unwrap();
            let actual_descriptor = out(|value| unsafe { registration.SecurityDescriptor(value) }).unwrap();
            assert!(actual_descriptor.vt() == windows::Win32::System::Variant::VT_BSTR, "native descriptor getter must return an owning BSTR variant");
            // Borrow the public generated BSTR union member only after the
            // VARTYPE check. The VARIANT retains ownership and clears it once.
            let descriptor_bstr: &BSTR = unsafe { &actual_descriptor.Anonymous.Anonymous.Anonymous.bstrVal };
            let descriptor_text = String::from_utf16(descriptor_bstr).unwrap();
            assert!(descriptor_text == captured_security, "the captured descriptor must be retained exactly");
            assert_eq!(prepared.matches("<SecurityDescriptor>").count(), 1);
            assert!(prepared.contains(&format!("<SecurityDescriptor>{captured_security}</SecurityDescriptor>")));
            if embedded {
                // With the descriptor already explicit, the complete native
                // serialization must change only the intended Command bytes.
                let expected = before.replace(old.to_str().unwrap(), target.to_str().unwrap());
                assert!(prepared == expected, "full detached XML changed beyond Command despite an unchanged explicit descriptor");
            }
            prepared_xml.push(prepared);
        }
        assert!(prepared_xml[0] == prepared_xml[1], "missing and already-embedded SD must produce the same complete expected XML");
        let actual_calls = capture.events.iter().filter_map(|event| match event { Event::Call(call) if call.returned_hresult.is_some() => Some(call), _ => None }).collect::<Vec<_>>();
        assert_eq!(actual_calls.iter().filter(|call| call.operation == "SetDetachedRegistrationSecurityDescriptor").count(), 2);
        assert!(actual_calls.iter().all(|call| require_clean(call).is_ok()));
        assert!(actual_calls.iter().all(|call| !matches!(call.operation, "RegisterTaskDefinition" | "Run" | "StopExactInstance" | "DeleteQualifiedTask")));
        println!("two native detached-definition cases received exact captured SD/full XML before registration; zero registered-task mutations");
    }
    #[test]
    #[ignore = "controlled read-only native SDK probe; never registers/runs/stops a task"]
    fn native_root_path_preserves_actual_hresult() {
        let scheduler = Scheduler::connect().unwrap();
        clear_error_info().unwrap();
        let mut path = BSTR::default();
        let hr = unsafe { (Interface::vtable(&scheduler.folder).Path)(Interface::as_raw(&scheduler.folder), (&mut path as *mut BSTR).cast()) };
        let info = capture_error_info();
        assert_eq!(hr.0, 0);
        assert_eq!(text(path).unwrap(), "\\");
        assert!(matches!(info, ErrorInfo::NoInfo { hresult: 1 }));
    }
}
