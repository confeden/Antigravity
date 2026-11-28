//! Windows containment and launch settings for paid IDE/application routing.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::paid::{PaidApp, PaidAppStatus};

const GROUP: &str = "AI Unlocker Paid IDE";
const CLAUDE_FAMILY: &str = "Claude_pzs8sxrjxfjjc";

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn clean_ps_error(stderr: &str, status: std::process::ExitStatus) -> String {
    let mut lines = Vec::new();
    for line in stderr.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("At line:")
            || trimmed.starts_with("строка:")
            || trimmed.starts_with("+ ")
            || trimmed.starts_with('~')
            || trimmed.starts_with("CategoryInfo")
            || trimmed.starts_with("FullyQualifiedErrorId")
        {
            break;
        }
        if !trimmed.is_empty() {
            lines.push(trimmed);
        }
    }
    let msg = lines.join(" ");
    if msg.contains("Enable Windows Firewall for all profiles before enabling paid routing.") {
        return "Включите брандмауэр Windows для всех профилей перед включением PAID.".into();
    }
    if msg.contains("Claude Desktop already has a managed") {
        return "В Claude Desktop уже задан управляемый прокси или PAC. AI Unlocker сохранил эту настройку.".into();
    }
    if msg.contains("Claude Desktop PAID policy failed verification.") {
        return "Windows не подтвердила сохранение настройки PAID для Claude Desktop.".into();
    }
    if msg.is_empty() {
        format!("Настройка Windows завершилась со статусом {status}")
    } else {
        msg
    }
}

fn ps(script: &str) -> Result<(), String> {
    let output = crate::utils::powershell_within(
        &format!("$ErrorActionPreference='Stop'; {script}"),
        Duration::from_secs(75),
    )
    .ok_or("Windows не ответила при настройке платного режима")?;
    if output.status.success() {
        return Ok(());
    }
    let reason = String::from_utf8_lossy(&output.stderr).trim().to_string();
    crate::dns_forwarder::log_proxy(&format!(
        "paid powershell failed ({}): {}",
        output.status, reason
    ));
    Err(clean_ps_error(&reason, output.status))
}

fn collect_programs(root: &Path, programs: &mut Vec<PathBuf>) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    const REPARSE_POINT: u32 = 0x400;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() && entry.metadata()?.file_attributes() & REPARSE_POINT == 0 {
            collect_programs(&entry.path(), programs)?;
        } else if kind.is_file() {
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
                && !entry.file_name().to_string_lossy().starts_with("unins")
            {
                programs.push(path);
            }
        }
    }
    Ok(())
}

const BOOTSTRAP: &str = include_str!("paid_ide_bootstrap.js");
const BOOTSTRAP_START: &str = "/* AI Unlocker paid IDE proxy */";
const BOOTSTRAP_END: &str = "/* End AI Unlocker paid IDE proxy */\n";
const IDE_CONFIGURED: &str = "ide-bootstrap-v1\n";

#[derive(Debug)]
struct Ide {
    exe: PathBuf,
    entry: PathBuf,
}

fn ide(install: &Path) -> Option<Ide> {
    if crate::install_label(install) != "Antigravity IDE" {
        return None;
    }
    let exe = ["Antigravity IDE.exe", "Antigravity.exe"]
        .into_iter()
        .map(|name| install.join(name))
        .find(|path| path.is_file())?;
    let app = install.join("resources/app");
    let entry = app.join("out/main.js");
    let package: serde_json::Value =
        serde_json::from_slice(&fs::read(app.join("package.json")).ok()?).ok()?;
    if package["type"] != "module"
        || !matches!(
            package["main"].as_str(),
            Some("./out/main.js" | "out/main.js")
        )
        || !entry.is_file()
    {
        return None;
    }
    Some(Ide { exe, entry })
}

fn installations() -> Vec<Ide> {
    let mut installs = crate::find_all_installs();
    installs.extend(crate::settings::manual_paths());
    let mut ides: Vec<_> = installs.iter().filter_map(|root| ide(root)).collect();
    ides.sort_by(|left, right| left.exe.cmp(&right.exe));
    ides.dedup_by(|left, right| left.exe == right.exe);
    ides
}

fn original_source(source: &str) -> Result<&str, String> {
    if !source.starts_with(BOOTSTRAP_START) {
        return Ok(source);
    }
    source
        .split_once(BOOTSTRAP_END)
        .map(|(_, original)| original)
        .ok_or_else(|| "Не удалось прочитать настройки запуска Antigravity IDE".into())
}

pub(crate) fn remove_bootstrap(path: &Path, source: &str) -> Result<bool, String> {
    let original = original_source(source)?;
    if original.len() == source.len() {
        return Ok(false);
    }
    crate::patch_ide::write_atomic(path, original)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(true)
}

fn install_bootstrap(entry: &Path) -> Result<(), String> {
    let source =
        fs::read_to_string(entry).map_err(|error| format!("{}: {error}", entry.display()))?;
    if source.starts_with(BOOTSTRAP) {
        return Ok(());
    }
    let original = original_source(&source)?;
    crate::patch_ide::write_atomic(entry, &format!("{BOOTSTRAP}{original}"))
        .map_err(|error| format!("{}: {error}", entry.display()))
}

pub(crate) fn repair_bootstrap(install: &Path) -> Result<(), String> {
    use std::io::Read;
    let Some(ide) = ide(install) else {
        return Ok(());
    };
    let mut head = vec![0; BOOTSTRAP.len()];
    let mut file = fs::File::open(&ide.entry).map_err(|error| error.to_string())?;
    match file.read_exact(&mut head) {
        Ok(()) if head == BOOTSTRAP.as_bytes() => return Ok(()),
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(error) => return Err(error.to_string()),
    }
    drop(file);
    install_bootstrap(&ide.entry)
}

pub fn discover_apps(installs: &[crate::ops::InstallRow]) -> Vec<PaidAppStatus> {
    let active = crate::paid::active_apps();
    let msix = discover_msix_packages();
    let find_ag = |label: &str| -> (bool, Option<String>) {
        match installs
            .iter()
            .find(|row| row.label == label)
            .and_then(|row| row.path.as_ref())
        {
            Some(path) => (true, Some(path.display().to_string())),
            None => (false, None),
        }
    };
    PaidApp::ALL
        .into_iter()
        .map(|app| {
            let (found, path_hint) = match app {
                PaidApp::AntigravityDesktop => find_ag("Antigravity 2.0"),
                PaidApp::AntigravityIde => match installs
                    .iter()
                    .find(|row| row.label == "Antigravity IDE")
                    .and_then(|row| row.path.as_ref())
                    .filter(|path| ide(path).is_some())
                {
                    Some(path) => (true, Some(path.display().to_string())),
                    None => (false, None),
                },
                PaidApp::AntigravityCli => find_ag("Antigravity CLI"),
                PaidApp::AntigravityVscode => find_ag("Antigravity для VS Code"),
                PaidApp::ClaudeCode => match find_claude_code() {
                    Some(path) => (true, Some(path.display().to_string())),
                    None => (false, None),
                },
                PaidApp::ClaudeDesktop => (msix.claude.is_some(), msix.claude.clone()),
                PaidApp::CodexCli => match codex_cli_path().filter(|path| path.is_file()) {
                    Some(path) => (true, Some(path.display().to_string())),
                    None => (false, None),
                },
                PaidApp::ChatGptDesktop => match msix.chatgpt.clone() {
                    Some(pkg) => (true, Some(pkg)),
                    None => (false, None),
                },
            };
            PaidAppStatus {
                app,
                found,
                path_hint,
                active: active.contains(&app),
            }
        })
        .collect()
}

fn find_claude_code() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(home) = std::env::var_os("USERPROFILE") {
        let h = PathBuf::from(home);
        candidates.push(h.join(r".local\bin\claude.exe"));
        candidates.push(h.join(r".claude\local\claude.exe"));
    }
    if let Some(appdata) = std::env::var_os("APPDATA") {
        candidates.push(PathBuf::from(appdata).join(r"npm\claude.cmd"));
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let l = PathBuf::from(local);
        candidates.push(l.join(r"Programs\claude\claude.exe"));
        candidates.push(l.join(r"Microsoft\WinGet\Links\claude.exe"));
    }
    find_executable(&candidates, &["claude.exe", "claude.cmd"])
}

fn claude_msix_exe() -> Result<PathBuf, String> {
    let script = format!(
        r#"
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$pkg=Get-AppxPackage -Name Claude | Where-Object {{ $_.PackageFamilyName -eq {} -and $_.InstallLocation }} | Select-Object -First 1
if ($pkg) {{
    $entry=(Get-AppxPackageManifest -Package $pkg).Package.Applications.Application |
        Where-Object {{ $_.Id -eq 'Claude' -and $_.EntryPoint -eq 'Windows.FullTrustApplication' }} |
        Select-Object -First 1
    if ($entry -and $entry.Executable) {{ Join-Path $pkg.InstallLocation $entry.Executable }}
}}
"#,
        quote(CLAUDE_FAMILY)
    );
    let output = crate::utils::powershell_within(&script, Duration::from_secs(8))
        .ok_or("Windows не ответила при поиске Claude Desktop")?;
    if !output.status.success() {
        return Err(clean_ps_error(&String::from_utf8_lossy(&output.stderr), output.status));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let exe = PathBuf::from(stdout.trim());
    if !exe.is_absolute() || !exe.is_file() {
        return Err("Не найден установленный MSIX-пакет Claude Desktop".into());
    }
    Ok(exe)
}

const CLAUDE_MACHINE_POLICY: &str = r"
$key = $machine.OpenSubKey('SOFTWARE\Policies\Claude')
$managed = $key -and ($key.ValueCount -gt 0)
";

const CLAUDE_POLICY_ROOTS: &str = "
$machine = [Microsoft.Win32.Registry]::LocalMachine
$user = [Microsoft.Win32.Registry]::CurrentUser
";

const CLAUDE_PROXY_POLICY: &str = r#"
$path = 'SOFTWARE\Policies\Claude'
$statePath = 'SOFTWARE\AI Unlocker\Claude Proxy'
$name = 'egressProxyUrl'
$pac = 'egressProxyPacUrl'
$mark = 'ManagedUrl'
if ($mode -eq 'remove') {
    foreach ($hive in @($user, $machine)) {
        $state = $hive.OpenSubKey($statePath)
        if (!$state -or !$state.GetValue($mark)) { continue }
        $owned = $state.GetValue($mark)
        $policy = $hive.OpenSubKey($path)
        if ($policy -and $policy.GetValue($name) -ceq $owned) {
            $hive.OpenSubKey($path, $true).DeleteValue($name)
        }
        $hive.OpenSubKey($statePath, $true).DeleteValue($mark)
    }
    return
}
$hive = if ($managed) { $machine } else { $user }
$policy = $hive.OpenSubKey($path)
$state = $hive.OpenSubKey($statePath)
$hasUrl = $policy -and ($policy.GetValueNames() -contains $name)
$current = if ($hasUrl) { $policy.GetValue($name) }
$owned = if ($state) { $state.GetValue($mark) }
if ($policy -and ($policy.GetValueNames() -contains $pac)) {
    throw 'Claude Desktop already has a managed PAC policy.'
}
if ($hasUrl -and (!$owned -or $current -cne $owned)) {
    throw 'Claude Desktop already has a managed proxy policy.'
}
if ($mode -eq 'check') { return }
$policy = $hive.CreateSubKey($path)
$state = $hive.CreateSubKey($statePath)
$policy.SetValue($name, $url, [Microsoft.Win32.RegistryValueKind]::String)
try {
    $state.SetValue($mark, $url, [Microsoft.Win32.RegistryValueKind]::String)
    if ($policy.GetValue($name) -cne $url -or $state.GetValue($mark) -cne $url) {
        throw 'Claude Desktop PAID policy failed verification.'
    }
} catch {
    if ($policy.GetValue($name) -ceq $url) {
        if ($hasUrl) { $policy.SetValue($name, $current, [Microsoft.Win32.RegistryValueKind]::String) }
        else { $policy.DeleteValue($name) }
    }
    if ($state.GetValue($mark) -ceq $url) {
        if ($owned) { $state.SetValue($mark, $owned, [Microsoft.Win32.RegistryValueKind]::String) }
        else { $state.DeleteValue($mark) }
    }
    throw
}
"#;

fn claude_proxy_policy(mode: &str, url: &str) -> Result<(), String> {
    ps(&format!(
        "$mode={}; $url={};\n{CLAUDE_POLICY_ROOTS}\n{CLAUDE_MACHINE_POLICY}\n{CLAUDE_PROXY_POLICY}",
        quote(mode), quote(url)
    ))
}

fn verify_paid_listener(port: u16) -> Result<(), String> {
    let relay = crate::background::installed_exe();
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let known = crate::portcheck::listener_path(address)
        .is_some_and(|actual| actual.as_os_str().eq_ignore_ascii_case(relay.as_os_str()));
    if !known {
        return Err("Windows не подтвердила, что порт PAID занят службой AI Unlocker.".into());
    }
    Ok(())
}

pub fn codex_cli_path() -> Option<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")?;
    Some(PathBuf::from(local).join(r"Programs\OpenAI\Codex\bin\codex.exe"))
}

fn configure_codex_cli(enabled: bool) -> Result<(), String> {
    let mode = if enabled { "set" } else { "remove" };
    ps(&format!(
        "& {{\n{}\n}} -Mode {}",
        include_str!("paid_codex.ps1").trim_start_matches('\u{feff}'),
        quote(mode)
    ))
}

fn find_executable(candidates: &[PathBuf], names: &[&str]) -> Option<PathBuf> {
    if let Some(found) = candidates.iter().find(|p| p.is_file()) {
        return Some(found.clone());
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for name in names {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[derive(Default)]
struct MsixPackages {
    claude: Option<String>,
    chatgpt: Option<String>,
}

fn discover_msix_packages() -> MsixPackages {
    let mut cmd = std::process::Command::new("reg");
    cmd.args([
        "query",
        r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages",
    ]);
    let Some(output) = crate::utils::bounded_output(
        crate::utils::no_window(&mut cmd),
        Duration::from_secs(5),
    ) else {
        return MsixPackages::default();
    };
    if !output.status.success() {
        return MsixPackages::default();
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut out = MsixPackages::default();
    for line in stdout.lines() {
        let Some(pkg) = line.trim().rsplit('\\').next() else {
            continue;
        };
        if out.claude.is_none() && pkg.starts_with("Claude_") && pkg.ends_with("__pzs8sxrjxfjjc") {
            out.claude = Some(pkg.to_string());
        } else if out.chatgpt.is_none()
            && (pkg.starts_with("OpenAI.Codex_") || pkg.starts_with("OpenAI.ChatGPT"))
        {
            out.chatgpt = Some(pkg.to_string());
        }
    }
    out
}

fn build_running_script(apps: &[PaidApp], ide_exes: &[PathBuf]) -> String {
    let mut names: Vec<&'static str> = Vec::new();
    let mut push_name = |name: &'static str| {
        if !names.contains(&name) {
            names.push(name);
        }
    };
    for &app in apps {
        match app {
            PaidApp::AntigravityDesktop => push_name("Antigravity.exe"),
            PaidApp::AntigravityIde => {
                push_name("Antigravity IDE.exe");
                push_name("Antigravity.exe");
            }
            PaidApp::AntigravityCli | PaidApp::AntigravityVscode => push_name("agy.exe"),
            PaidApp::ClaudeCode | PaidApp::ClaudeDesktop => push_name("claude.exe"),
            PaidApp::CodexCli => push_name("codex.exe"),
            PaidApp::ChatGptDesktop => {
                push_name("ChatGPT.exe");
                push_name("codex.exe");
            }
        }
    }
    let filter = names
        .iter()
        .map(|name| format!("Name={}", quote(name)))
        .collect::<Vec<_>>()
        .join(" OR ");
    let ide_paths = ide_exes
        .iter()
        .map(|path| quote(&path.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(",");
    let mut checks = Vec::new();
    for &app in apps {
        let id = quote(app.id());
        let check = match app {
            PaidApp::AntigravityDesktop => {
                format!(
                    "if ($procs | Where-Object {{ $_.Name -ieq 'Antigravity.exe' -and ($idePaths -notcontains $_.ExecutablePath) }}) {{ Write-Output {id} }}"
                )
            }
            PaidApp::AntigravityIde => {
                format!(
                    "if ($procs | Where-Object {{ ($idePaths -contains $_.ExecutablePath) -or ($_.Name -ieq 'Antigravity IDE.exe') }}) {{ Write-Output {id} }}"
                )
            }
            PaidApp::AntigravityCli => {
                format!(
                    "if ($procs | Where-Object {{ $_.Name -ieq 'agy.exe' -and ($_.ExecutablePath -notlike '*\\.gemini\\bin\\*') }}) {{ Write-Output {id} }}"
                )
            }
            PaidApp::AntigravityVscode => {
                format!(
                    "if ($procs | Where-Object {{ $_.Name -ieq 'agy.exe' -and ($_.ExecutablePath -like '*\\.gemini\\bin\\*') }}) {{ Write-Output {id} }}"
                )
            }
            PaidApp::ClaudeCode => {
                format!(
                    "if ($procs | Where-Object {{ $_.Name -ieq 'claude.exe' -and $_.ExecutablePath -and ($_.ExecutablePath -notlike '*\\WindowsApps\\*') -and ($_.ExecutablePath -notlike '*\\AnthropicClaude\\*') }}) {{ Write-Output {id} }}"
                )
            }
            PaidApp::ClaudeDesktop => {
                format!(
                    "if ($procs | Where-Object {{ $_.Name -ieq 'Claude.exe' -and (-not $_.ExecutablePath -or $_.ExecutablePath -like '*\\WindowsApps\\*' -or $_.ExecutablePath -like '*\\AnthropicClaude\\*') }}) {{ Write-Output {id} }}"
                )
            }
            PaidApp::CodexCli => {
                format!(
                    "if ($procs | Where-Object {{ $_.Name -ieq 'codex.exe' -and ($_.ExecutablePath -notlike '*\\WindowsApps\\*') }}) {{ Write-Output {id} }}"
                )
            }
            PaidApp::ChatGptDesktop => {
                format!(
                    "if ($procs | Where-Object {{ $_.Name -ieq 'ChatGPT.exe' -or ($_.Name -ieq 'codex.exe' -and $_.ExecutablePath -like '*\\WindowsApps\\*') }}) {{ Write-Output {id} }}"
                )
            }
        };
        checks.push(check);
    }
    format!(
        "$ErrorActionPreference='Stop'; $idePaths=@({ide_paths}); $procs=@(Get-CimInstance Win32_Process -Filter {filter}); {checks}",
        filter = quote(&filter),
        checks = checks.join("; "),
    )
}

pub fn running_for(apps: &[PaidApp]) -> Result<Vec<&'static str>, String> {
    if apps.is_empty() {
        return Ok(Vec::new());
    }
    let ide_exes: Vec<PathBuf> = if apps.contains(&PaidApp::AntigravityIde) {
        installations().into_iter().map(|ide| ide.exe).collect()
    } else {
        Vec::new()
    };
    let script = build_running_script(apps, &ide_exes);
    let output =
        crate::utils::powershell(&script).ok_or("Windows не ответила при проверке открытых IDE")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        crate::dns_forwarder::log_proxy(&format!(
            "running check failed ({}): {}",
            output.status, stderr
        ));
        return Err("Не удалось проверить, какие IDE открыты".into());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut labels = Vec::new();
    for line in stdout.lines() {
        if let Some(app) = PaidApp::from_id(line) {
            let label = app.label();
            if !labels.contains(&label) {
                labels.push(label);
            }
        }
    }
    Ok(labels)
}

fn require_admin() -> Result<(), String> {
    if !crate::utils::is_admin() {
        Err("Перезапустите AI Unlocker от администратора, чтобы применить правила Windows".into())
    } else {
        Ok(())
    }
}

fn remove_firewall_rules() -> Result<(), String> {
    ps(&format!(
        r#"
$rules=@(Get-NetFirewallRule -PolicyStore PersistentStore -Group {} -ErrorAction SilentlyContinue)
foreach ($rule in $rules) {{ $rule | Remove-NetFirewallRule }}
"#,
        quote(GROUP)
    ))
}

fn claude_settings_path() -> Option<PathBuf> {
    let home = std::env::var_os("USERPROFILE")?;
    Some(PathBuf::from(home).join(r".claude\settings.json"))
}

fn claude_backup_path() -> PathBuf {
    crate::dns_forwarder::log_dir().join("paid-claude-backup.json")
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct ClaudeProxyBackup {
    http_proxy: Option<String>,
    https_proxy: Option<String>,
    no_proxy: Option<String>,
}

fn enable_claude_code(proxy_url: &str) -> Result<(), String> {
    let Some(path) = claude_settings_path() else {
        return Err("Не найден профиль пользователя для Claude Code".into());
    };
    enable_claude_code_at(&path, &claude_backup_path(), proxy_url)
}

fn enable_claude_code_at(
    settings_path: &Path,
    backup_path: &Path,
    proxy_url: &str,
) -> Result<(), String> {
    let mut root: serde_json::Value = match fs::read_to_string(settings_path) {
        Ok(text) if !text.trim().is_empty() => serde_json::from_str(&text)
            .map_err(|error| format!("Не удалось прочитать {}: {error}", settings_path.display()))?,
        Ok(_) => serde_json::json!({}),
        Err(err) if err.kind() == io::ErrorKind::NotFound => serde_json::json!({}),
        Err(err) => return Err(format!("{}: {err}", settings_path.display())),
    };
    let root_obj = root
        .as_object_mut()
        .ok_or_else(|| format!("{} должен содержать JSON-объект", settings_path.display()))?;
    if !root_obj.contains_key("env") {
        root_obj.insert("env".into(), serde_json::json!({}));
    }
    let env_obj = root_obj
        .get_mut("env")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| format!("Поле env в {} не является объектом", settings_path.display()))?;

    if !backup_path.exists() {
        let backup = ClaudeProxyBackup {
            http_proxy: env_obj
                .get("HTTP_PROXY")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
            https_proxy: env_obj
                .get("HTTPS_PROXY")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
            no_proxy: env_obj
                .get("NO_PROXY")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
        };
        if let Some(parent) = backup_path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let encoded = serde_json::to_string_pretty(&backup).map_err(|error| error.to_string())?;
        crate::patch_ide::write_atomic(backup_path, &encoded)
            .map_err(|error| error.to_string())?;
    }

    env_obj.insert("HTTP_PROXY".into(), serde_json::json!(proxy_url));
    env_obj.insert("HTTPS_PROXY".into(), serde_json::json!(proxy_url));
    env_obj.insert("NO_PROXY".into(), serde_json::json!("localhost,127.0.0.1,::1"));

    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let output = serde_json::to_string_pretty(&root).map_err(|error| error.to_string())?;
    crate::patch_ide::write_atomic(settings_path, &output)
        .map_err(|error| format!("{}: {error}", settings_path.display()))
}

fn disable_claude_code() -> Result<(), String> {
    let Some(path) = claude_settings_path() else {
        return Ok(());
    };
    disable_claude_code_at(&path, &claude_backup_path())
}

fn disable_claude_code_at(settings_path: &Path, backup_path: &Path) -> Result<(), String> {
    if !settings_path.exists() {
        let _ = fs::remove_file(backup_path);
        return Ok(());
    }
    let text = fs::read_to_string(settings_path)
        .map_err(|error| format!("{}: {error}", settings_path.display()))?;
    let mut root: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| format!("{}: {error}", settings_path.display()))?;
    let Some(env_obj) = root
        .as_object_mut()
        .and_then(|obj| obj.get_mut("env"))
        .and_then(serde_json::Value::as_object_mut)
    else {
        let _ = fs::remove_file(backup_path);
        return Ok(());
    };

    let mut changed = false;
    if backup_path.exists() {
        let backup_raw = fs::read_to_string(backup_path).map_err(|error| error.to_string())?;
        let backup: ClaudeProxyBackup =
            serde_json::from_str(&backup_raw).map_err(|error| error.to_string())?;
        for (key, value) in [
            ("HTTP_PROXY", backup.http_proxy),
            ("HTTPS_PROXY", backup.https_proxy),
            ("NO_PROXY", backup.no_proxy),
        ] {
            match value {
                Some(prev) => {
                    env_obj.insert(key.into(), serde_json::json!(prev));
                    changed = true;
                }
                None => {
                    if env_obj.remove(key).is_some() {
                        changed = true;
                    }
                }
            }
        }
        fs::remove_file(backup_path).map_err(|error| error.to_string())?;
    } else {
        let paid_urls = crate::proxy::all_paid_urls();
        let is_paid = |key: &str| {
            env_obj
                .get(key)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|val| paid_urls.iter().any(|u| val.eq_ignore_ascii_case(u)))
        };
        let removed_http = is_paid("HTTP_PROXY");
        let removed_https = is_paid("HTTPS_PROXY");
        if removed_http {
            env_obj.remove("HTTP_PROXY");
            changed = true;
        }
        if removed_https {
            env_obj.remove("HTTPS_PROXY");
            changed = true;
        }
        if (removed_http || removed_https)
            && env_obj.get("NO_PROXY").and_then(serde_json::Value::as_str)
                == Some("localhost,127.0.0.1,::1")
        {
            env_obj.remove("NO_PROXY");
            changed = true;
        }
    }

    if changed {
        let output = serde_json::to_string_pretty(&root).map_err(|error| error.to_string())?;
        crate::patch_ide::write_atomic(settings_path, &output)
            .map_err(|error| format!("{}: {error}", settings_path.display()))?;
    }
    Ok(())
}

fn normalize_apps(desired: &[PaidApp]) -> Vec<PaidApp> {
    PaidApp::ALL
        .into_iter()
        .filter(|app| desired.contains(app) && app.paid_implemented())
        .collect()
}

fn needs_admin_for(desired: &[PaidApp]) -> bool {
    !desired.is_empty() || crate::paid::enabled() || policy_file().is_file()
        || (crate::background::is_running() && crate::background::relay_is_outdated())
}

fn worker_error_path() -> PathBuf {
    crate::dns_forwarder::log_dir().join(format!("paid-worker-{}.err", std::process::id()))
}

fn build_elevated_worker_script(exe: &Path, args: &str) -> String {
    format!(
        "try {{ $worker = Start-Process -FilePath {} -ArgumentList {} -Verb RunAs -Wait -PassThru }} \
         catch [System.ComponentModel.Win32Exception] {{ \
             if ($_.Exception.NativeErrorCode -eq 1223) {{ [Console]::Error.WriteLine('AIU_UAC_CANCELLED'); exit 1223 }}; \
             throw \
         }} \
         catch {{ \
             if ($_.Exception.InnerException -is [System.ComponentModel.Win32Exception] -and $_.Exception.InnerException.NativeErrorCode -eq 1223) {{ [Console]::Error.WriteLine('AIU_UAC_CANCELLED'); exit 1223 }}; \
             throw \
         }}; \
         if ($worker.ExitCode -ne 0) {{ [Console]::Error.WriteLine('AIU_WORKER_EXIT:' + $worker.ExitCode); exit $worker.ExitCode }}",
        quote(&exe.to_string_lossy()),
        quote(args)
    )
}

pub fn transition_apps(desired: &[PaidApp]) -> Result<(), String> {
    let normalized = normalize_apps(desired);
    if crate::utils::is_admin() || !needs_admin_for(&normalized) {
        return apply_apps(&normalized);
    }
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let arg = if normalized.is_empty() {
        "none".to_string()
    } else {
        normalized
            .iter()
            .map(|app| app.id())
            .collect::<Vec<_>>()
            .join(",")
    };
    let err_path = worker_error_path();
    if let Some(parent) = err_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::remove_file(&err_path);
    let err_arg = err_path.to_string_lossy().replace('"', "");
    let args = format!("--set-paid-apps {arg} \"{err_arg}\"");
    let script = build_elevated_worker_script(&exe, &args);
    let output = crate::utils::powershell_within(
        &format!("$ErrorActionPreference='Stop'; {script}"),
        Duration::from_secs(75),
    );
    let worker_err = fs::read_to_string(&err_path).ok();
    let _ = fs::remove_file(&err_path);
    let output = output.ok_or("Windows не ответила при настройке платного режима")?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if output.status.code() == Some(1223) || stderr.contains("AIU_UAC_CANCELLED") {
        return Err("Нужны права администратора — запрос UAC отменён.".into());
    }
    if let Some(msg) = worker_err.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        return Err(msg);
    }
    crate::dns_forwarder::log_proxy(&format!(
        "paid powershell failed ({}): {}",
        output.status, stderr
    ));
    Err(clean_ps_error(&stderr, output.status))
}

fn policy_file() -> PathBuf {
    crate::dns_forwarder::log_dir().join("paid-wfp-state.json")
}

fn lock_transition() -> Result<fs::File, String> {
    let dir = crate::dns_forwarder::log_dir();
    fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(dir.join("paid-transition.lock"))
        .map_err(|error| error.to_string())?;
    file.try_lock().map_err(|error| match error {
        fs::TryLockError::WouldBlock => "Дождитесь окончания настройки PAID.".into(),
        fs::TryLockError::Error(error) => error.to_string(),
    })?;
    Ok(file)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PolicyState {
    port: u16,
    apps: Vec<String>,
    ide_port: Option<u16>,
}

impl PolicyState {
    fn current() -> Option<Self> {
        serde_json::from_str(&fs::read_to_string(policy_file()).ok()?).ok()
    }

    fn covers(&self, apps: &[PaidApp]) -> bool {
        self.port != 0
            && self.apps.len() == apps.len()
            && apps.iter().all(|app| self.apps.iter().any(|id| id == app.id()))
    }
}

pub fn protected_paid_port() -> Option<u16> {
    PolicyState::current()
        .map(|state| state.port)
        .filter(|port| *port != 0)
}

pub fn kill_switch_configured(apps: &[PaidApp]) -> bool {
    PolicyState::current().is_some_and(|state| {
        state.covers(apps) && state.port == crate::proxy::paid_port()
    })
}

struct StrictTargets {
    programs: Vec<PathBuf>,
    packages: Vec<&'static str>,
    ides: Vec<Ide>,
    ide_programs: Vec<PathBuf>,
    hub: Option<crate::paid_ide_hub::Hub>,
}

impl StrictTargets {
    fn find(apps: &[PaidApp]) -> Result<Self, String> {
        let mut targets = Self {
            programs: Vec::new(),
            packages: Vec::new(),
            ides: Vec::new(),
            ide_programs: Vec::new(),
            hub: None,
        };

        if apps.contains(&PaidApp::AntigravityIde) {
            targets.ides = installations();
            if targets.ides.is_empty() {
                return Err("Поддерживаемая Antigravity IDE не найдена".into());
            }
            let settings = crate::paid_ide_hub::settings_path()?;
            let mut listeners = Vec::new();
            for ide in &targets.ides {
                let root = ide.exe.parent().ok_or("Не найден каталог Antigravity IDE")?;
                if crate::endpoint::ide_settings_path(root).as_deref() != Some(settings.as_path()) {
                    return Err("Защита PAID поддерживает стандартный профиль Antigravity IDE".into());
                }
                collect_programs(root, &mut targets.ide_programs).map_err(|error| error.to_string())?;
                listeners.push(ide.exe.clone());
            }
            let home = std::env::var_os("USERPROFILE").ok_or("Не найден профиль Windows")?;
            let agy = PathBuf::from(home).join(r".gemini\bin\agy.exe");
            if !agy.is_file() {
                return Err("Antigravity IDE ещё не установила backend agy.exe. Откройте IDE один раз и закройте её.".into());
            }
            listeners.push(agy.clone());
            targets.ide_programs.push(agy);
            targets.programs.extend(targets.ide_programs.iter().cloned());
            targets.hub = Some(crate::paid_ide_hub::Hub::find(settings, listeners)?);
        }

        if apps.iter().any(|app| matches!(app, PaidApp::AntigravityDesktop | PaidApp::AntigravityCli | PaidApp::AntigravityVscode)) {
            let mut installs = crate::discover_installs_fast();
            installs.extend(crate::settings::manual_paths());
            for (app, label) in [
                (PaidApp::AntigravityDesktop, "Antigravity 2.0"),
                (PaidApp::AntigravityCli, "Antigravity CLI"),
                (PaidApp::AntigravityVscode, "Antigravity для VS Code"),
            ] {
                if !apps.contains(&app) {
                    continue;
                }
                let programs: Vec<_> = installs.iter()
                    .filter(|path| crate::install_label(path) == label)
                    .flat_map(|path| crate::patch_binary::binary_targets(path))
                    .filter(|path| path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("exe")))
                    .collect();
                if programs.is_empty() {
                    return Err(format!("Не найдены сетевые компоненты {label} для защиты PAID"));
                }
                targets.programs.extend(programs);
            }
        }

        if apps.contains(&PaidApp::ClaudeDesktop) {
            let exe = claude_msix_exe()?;
            let root = exe.parent().ok_or("Не найден каталог Claude Desktop")?;
            collect_programs(root, &mut targets.programs).map_err(|error| error.to_string())?;
            targets.packages.push(CLAUDE_FAMILY);
        }
        if apps.contains(&PaidApp::ClaudeCode) {
            let exe = find_claude_code()
                .filter(|path| path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("exe")))
                .ok_or("Для защиты PAID требуется отдельный нативный claude.exe")?;
            targets.programs.push(exe);
        }
        if apps.contains(&PaidApp::CodexCli) {
            let exe = codex_cli_path().filter(|path| path.is_file())
                .ok_or("Для PAID нужна нативная установка Codex CLI для Windows.")?;
            targets.programs.push(exe);
        }
        targets.programs.sort_unstable();
        targets.programs.dedup();
        Ok(targets)
    }

    fn install(&self, apps: &[PaidApp], port: u16) -> Result<(), String> {
        verify_paid_listener(port)?;
        let ipc = if let Some(hub) = &self.hub {
            hub.verify(port)?;
            Some(crate::paid_firewall::IdeIpc {
                port: hub.port,
                programs: &self.ide_programs,
                listeners: &hub.listeners,
            })
        } else {
            None
        };
        let state = PolicyState {
            port,
            apps: apps.iter().map(|app| app.id().to_string()).collect(),
            ide_port: self.hub.as_ref().map(|hub| hub.port),
        };
        let state = serde_json::to_string(&state).map_err(|error| error.to_string())?;
        let marker = policy_file();
        let previous = match fs::read_to_string(&marker) {
            Ok(text) => Some(text),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.to_string()),
        };
        crate::patch_ide::write_atomic(&marker, "pending").map_err(|error| error.to_string())?;
        if let Err(error) = crate::paid_firewall::install(
            &self.programs, &self.packages, &crate::background::installed_exe(), port, ipc,
        ) {
            let restore = match previous {
                Some(text) => crate::patch_ide::write_atomic(&marker, &text)
                    .map_err(|error| error.to_string()),
                None => remove_file_if_exists(&marker),
            };
            return match restore {
                Ok(()) => Err(error),
                Err(restore) => Err(format!("{error}. Восстановление состояния правил: {restore}")),
            };
        }
        verify_paid_listener(port)?;
        crate::patch_ide::write_atomic(&marker, &state).map_err(|error| error.to_string())
    }
}

fn clear_kill_switch() -> Result<(), String> {
    if crate::utils::is_admin() || policy_file().is_file() {
        crate::paid_firewall::remove()?;
        remove_file_if_exists(&policy_file())?;
    }
    Ok(())
}

fn write_apps(apps: &[PaidApp]) -> Result<(), String> {
    let marker = crate::paid::marker();
    if apps.is_empty() {
        return remove_file_if_exists(&marker);
    }
    let encoded = crate::paid::format_marker(apps)?;
    crate::patch_ide::write_atomic(&marker, &encoded).map_err(|error| error.to_string())
}

fn antigravity_proxy_scope(apps: &[PaidApp]) -> (bool, bool) {
    (
        apps.iter().any(|app| app.is_antigravity()),
        apps.iter().any(|app| matches!(
            app, PaidApp::AntigravityDesktop | PaidApp::AntigravityCli | PaidApp::AntigravityVscode
        )),
    )
}

fn configure_app_proxies(
    previous: &[PaidApp], apps: &[PaidApp], paid_url: &str, refresh: bool,
) -> Result<(), String> {
    let (ag, ag_env) = antigravity_proxy_scope(apps);
    if antigravity_proxy_scope(previous) != (ag, ag_env) || (refresh && ag) {
        if ag_env {
            crate::endpoint::ensure_proxy_env(paid_url)?;
        } else if ag {
            crate::endpoint::remove_proxy(&crate::proxy::proxy_url(), "")?;
        } else {
            crate::endpoint::remove_paid_proxy_env()?;
        }
    }
    let claude_code = apps.contains(&PaidApp::ClaudeCode);
    if previous.contains(&PaidApp::ClaudeCode) != claude_code || (refresh && claude_code) {
        if claude_code {
            enable_claude_code(paid_url)?;
        } else {
            disable_claude_code()?;
        }
    }
    let claude_desktop = apps.contains(&PaidApp::ClaudeDesktop);
    if previous.contains(&PaidApp::ClaudeDesktop) != claude_desktop || (refresh && claude_desktop) {
        claude_proxy_policy(if claude_desktop { "set" } else { "remove" }, paid_url)?;
    }
    let codex_cli = apps.contains(&PaidApp::CodexCli);
    if previous.contains(&PaidApp::CodexCli) != codex_cli || (refresh && codex_cli) {
        configure_codex_cli(codex_cli)?;
    }
    Ok(())
}

pub fn apply_apps(desired: &[PaidApp]) -> Result<(), String> {
    let desired = normalize_apps(desired);
    if needs_admin_for(&desired) {
        require_admin()?;
    }
    let _transition = lock_transition()?;
    let previous = crate::paid::active_apps();
    if !previous.is_empty() {
        require_admin()?;
    }
    let removes = previous.iter().any(|app| !desired.contains(app));
    let adds = desired.iter().any(|app| !previous.contains(app));
    if adds {
        let license = crate::paid::Device::load()?.check()?;
        if !license.eligible {
            return Err(license
                .reason
                .and_then(crate::paid::LicenseReason::user_message)
                .unwrap_or("Для активации нужна выданная лицензия")
                .into());
        }
    }
    let policy = PolicyState::current();
    let refresh = policy.as_ref().is_none_or(|state| {
        !state.covers(&previous) || state.port != crate::proxy::paid_port()
    });
    let reapply = refresh || (!previous.is_empty() && desired == previous);
    let had_claude_desktop = previous.contains(&PaidApp::ClaudeDesktop);
    let want_claude_desktop = desired.contains(&PaidApp::ClaudeDesktop);
    if want_claude_desktop && (!had_claude_desktop || reapply) {
        claude_proxy_policy("check", "")?;
    } else if had_claude_desktop && !want_claude_desktop
        && !running_for(&[PaidApp::ClaudeDesktop])?.is_empty()
    {
        return Err("Выйдите из Claude Desktop через значок в трее перед отключением PAID.".into());
    }

    let next = (!desired.is_empty()).then(|| StrictTargets::find(&desired)).transpose()?;
    let hold = if adds && removes {
        let mut apps = previous.clone();
        apps.extend(desired.iter().copied());
        let apps = normalize_apps(&apps);
        Some((StrictTargets::find(&apps)?, apps))
    } else {
        None
    };

    let had_ide = previous.contains(&PaidApp::AntigravityIde);
    if desired.contains(&PaidApp::AntigravityIde)
        && !had_ide
        && !running_for(&[PaidApp::AntigravityIde])?.is_empty()
    {
        return Err("Закройте Antigravity IDE перед настройкой защиты PAID.".into());
    }

    let was_ag = previous.iter().any(|app| app.is_antigravity());
    let want_ag = desired.iter().any(|app| app.is_antigravity());
    if !desired.is_empty()
        && (crate::background::relay_is_outdated()
            || (!was_ag && want_ag)
            || verify_paid_listener(crate::proxy::paid_port()).is_err()
                && !crate::background::is_running())
    {
        crate::background::enable()?;
    }
    let port = if next.is_some() {
        crate::proxy::wait_for_our_paid_listener(Duration::from_secs(20))
            .ok_or("Платный локальный прокси не запустился")?
    } else {
        crate::proxy::paid_port()
    };
    if let Some((scope, apps)) = &hold {
        scope.install(apps, port)?;
    } else if let Some(scope) = next.as_ref().filter(|_| !removes) {
        scope.install(&desired, port)?;
    }
    let paid_url = crate::proxy::url_at(port);

    let result = (|| {
        if let Some(targets) = &next {
            if let Some(hub) = targets.hub.as_ref().filter(|hub| {
                !had_ide || reapply || !hub.configured
                    || policy.as_ref().and_then(|state| state.ide_port) != Some(hub.port)
                    || !crate::paid::ide_marker().is_file()
            }) {
                hub.configure()?;
                for ide in &targets.ides {
                    install_bootstrap(&ide.entry)?;
                }
                crate::patch_ide::write_atomic(&crate::paid::ide_marker(), IDE_CONFIGURED)
                    .map_err(|error| error.to_string())?;
            }
        }
        if want_ag && (!was_ag || reapply) {
            let mut settings = crate::settings::Settings::load();
            settings.dns = false;
            settings.local_proxy = false;
            settings.group_proxy = false;
            if !settings.save() {
                return Err("Не удалось сохранить настройки Antigravity для PAID".into());
            }
            crate::dns::remove_dns_nrpt_checked()?;
            crate::dns::invalidate_cache();
            crate::dns::flush_client_cache();
        }
        configure_app_proxies(&previous, &desired, &paid_url, reapply)?;
        if had_ide && !desired.contains(&PaidApp::AntigravityIde) {
            crate::paid_ide_hub::restore()?;
            remove_file_if_exists(&crate::paid::ide_marker())?;
        }
        write_apps(&desired)
    })();
    if let Err(error) = result {
        // Keep the kernel blocks until the previous proxy settings are restored.
        let restore = configure_app_proxies(&desired, &previous, &paid_url, reapply)
            .and_then(|()| {
                if previous.is_empty() && !desired.is_empty() {
                    if desired.contains(&PaidApp::AntigravityIde) {
                        crate::paid_ide_hub::restore()?;
                        remove_file_if_exists(&crate::paid::ide_marker())?;
                    }
                    clear_kill_switch()
                } else if adds {
                    StrictTargets::find(&previous)?.install(&previous, port)
                } else {
                    Ok(())
                }
            });
        return match restore {
            Ok(()) => Err(error),
            Err(restore) => Err(format!("{error}. Восстановление прокси приложений: {restore}")),
        };
    }

    if let Some(scope) = next.as_ref().filter(|_| removes) {
        scope.install(&desired, port)?;
    } else if next.is_none() {
        clear_kill_switch()?;
    }
    if reapply && (!previous.is_empty() || !desired.is_empty()) {
        remove_firewall_rules()?;
    }
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.to_string()),
    }
}

pub fn start() -> Result<(), String> {
    require_admin()?;
    let installs = crate::ops::collect_install_rows_fast();
    let found: Vec<PaidApp> = discover_apps(&installs)
        .into_iter()
        .filter(|row| row.found && row.app.paid_implemented())
        .map(|row| row.app)
        .collect();
    if found.is_empty() {
        return Err("Поддерживаемые приложения для PAID не найдены".into());
    }
    apply_apps(&found)
}

pub fn disable() -> Result<(), String> {
    apply_apps(&[])
}

pub fn clean() -> Result<(), String> {
    let _transition = lock_transition()?;
    if crate::paid::is_app_active(PaidApp::CodexCli) {
        configure_codex_cli(false)?;
    }
    claude_proxy_policy("remove", "")?;
    crate::paid_ide_hub::restore()?;
    clear_kill_switch()?;
    if crate::utils::is_admin() {
        remove_firewall_rules()?;
    }
    remove_file_if_exists(&crate::paid::ide_marker())?;
    remove_file_if_exists(&crate::paid::marker())?;
    disable_claude_code()?;
    let _ = crate::endpoint::remove_paid_proxy_env()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_profiles_scope_proxy_to_the_command_and_restore_existing_bytes() {
        let script = include_str!("paid_codex.ps1").trim_start_matches('\u{feff}');
        ps(&format!(r##"
$tempDir = [IO.Path]::GetTempPath()
$root = Join-Path $tempDir ('aiu-codex-profile-' + [Guid]::NewGuid().ToString('N'))
$profileDir = Join-Path $root 'WindowsPowerShell'
$file = Join-Path $profileDir 'profile.ps1'
[void][IO.Directory]::CreateDirectory($profileDir)
$original = "# Existing profile`n"
[IO.File]::WriteAllText($file, $original, [Text.Encoding]::Unicode)
$originalBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($file))
function Configure([string]$mode) {{
    & {{
        {script}
    }} -Mode $mode -Documents $root
}}
try {{
    Configure 'set'
    $installed = [Convert]::ToBase64String([IO.File]::ReadAllBytes($file))
    Configure 'set'
    if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($file)) -cne $installed) {{ throw 'Hook is not idempotent.' }}
    $env:LOCALAPPDATA = $root
    $exeDir = Join-Path $root 'Programs\OpenAI\Codex\bin'
    [void][IO.Directory]::CreateDirectory($exeDir)
    Copy-Item -LiteralPath "$env:SystemRoot\System32\cmd.exe" -Destination (Join-Path $exeDir 'codex.exe')
    $env:Path = "$exeDir;$env:Path"
    $env:HTTPS_PROXY = 'http://original.invalid:80'
    $state = Join-Path $root 'AGUnlocker'
    [void][IO.Directory]::CreateDirectory($state)
    $selection = Join-Path $state 'paid-proxy-enabled'
    [IO.File]::WriteAllText($selection, '{{"version":2,"apps":["codex-cli"]}}')
    [IO.File]::WriteAllText((Join-Path $state 'paid-wfp-state.json'), '{{"port":53130,"apps":["codex-cli"]}}')
    . $file
    $routed = (codex /D /C 'echo %HTTPS_PROXY%').Trim()
    if ($routed -ne 'http://127.0.0.1:53130') {{ throw "Wrong proxy: $routed" }}
    if ($env:HTTPS_PROXY -ne 'http://original.invalid:80') {{ throw 'Parent environment changed.' }}
    Configure 'remove'
    if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($file)) -cne $originalBytes) {{ throw 'Profile did not round-trip.' }}
    Remove-Item -LiteralPath $selection
    $direct = (codex /D /C 'echo %HTTPS_PROXY%').Trim()
    if ($direct -ne 'http://original.invalid:80') {{ throw 'The loaded profile did not restore normal execution.' }}
}} finally {{
    $owned = Get-Item -LiteralPath $root
    if ($owned.Parent.FullName -ne $tempDir.TrimEnd('\') -or $owned.Name -notlike 'aiu-codex-profile-*') {{
        throw 'Unexpected test cleanup path.'
    }}
    Remove-Item -LiteralPath $owned.FullName -Recurse -Force
}}
"##)).unwrap();
    }

    #[test]
    fn claude_proxy_policy_respects_precedence_and_ownership() {
        ps(&format!(
            r#"
$parent = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software', $true)
$fixture = 'AIUnlockerClaudeProxyTest-' + [Guid]::NewGuid().ToString('N')
$base = $parent.CreateSubKey($fixture)
try {{
    $user = $base.CreateSubKey('User')
    $machine = $base.CreateSubKey('Machine')
    function Apply-Policy([string]$mode, [string]$url) {{
        {CLAUDE_MACHINE_POLICY}
        {CLAUDE_PROXY_POLICY}
    }}
    $desired = 'http://127.0.0.1:53130'
    $foreign = 'http://127.0.0.1:18080'
    $path = 'SOFTWARE\Policies\Claude'
    $name = 'egressProxyUrl'
    Apply-Policy 'set' $desired
    $userPolicy = $user.OpenSubKey($path, $true)
    if ($userPolicy.GetValue($name) -ne $desired) {{ throw 'User policy missing.' }}
    Apply-Policy 'remove' ''
    if ($userPolicy.GetValue($name)) {{ throw 'User policy leaked after disable.' }}

    $existing = $machine.CreateSubKey($path)
    $existing.SetValue('disableAutoUpdates', 1)
    $existing.SetValue($name, $foreign)
    $preserved = $false
    try {{ Apply-Policy 'set' $desired }} catch {{
        if ($_.Exception.Message -notlike '*already has a managed proxy*') {{ throw }}
        $preserved = $true
    }}
    if (!$preserved -or $existing.GetValue($name) -ne $foreign) {{ throw 'Foreign policy replaced.' }}
    $existing.DeleteValue($name)
    $existing.SetValue('egressProxyPacUrl', 'http://127.0.0.1:18080/test.pac')
    $pacPreserved = $false
    try {{ Apply-Policy 'set' $desired }} catch {{
        if ($_.Exception.Message -notlike '*already has a managed PAC*') {{ throw }}
        $pacPreserved = $true
    }}
    if (!$pacPreserved) {{ throw 'PAC was ignored.' }}
    $existing.DeleteValue('egressProxyPacUrl')
    Apply-Policy 'set' $desired
    if ($existing.GetValue($name) -ne $desired -or $userPolicy.GetValue($name)) {{ throw 'Machine precedence ignored.' }}
    $existing.SetValue($name, $foreign)
    Apply-Policy 'remove' ''
    if ($existing.GetValue($name) -ne $foreign -or $existing.GetValue('disableAutoUpdates') -ne 1) {{
        throw 'Disable removed a foreign setting.'
    }}
}} finally {{
    $base.Dispose()
    $parent.DeleteSubKeyTree($fixture)
    $parent.Dispose()
}}
"#
        )).expect("isolated Claude policy fixture");
    }

    #[test]
    fn running_script_has_valid_powershell_syntax_and_no_stray_backslashes() {
        let script = build_running_script(&PaidApp::ALL, &[PathBuf::from(r"C:\Apps\Antigravity IDE\Antigravity IDE.exe")]);
        assert!(!script.contains("\\\\\n") && !script.contains(" \\ "));
        let check = format!(
            "$err=$null; [void][System.Management.Automation.Language.Parser]::ParseInput({}, [ref]$null, [ref]$err); if ($err.Count) {{ throw ($err | Out-String) }}",
            quote(&script)
        );
        let output = crate::utils::powershell(&check).expect("powershell runs");
        assert!(
            output.status.success(),
            "PowerShell parse error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn claude_code_proxy_enable_and_restore_preserves_other_settings() {
        let dir = std::env::temp_dir().join(format!("ag_claude_paid_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let settings = dir.join("settings.json");
        let backup = dir.join("backup.json");
        fs::write(
            &settings,
            r#"{
  "theme": "dark",
  "env": {
    "CUSTOM_FLAG": "keep",
    "HTTPS_PROXY": "http://127.0.0.1:8888"
  }
}"#,
        )
        .unwrap();

        enable_claude_code_at(&settings, &backup, "http://127.0.0.1:53130").unwrap();
        let enabled: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(enabled["theme"], "dark");
        assert_eq!(enabled["env"]["CUSTOM_FLAG"], "keep");
        assert_eq!(enabled["env"]["HTTP_PROXY"], "http://127.0.0.1:53130");
        assert_eq!(enabled["env"]["HTTPS_PROXY"], "http://127.0.0.1:53130");
        assert_eq!(enabled["env"]["NO_PROXY"], "localhost,127.0.0.1,::1");

        disable_claude_code_at(&settings, &backup).unwrap();
        let restored: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(restored["theme"], "dark");
        assert_eq!(restored["env"]["CUSTOM_FLAG"], "keep");
        assert!(restored["env"].get("HTTP_PROXY").is_none());
        assert_eq!(restored["env"]["HTTPS_PROXY"], "http://127.0.0.1:8888");
        assert!(restored["env"].get("NO_PROXY").is_none());
        assert!(!backup.exists());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn clean_ps_error_strips_stack_trace_and_translates_firewall_message() {
        let raw = "AI Unlocker could not change paid routing.\r\nAt line:1 char:300\r\n+ ... de -ne 0) { throw ...\r\n+                 ~~~\r\n    + CategoryInfo          : OperationStopped\r\n";
        let status = std::process::Command::new("cmd")
            .args(["/c", "exit 1"])
            .status()
            .unwrap();
        assert_eq!(
            clean_ps_error(raw, status),
            "AI Unlocker could not change paid routing."
        );
        let fw = "Enable Windows Firewall for all profiles before enabling paid routing.\r\nстрока:1 символ:1\r\n";
        assert_eq!(
            clean_ps_error(fw, status),
            "Включите брандмауэр Windows для всех профилей перед включением PAID."
        );
        assert!(clean_ps_error("", status).contains("Настройка Windows завершилась со статусом"));
    }

    #[test]
    fn elevated_worker_script_has_valid_powershell_syntax() {
        let script = build_elevated_worker_script(
            Path::new(r"C:\Apps\AI Unlocker\ag_unlocker.exe"),
            r#"--set-paid-apps antigravity-desktop "C:\Users\Test\AppData\Local\AGUnlocker\paid-worker.err""#,
        );
        let check = format!(
            "$err=$null; [void][System.Management.Automation.Language.Parser]::ParseInput({}, [ref]$null, [ref]$err); if ($err.Count) {{ throw ($err | Out-String) }}",
            quote(&script)
        );
        let output = crate::utils::powershell(&check).expect("powershell runs");
        assert!(
            output.status.success(),
            "PowerShell parse error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
