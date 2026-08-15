use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

mod asar;
mod auth;
mod canary;
mod console_style;
mod dns;
mod patch_binary;
mod patch_gemini;
mod patch_ide;
mod utils;

use asar::extract_asar;
use auth::login_screen;
use dns::{is_nrpt_applied, remove_dns_nrpt, setup_dns_nrpt, setup_dns_nrpt_with};
use patch_binary::{kill_affected_processes, patch_all_binaries, unpatch_all_binaries};
use patch_gemini::run_gemini_patcher;
use patch_ide::{is_new_desktop_architecture, patch_desktop, patch_extension_js, patch_ide};
use utils::{clear_screen, is_admin, link, mask_path, open_hint, open_url, print_results, prompt};

// Title shown at the top of the main menu.
const APP_TITLE: &str = "Antigravity Unlocker 2";
// Version is read from Cargo.toml at compile time (build_rust.py keeps
// Cargo.toml in sync). Bumping the version here also rotates the license keys,
// since keys are salted with this value in auth.rs.
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

const TELEGRAM_URL: &str = "https://t.me/nova_txt";
const DONATE_URL: &str = "https://nova-app.eu/donate";

fn clean_input_path(input: &str) -> String {
    let mut s = input.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        if s.len() >= 2 {
            s = &s[1..s.len() - 1];
        }
    }
    s = s.trim();
    s = s.trim_matches('"').trim_matches('\'').trim();
    s.to_string()
}

fn is_install_root(path: &Path) -> bool {
    if !path.exists() || !path.is_dir() {
        return false;
    }

    let path_str = path.to_string_lossy().to_lowercase();
    if path_str == "c:\\windows"
        || path_str.starts_with("c:\\windows\\")
        || path_str.contains("\\windows\\system32")
        || path_str.contains("\\windows\\syswow64")
    {
        return false;
    }

    let resources = path.join("resources");
    if resources.exists() && resources.is_dir() {
        if resources.join("app.asar").exists()
            || resources.join("app").exists()
            || resources.join("bin").exists()
        {
            return true;
        }
    }
    if path.join("agy.exe").exists() {
        return true;
    }
    if path.join("Antigravity.exe").exists()
        || path.join("Antigravity IDE.exe").exists()
        || path.join("antigravity.exe").exists()
    {
        return true;
    }
    if path.join("out").join("main.js").exists() || path.join("dist").join("main.js").exists() {
        return true;
    }
    false
}

pub fn resolve_install_root(raw: &Path) -> Option<PathBuf> {
    let mut p = raw.to_path_buf();

    if p.is_file() {
        if let Some(parent) = p.parent() {
            p = parent.to_path_buf();
        }
    }

    if !p.exists() {
        return None;
    }

    if is_install_root(&p) {
        return Some(p);
    }

    let mut current = p.clone();
    for _ in 0..4 {
        if let Some(parent) = current.parent() {
            if is_install_root(parent) {
                return Some(parent.to_path_buf());
            }
            current = parent.to_path_buf();
        } else {
            break;
        }
    }

    let subfolder_candidates = [
        "Antigravity IDE",
        "Antigravity",
        "agy",
        "Programs\\Antigravity IDE",
        "Programs\\Antigravity",
        "resources",
    ];
    for sub in subfolder_candidates {
        let candidate = p.join(sub);
        if is_install_root(&candidate) {
            return Some(candidate);
        }
    }

    None
}

fn find_all_installs() -> Vec<PathBuf> {
    let mut installs = Vec::new();
    let mut candidates = Vec::new();

    let local_appdata = env::var("LOCALAPPDATA").unwrap_or_default();
    let prog_files = env::var("PROGRAMFILES").unwrap_or_default();
    let prog_files_x86 = env::var("PROGRAMFILES(X86)").unwrap_or_default();

    let standard_paths = vec![
        PathBuf::from(&local_appdata)
            .join("Programs")
            .join("Antigravity"),
        PathBuf::from(&local_appdata)
            .join("Programs")
            .join("Antigravity IDE"),
        PathBuf::from(&prog_files).join("Antigravity"),
        PathBuf::from(&prog_files).join("Antigravity IDE"),
        PathBuf::from(&prog_files_x86).join("Antigravity"),
        PathBuf::from(&prog_files_x86).join("Antigravity IDE"),
        PathBuf::from(&local_appdata).join("Antigravity"),
        PathBuf::from(&local_appdata).join("Antigravity IDE"),
        PathBuf::from(&local_appdata).join("agy").join("bin"),
        PathBuf::from(&local_appdata).join("agy"),
    ];
    candidates.extend(standard_paths);

    #[cfg(target_os = "windows")]
    {
        let ps_cmd = r#"Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -like '*Antigravity*' -or $_.DisplayName -like '*agy*' -or $_.InstallLocation -like '*Antigravity*' } | ForEach-Object { $_.InstallLocation }"#;
        if let Ok(output) = Command::new("powershell")
            .args(["-NoProfile", "-Command", ps_cmd])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let cleaned = clean_input_path(line);
                    if !cleaned.is_empty() {
                        candidates.push(PathBuf::from(&cleaned));
                    }
                }
            }
        }
    }

    for cand in candidates {
        if let Some(resolved) = resolve_install_root(&cand) {
            if !installs.contains(&resolved) {
                installs.push(resolved);
            }
        }
    }
    installs
}

/// Puts a v2.4+ install back into its pristine shape: the extracted
/// `resources/app` from an older patch is removed and `app.asar` is restored.
/// Electron prefers `resources/app` over the archive, so the directory must be
/// gone before the archive is put back.
fn restore_pristine_asar(resources: &Path) -> Result<(), String> {
    let app_dir = resources.join("app");
    let app_asar = resources.join("app.asar");
    let asar_bak = resources.join("app.asar.bak");

    // Only touch resources/app when it demonstrably came from an archive.
    // Antigravity IDE ships resources/app as its real, unpacked layout - with
    // neither app.asar nor a backup present there is nothing to restore, and
    // deleting the directory would destroy the install.
    if !asar_bak.exists() && !app_asar.exists() {
        return Ok(());
    }

    if app_dir.exists() {
        fs::remove_dir_all(&app_dir)
            .map_err(|e| format!("не удалось удалить resources\\app: {}", e))?;
    }
    if asar_bak.exists() && !app_asar.exists() {
        fs::rename(&asar_bak, &app_asar)
            .map_err(|e| format!("не удалось восстановить app.asar: {}", e))?;
    }
    Ok(())
}

fn process_install(install: &Path) -> Result<String, String> {
    // Patch all relevant binaries (Language Server / CLI).
    let bin_summary = patch_all_binaries(install);

    let resources = install.join("resources");
    let app_dir = resources.join("app");
    let app_asar = resources.join("app.asar");

    if app_asar.exists() {
        // Peek at dist/main.js straight out of the archive. On v2.4+ the shell
        // carries no auth code, so nothing is unpacked and the install stays
        // byte-identical to a fresh one.
        let is_new_arch = asar::read_asar_entry(&app_asar, "dist/main.js")
            .and_then(|b| String::from_utf8(b).ok())
            .map_or(false, |src| is_new_desktop_architecture(&src));

        if is_new_arch {
            // Clean up leftovers from a patch applied before v2.4.
            restore_pristine_asar(&resources)?;
            println!("  [INFO] v2.4+ архитектура — JS-патч не требуется (auth в Language Server)");
            // The Language Server is the only thing being patched here, so if
            // it did not take there is nothing to report as success.
            if bin_summary.ok == 0 {
                return Err(binary_failure_message(&bin_summary));
            }
            return Ok("Antigravity Desktop".to_string());
        }

        // Older layout: unpack so the JS can be patched.
        if app_dir.exists() {
            let _ = fs::remove_dir_all(&app_dir);
        }
        if !extract_asar(&app_asar, &app_dir) {
            return Err("Ошибка получения доступа к приложению".to_string());
        }
    }

    let ide_js = app_dir.join("out").join("main.js");
    let desktop_js = app_dir.join("dist").join("main.js");

    if ide_js.exists() {
        patch_ide(install, &ide_js)?;
        if let Err(e) = patch_extension_js(install) {
            println!("{} {}", "[WARN] Патч extension.js пропущен:", e);
        }
        return Ok("Antigravity IDE".to_string());
    } else if desktop_js.exists() {
        let js_patched = patch_desktop(install, &desktop_js)?;
        if !js_patched {
            // v2.4+ unpacked by an older build of this tool: undo the unpack.
            restore_pristine_asar(&resources)?;
        }
        return Ok("Antigravity Desktop".to_string());
    } else if install.join("agy.exe").exists() {
        if bin_summary.ok == 0 {
            return Err(binary_failure_message(&bin_summary));
        }
        return Ok("Antigravity CLI".to_string());
    }

    Err("Компоненты приложения не найдены".to_string())
}

fn binary_failure_message(summary: &patch_binary::BinarySummary) -> String {
    if summary.total() == 0 {
        "Бинарник Language Server / CLI не найден в этой установке".to_string()
    } else {
        "Сигнатура в Language Server не найдена — вероятно, вышла новая версия Antigravity"
            .to_string()
    }
}

fn is_gemini_cli_installed() -> bool {
    if let Ok(appdata) = env::var("APPDATA") {
        let path = PathBuf::from(appdata)
            .join("npm")
            .join("node_modules")
            .join("@google")
            .join("gemini-cli");
        path.exists() && path.is_dir()
    } else {
        false
    }
}

fn handle_restore_dns() {
    print!("Удаление NRPT-правил DNS... ");
    io::stdout().flush().ok();
    remove_dns_nrpt();
    println!("готово.");

    println!("{}", "Готово!");
    thread::sleep(Duration::from_secs(2));
}

/// Full revert: undoes the binary patch, puts app.asar back and drops the DNS
/// rules, so the machine returns to its pre-patch state without reinstalling.
fn handle_revert_all() {
    clear_screen();
    println!("{}", APP_TITLE);
    println!();
    println!("Полный откат: снятие патча с бинарников, восстановление app.asar");
    println!("и удаление NRPT-правил DNS.");
    println!("------------------------------------------------------------");

    kill_affected_processes();

    let installs = find_all_installs();
    if installs.is_empty() {
        println!("Установки Antigravity не найдены.");
    }

    let mut reverted = Vec::new();
    for inst in &installs {
        println!("{}", "--------------------------------------------------");
        println!(
            "{} {}",
            "Обработка:",
            mask_path(&inst.display().to_string())
        );
        let n = unpatch_all_binaries(inst);
        if let Err(e) = restore_pristine_asar(&inst.join("resources")) {
            println!("  \x1b[33m[ERR] {}\x1b[0m\x1b[92m", e);
        }
        if n > 0 {
            reverted.push(mask_path(&inst.display().to_string()));
        }
    }

    println!("{}", "--------------------------------------------------");
    print!("Удаление NRPT-правил DNS... ");
    io::stdout().flush().ok();
    remove_dns_nrpt();
    println!("готово.");

    print_results(&reverted, &[]);
}

fn is_valid_gemini_api_key(key: &str) -> bool {
    key.trim().starts_with("AIzaSy") && key.trim().len() == 39
}

fn get_system_gcloud_project() -> Option<String> {
    if let Ok(proj) = env::var("GOOGLE_CLOUD_PROJECT") {
        if !proj.is_empty() {
            return Some(proj.trim().to_string());
        }
    }
    #[cfg(target_os = "windows")]
    {
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "[Environment]::GetEnvironmentVariable('GOOGLE_CLOUD_PROJECT', 'User')",
            ])
            .output()
            .ok()?;
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !stdout.is_empty() {
                return Some(stdout);
            }
        }
    }
    let settings_path = format!(
        "{}\\.gemini\\settings.json",
        env::var("USERPROFILE").unwrap_or_default()
    );
    if let Ok(content) = std::fs::read_to_string(&settings_path) {
        if let Some(start) = content.find(r#""project":""#) {
            let remainder = &content[start + 11..];
            if let Some(end) = remainder.find('"') {
                let proj = &remainder[..end];
                if !proj.is_empty() {
                    return Some(proj.to_string());
                }
            }
        }
    }
    None
}

fn is_valid_project_id(proj: &str) -> bool {
    let p = proj.trim();
    if p.is_empty() || p.len() < 4 || p.len() > 30 {
        return false;
    }
    p.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn update_settings_project_id(project_id: &str) -> Result<(), String> {
    let settings_path = format!(
        "{}\\.gemini\\settings.json",
        env::var("USERPROFILE").unwrap_or_default()
    );
    if !std::path::Path::new(&settings_path).exists() {
        let settings_dir = format!("{}\\.gemini", env::var("USERPROFILE").unwrap_or_default());
        std::fs::create_dir_all(&settings_dir)
            .map_err(|e| format!("Не удалось создать директорию {}: {}", settings_dir, e))?;

        let default_content = format!("{{\n  \"project\": \"{}\"\n}}", project_id);
        std::fs::write(&settings_path, default_content)
            .map_err(|e| format!("Не удалось записать settings.json: {}", e))?;
        return Ok(());
    }

    let content = std::fs::read_to_string(&settings_path)
        .map_err(|e| format!("Не удалось прочитать settings.json: {}", e))?;

    let new_content = if content.contains(r#""project":"#) {
        if let Some(start) = content.find(r#""project":"#) {
            let remainder = &content[start + 10..];
            if let Some(quote_start) = remainder.find('"') {
                let after_quote = &remainder[quote_start + 1..];
                if let Some(quote_end) = after_quote.find('"') {
                    let before = &content[..start + 10 + quote_start + 1];
                    let after = &after_quote[quote_end..];
                    format!("{}{}{}", before, project_id, after)
                } else {
                    content.clone()
                }
            } else {
                content.clone()
            }
        } else {
            content.clone()
        }
    } else {
        if let Some(pos) = content.find('{') {
            let (before, after) = content.split_at(pos + 1);
            format!("{}\n  \"project\": \"{}\",{}", before, project_id, after)
        } else {
            content.clone()
        }
    };

    std::fs::write(&settings_path, new_content)
        .map_err(|e| format!("Не удалось обновить settings.json: {}", e))?;
    Ok(())
}

fn get_system_gemini_api_key() -> Option<String> {
    if let Ok(key) = env::var("GEMINI_API_KEY") {
        if is_valid_gemini_api_key(&key) {
            return Some(key.trim().to_string());
        }
    }
    #[cfg(target_os = "windows")]
    {
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "[Environment]::GetEnvironmentVariable('GEMINI_API_KEY', 'User')",
            ])
            .output()
            .ok()?;
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if is_valid_gemini_api_key(&stdout) {
                return Some(stdout);
            }
        }
    }
    None
}

fn handle_patch_antigravity() {
    kill_affected_processes();
    let installs = find_all_installs();

    if installs.is_empty() {
        println!("{}", "Установки Antigravity не найдены.");
        thread::sleep(Duration::from_secs(2));
        return;
    }

    let mut successes = Vec::new();
    let mut failures = Vec::new();

    for inst in &installs {
        println!("{}", "--------------------------------------------------");
        println!(
            "{} {}",
            "Обработка:",
            mask_path(&inst.display().to_string())
        );
        match process_install(inst) {
            Ok(name) => {
                println!("{} {}", "[OK] Успешно пропатчено:", name);
                successes.push(name);
            }
            Err(e) => {
                println!("\x1b[33m[ERR] Ошибка: {}\x1b[0m\x1b[92m", e);
                failures.push(format!(
                    "{} - {}",
                    mask_path(&inst.display().to_string()),
                    e
                ));
            }
        }
    }

    if (!successes.is_empty() || !failures.is_empty()) && is_admin() {
        if !is_nrpt_applied() {
            print!("\nПатч для Google серверов... ");
            io::stdout().flush().ok();
            match setup_dns_nrpt() {
                Ok(_) => println!("OK"),
                Err(_) => println!("пропущено"),
            }
        }
    }

    print_results(&successes, &failures);
}

fn handle_patch_gemini() {
    kill_affected_processes();
    let gemini_cli_exists = is_gemini_cli_installed();

    if !gemini_cli_exists {
        println!("{}", "Gemini CLI не найден.");
        thread::sleep(Duration::from_secs(2));
        return;
    }

    let mut successes = Vec::new();
    let mut failures = Vec::new();

    let mut api_key = String::new();

    // The Gemini flow points the user at the AI Studio key page, so that host
    // is routed too.
    if is_admin() {
        print!("\nПатч для Google серверов... ");
        io::stdout().flush().ok();
        match setup_dns_nrpt_with(true) {
            Ok(_) => println!("OK"),
            Err(_) => println!("пропущено"),
        }
    }

    let existing_key = get_system_gemini_api_key();
    const API_KEYS_URL: &str = "https://aistudio.google.com/app/u/1/api-keys";

    println!("\n============================================================");
    println!("Gemini CLI (forbidden necromancy)");
    println!("Требуется: AIzaSy-ключ из");
    println!(
        "  {}",
        link(API_KEYS_URL, "aistudio.google.com/app/u/1/api-keys")
    );
    println!("  {}", open_hint("open"));
    println!();

    if let Some(ref ext_key) = existing_key {
        let masked = format!("{}***{}", &ext_key[..6], &ext_key[ext_key.len() - 4..]);
        println!(
            "  - Нажмите Enter для использования сохраненного ключа ({})",
            masked
        );
        println!("  - Или введите 'skip' для сброса ключа и перехода к браузерному OAuth");
        println!("  - Или вставьте новый AIzaSy-ключ");
    } else {
        println!("  - Вставьте AIzaSy-ключ");
        println!(
            "  - Или нажмите Enter (пустая строка) для пропуска (авторизация через браузер/OAuth)"
        );
    }
    println!("------------------------------------------------------------");

    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap_or(0);
        let key_input = input.trim().to_string();

        print!("\x1b[1A\x1b[2K");
        io::stdout().flush().unwrap();

        if key_input.eq_ignore_ascii_case("open") || key_input.eq_ignore_ascii_case("o") {
            open_url(API_KEYS_URL);
            println!("> (страница открыта в браузере)");
            continue;
        }

        if key_input.is_empty() {
            if let Some(ref ext_key) = existing_key {
                api_key = ext_key.clone();
                let masked = format!("{}***{}", &api_key[..6], &api_key[api_key.len() - 4..]);
                println!("> {}", masked);
                println!("Используется сохраненный API-ключ.");
            } else {
                println!("> (пропущено - будет использоваться авторизация через браузер/OAuth)");
            }
            break;
        }

        if key_input.to_lowercase() == "skip" || key_input.to_lowercase() == "oauth" {
            println!("> (сброшено - будет использоваться авторизация через браузер/OAuth)");
            api_key = String::new();
            break;
        }

        if is_valid_gemini_api_key(&key_input) {
            api_key = key_input;
            let masked = format!("{}***{}", &api_key[..6], &api_key[api_key.len() - 4..]);
            println!("> {}", masked);
            println!("API-ключ получен.");
            break;
        } else {
            println!("> (неверный формат)");
            println!("\x1b[33m[ERR] Неверный формат API-ключа. Ожидается: AIzaSy (39 символов).\x1b[0m\x1b[92m");
        }
    }

    let mut project_id = String::new();
    let existing_project = get_system_gcloud_project();
    const PROJECT_URL: &str = "https://aistudio.google.com/app/apikey";

    println!("\n============================================================");
    println!("Google Cloud Project ID (Идентификатор проекта)");
    println!("Требуется для работы OAuth (авторизации через браузер).");
    println!("Вы можете получить его из:");
    println!("  {}", link(PROJECT_URL, "aistudio.google.com/app/apikey"));
    println!("  (кликните на имя проекта или шестеренку у вашего ключа)");
    println!("  {}", open_hint("open"));
    println!();

    if let Some(ref ext_proj) = existing_project {
        println!(
            "  - Нажмите Enter для использования сохраненного Project ID ({})",
            ext_proj
        );
        println!("  - Или введите 'skip' для сброса и использования дефолтного cloudshell-gca");
        println!("  - Или введите новый Project ID");
    } else {
        println!("  - Введите Project ID");
        println!("  - Или нажмите Enter для пропуска (будет использован дефолтный cloudshell-gca)");
    }
    println!("------------------------------------------------------------");

    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap_or(0);
        let proj_input = input.trim().to_string();

        print!("\x1b[1A\x1b[2K");
        io::stdout().flush().unwrap();

        if proj_input.eq_ignore_ascii_case("open") || proj_input.eq_ignore_ascii_case("o") {
            open_url(PROJECT_URL);
            println!("> (страница открыта в браузере)");
            continue;
        }

        if proj_input.is_empty() {
            if let Some(ref ext_proj) = existing_project {
                project_id = ext_proj.clone();
                println!("> {}", project_id);
                println!("Используется сохраненный Project ID.");
            } else {
                println!("> (пропущено - по умолчанию cloudshell-gca)");
            }
            break;
        }

        if proj_input.to_lowercase() == "skip" || proj_input.to_lowercase() == "default" {
            println!("> (сброшено - по умолчанию cloudshell-gca)");
            project_id = String::new();
            break;
        }

        if is_valid_project_id(&proj_input) {
            project_id = proj_input;
            println!("> {}", project_id);
            println!("Project ID получен.");
            break;
        } else {
            println!("> (неверный формат)");
            println!("\x1b[33m[ERR] Неверный формат Project ID. Ожидается: от 4 до 30 символов, строчные латинские буквы, цифры и дефис.\x1b[0m\x1b[92m");
        }
    }

    println!("{}", "--------------------------------------------------");
    println!("Разблокировка Gemini CLI...");

    let set_gemini = if !api_key.is_empty() {
        format!(
            "[Environment]::SetEnvironmentVariable('GEMINI_API_KEY', '{}', 'User')",
            api_key
        )
    } else {
        "[Environment]::SetEnvironmentVariable('GEMINI_API_KEY', $null, 'User')".to_string()
    };
    Command::new("powershell")
        .args(["-NoProfile", "-Command", &set_gemini])
        .output()
        .ok();

    let set_project = if !project_id.is_empty() {
        format!(
            "[Environment]::SetEnvironmentVariable('GOOGLE_CLOUD_PROJECT', '{}', 'User')",
            project_id
        )
    } else {
        "[Environment]::SetEnvironmentVariable('GOOGLE_CLOUD_PROJECT', $null, 'User')".to_string()
    };
    Command::new("powershell")
        .args(["-NoProfile", "-Command", &set_project])
        .output()
        .ok();

    if !project_id.is_empty() {
        if let Err(e) = update_settings_project_id(&project_id) {
            println!(
                "\x1b[33m[ERR] Не удалось обновить settings.json: {}\x1b[0m\x1b[92m",
                e
            );
        }
    }

    match run_gemini_patcher() {
        Ok(_) => {
            println!("[OK] Gemini CLI успешно разблокирован!");
            successes.push("Gemini CLI".to_string());
        }
        Err(e) => {
            println!(
                "\x1b[33m[ERR] Ошибка разблокировки Gemini CLI: {}\x1b[0m\x1b[92m",
                e
            );
            failures.push(format!("Gemini CLI - {}", e));
        }
    }

    print_results(&successes, &failures);
}

fn handle_manual_path() {
    clear_screen();
    println!("{}", APP_TITLE);
    println!("\n============================================================");
    println!("Указать путь к Antigravity вручную");
    println!("Вставьте путь к папке установки или исполняемому файлу");
    println!("(с кавычками или без, например: D:\\Antigravity IDE)");
    println!("------------------------------------------------------------");
    print!("> ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or(0);

    let cleaned = clean_input_path(&input);
    if cleaned.is_empty() {
        return;
    }

    let input_path = PathBuf::from(&cleaned);

    println!("{}", "--------------------------------------------------");
    let resolved = match resolve_install_root(&input_path) {
        Some(path) => path,
        None => {
            println!(
                "\x1b[33m[ERR] По указанному пути установка Antigravity не найдена.\x1b[0m\x1b[92m"
            );
            println!("Проверьте правильность пути: {}", cleaned);
            println!("\nЧтобы вернуться в главное меню, нажмите Enter");
            let mut wait = String::new();
            io::stdin().read_line(&mut wait).ok();
            return;
        }
    };

    println!(
        "{} {}",
        "Обработка:",
        mask_path(&resolved.display().to_string())
    );

    let mut successes = Vec::new();
    let mut failures = Vec::new();

    match process_install(&resolved) {
        Ok(name) => {
            println!("{} {}", "[OK] Успешно пропатчено:", name);
            successes.push(name);
        }
        Err(e) => {
            println!("\x1b[33m[ERR] Ошибка: {}\x1b[0m\x1b[92m", e);
            failures.push(format!(
                "{} - {}",
                mask_path(&resolved.display().to_string()),
                e
            ));
        }
    }

    if (!successes.is_empty() || !failures.is_empty()) && is_admin() {
        if !is_nrpt_applied() {
            print!("\nПатч для Google серверов... ");
            io::stdout().flush().ok();
            match setup_dns_nrpt() {
                Ok(_) => println!("OK"),
                Err(_) => println!("пропущено"),
            }
        }
    }

    print_results(&successes, &failures);
}

fn show_admin_prewarning() {
    clear_screen();
    println!("{}", APP_TITLE);
    println!();
    println!("Внимание: анлокер запущен без прав администратора.");
    println!();
    println!("Без админ-прав будут сняты только клиентские региональные");
    println!("ограничения. Серверный патч требует повышенных привилегий");
    println!("и будет пропущен.");
    println!();
    println!("Если вы находитесь в санкционной территории и упираетесь");
    println!("в 'User location is not supported' — закройте окно и");
    println!("запустите программу от имени Администратора.");
    println!();
    print!("Нажмите Enter чтобы продолжить... ");
    io::stdout().flush().ok();
    let mut tmp = String::new();
    io::stdin().read_line(&mut tmp).ok();
}

fn main() {
    // `--about` / `--license` / `--version`: prints the copyright notice and the
    // build canaries, then exits. Deliberately before the key prompt so any
    // binary can be fingerprinted without a licence key.
    canary::handle_cli_flags();

    let window_title = format!("Antigravity анлокер v{}", APP_VERSION);
    #[cfg(target_os = "windows")]
    console_style::set(&window_title);

    if !is_admin() && !is_nrpt_applied() {
        show_admin_prewarning();
    }

    login_screen();

    loop {
        clear_screen();
        // Users only need the product name and version here; the build canary is
        // not shown (it stays in the binary, the version resource and `--about`
        // for provenance). RELEASE_TOKEN is pinned into the binary by
        // canary::CANARY_ANCHOR, so dropping this reference cannot strip it.
        println!("{} v{}", APP_TITLE, APP_VERSION);
        println!();
        println!("1. Разблокировать Antigravity / Antigravity IDE / Antigravity CLI");
        println!("2. Разблокировать Gemini CLI (deprecated)");
        println!("3. Отменить NRPT-патч (отключит исправление ошибок \"400\")");
        println!(
            "4. Открыть Telegram-группу ({})",
            link(TELEGRAM_URL, TELEGRAM_URL)
        );
        println!("5. Поблагодарить автора ({})", link(DONATE_URL, DONATE_URL));
        println!("6. Указать путь к Antigravity вручную");
        println!("7. Полный откат (снять патч и вернуть исходное состояние)");
        println!("0. Выход");
        println!();
        println!("Пункты 4 и 5 открывают ссылку в браузере.");
        if !is_admin() && !is_nrpt_applied() {
            println!("Запущено без админ-прав: серверный патч будет пропущен.");
        }
        println!();

        match prompt("> ").as_str() {
            "1" => handle_patch_antigravity(),
            "2" => handle_patch_gemini(),
            "3" => handle_restore_dns(),
            "4" => open_url(TELEGRAM_URL),
            "5" => open_url(DONATE_URL),
            "6" => handle_manual_path(),
            "7" => handle_revert_all(),
            "0" => break,
            _ => {
                println!("{}", "Неверный выбор.");
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}
