//! Antigravity IDE's local HTTP connection to its agy backend.

use std::fs;
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use jsonc_parser::cst::{CstObject, CstRootNode};
use jsonc_parser::{json, ParseOptions};

const SETTING: &str = "antigravity.serverPort";
const DEFAULT_PORT: u16 = 42130;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum Setting {
    Missing,
    Number(u16),
    Text(String),
    Null,
}

impl Setting {
    fn read(object: &CstObject) -> Result<Self, String> {
        let Some(property) = object.get(SETTING) else {
            return Ok(Self::Missing);
        };
        let value = property
            .value()
            .ok_or("Antigravity IDE: значение serverPort отсутствует")?;
        match serde_json::from_str(&value.to_string()) {
            Ok(serde_json::Value::Number(number)) => number
                .as_u64()
                .and_then(|value| u16::try_from(value).ok())
                .map(Self::Number)
                .ok_or_else(|| {
                    "Antigravity IDE: serverPort должен быть в диапазоне 0–65535".into()
                }),
            Ok(serde_json::Value::String(text)) => Ok(Self::Text(text)),
            Ok(serde_json::Value::Null) => Ok(Self::Null),
            _ => Err("Antigravity IDE: недопустимое значение serverPort".into()),
        }
    }

    fn port(&self) -> Result<u16, String> {
        match self {
            Self::Number(value) => Ok(*value),
            Self::Text(value) if !value.trim().is_empty() => value
                .trim()
                .parse()
                .map_err(|_| "Antigravity IDE: serverPort должен быть в диапазоне 0–65535".into()),
            _ => Ok(0),
        }
    }

    fn write(&self, object: &CstObject) {
        let value = match self {
            Self::Number(number) => json!(u32::from(*number)),
            Self::Text(text) => json!(text.clone()),
            Self::Null => json!(null),
            Self::Missing => {
                if let Some(property) = object.get(SETTING) {
                    property.remove();
                }
                return;
            }
        };
        if let Some(property) = object.get(SETTING) {
            property.set_value(value);
        } else {
            object.append(SETTING, value);
        }
    }
}

fn read(path: &Path) -> Result<String, String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok("{}".into()),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

fn parse(text: &str) -> Result<(CstRootNode, CstObject), String> {
    let root = CstRootNode::parse(
        text.trim_start_matches('\u{feff}'),
        &ParseOptions::default(),
    )
    .map_err(|error| format!("Настройки Antigravity IDE: {error}"))?;
    let object = if let Some(object) = root.object_value() {
        object
    } else if root.value().is_none() {
        root.object_value_or_set()
    } else {
        return Err("Настройки Antigravity IDE должны содержать объект JSONC".into());
    };
    Ok((root, object))
}

fn write(path: &Path, original: &str, root: &CstRootNode) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let mut updated = root.to_string();
    if original.starts_with('\u{feff}') {
        updated.insert(0, '\u{feff}');
    }
    crate::patch_ide::write_atomic(path, &updated)
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn backup_path() -> PathBuf {
    crate::dns_forwarder::log_dir().join("paid-ide-hub-setting.json")
}

pub(super) fn settings_path() -> Result<PathBuf, String> {
    let root = std::env::var_os("APPDATA").ok_or("Не найден каталог настроек Antigravity IDE")?;
    Ok(PathBuf::from(root).join("Antigravity IDE/User/settings.json"))
}

fn backup() -> Result<Option<Setting>, String> {
    match fs::read(backup_path()) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| error.to_string()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

pub(super) struct Hub {
    pub port: u16,
    pub configured: bool,
    pub listeners: Vec<PathBuf>,
    settings: PathBuf,
}

impl Hub {
    pub fn find(settings: PathBuf, listeners: Vec<PathBuf>) -> Result<Self, String> {
        let text = read(&settings)?;
        let (_, object) = parse(&text)?;
        let configured = Setting::read(&object)?.port()?;
        let port = if configured == 0 {
            DEFAULT_PORT
        } else {
            configured
        };
        Ok(Self {
            port,
            configured: configured != 0,
            listeners,
            settings,
        })
    }

    pub fn verify(&self, proxy_port: u16) -> Result<(), String> {
        if self.port == proxy_port {
            return Err("Порт backend Antigravity IDE совпадает с портом прокси PAID".into());
        }
        let address = SocketAddr::from(([127, 0, 0, 1], self.port));
        if let Some(image) = crate::portcheck::listener_path(address) {
            if self
                .listeners
                .iter()
                .any(|path| path.as_os_str().eq_ignore_ascii_case(image.as_os_str()))
            {
                return Ok(());
            }
        } else if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err() {
            return Ok(());
        }
        Err(format!(
            "Локальный порт backend Antigravity IDE {} занят другой программой",
            self.port
        ))
    }

    pub fn configure(&self) -> Result<(), String> {
        let original = read(&self.settings)?;
        let (root, object) = parse(&original)?;
        let value = Setting::read(&object)?;
        match value.port()? {
            port if port == self.port => return Ok(()),
            0 if self.port == DEFAULT_PORT => {}
            _ => {
                return Err(
                    "Порт backend Antigravity IDE изменился. Перезапустите AI Unlocker.".into(),
                )
            }
        }

        if backup()?.is_none() {
            let encoded = serde_json::to_string(&value).map_err(|error| error.to_string())?;
            crate::patch_ide::write_atomic(&backup_path(), &encoded)
                .map_err(|error| format!("Резервная копия порта backend IDE: {error}"))?;
        }
        Setting::Number(self.port).write(&object);
        write(&self.settings, &original, &root)
    }
}

pub(super) fn restore() -> Result<(), String> {
    let Some(backup) = backup()? else {
        return Ok(());
    };
    let file = settings_path()?;
    let original = read(&file)?;
    let (root, object) = parse(&original)?;
    if Setting::read(&object)? == Setting::Number(DEFAULT_PORT) {
        backup.write(&object);
        write(&file, &original, &root)?;
    }
    fs::remove_file(backup_path()).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinning_and_restoring_the_hub_preserves_jsonc_and_other_keys() {
        let source = "{\n  // User comment\n  \"editor.fontSize\": 14,\n  \"antigravity.serverPort\": 0,\n}\n";
        let (root, object) = parse(source).unwrap();
        let original = Setting::read(&object).unwrap();
        Setting::Number(DEFAULT_PORT).write(&object);
        assert_eq!(
            Setting::read(&object).unwrap().port().unwrap(),
            DEFAULT_PORT
        );
        assert_eq!(
            root.to_string(),
            source.replace(": 0,", &format!(": {DEFAULT_PORT},"))
        );
        original.write(&object);
        assert_eq!(root.to_string(), source);

        let (root, object) = parse("{}").unwrap();
        Setting::Number(DEFAULT_PORT).write(&object);
        Setting::Missing.write(&object);
        assert!(Setting::read(&object).unwrap() == Setting::Missing);
        assert!(parse(&root.to_string()).is_ok());
    }
}
