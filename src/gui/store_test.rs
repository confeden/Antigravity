//! Loopback-only client for the private storefront test.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui;

const COPY_WINDOW: Duration = Duration::from_secs(15 * 60);
const CHECK_INTERVAL: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Clone, serde::Serialize)]
struct Device {
    code: String,
    proof: String,
}

impl Device {
    fn generate() -> Result<Self, &'static str> {
        let mut bytes = [0; 40];
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut bytes)
            .map_err(|_| "Не удалось создать тестовый код")?;
        let number = u64::from_be_bytes(bytes[..8].try_into().expect("8 bytes"));
        let code = (0..12)
            .map(|position| CODE_ALPHABET[((number >> (5 * position)) & 31) as usize] as char)
            .collect();
        Ok(Self {
            code,
            proof: hex::encode(&bytes[8..]),
        })
    }
}

pub(super) struct Activation {
    port: u16,
    device: Option<Device>,
    copied_at: Option<Instant>,
    registered_copy: Option<Instant>,
    checked_at: Option<Instant>,
    pending: Option<(Instant, Receiver<Result<bool, String>>)>,
    active: bool,
    note: Option<String>,
}

impl Activation {
    pub(super) fn from_env() -> Option<Self> {
        let port = std::env::var("AI_UNLOCKER_TEST_STORE_PORT")
            .ok()?
            .parse()
            .ok()?;
        if port == 0 {
            return None;
        }
        Some(Self::new(port))
    }

    fn new(port: u16) -> Self {
        Self {
            port,
            device: None,
            copied_at: None,
            registered_copy: None,
            checked_at: None,
            pending: None,
            active: false,
            note: None,
        }
    }

    pub(super) fn view(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.strong("Тест лицензии AI Unlocker");
            if self.active {
                ui.colored_label(super::theme::palette(ui).ok, "Тестовая лицензия активна");
                return;
            }
            if ui.button("Скопировать тестовый код").clicked() {
                if let Err(reason) = self.copy() {
                    self.note = Some(reason.into());
                }
            }
            if let Some(device) = &self.device {
                ui.label(&device.code);
            }
            if let Some(note) = &self.note {
                ui.label(note);
            }
        });
        ui.add_space(8.0);
    }

    fn copy(&mut self) -> Result<(), &'static str> {
        if self.device.is_none() {
            self.device = Some(Device::generate()?);
        }
        let device = self.device.as_ref().expect("generated device");
        if !crate::utils::set_clipboard_text(&device.code) {
            return Err("Не удалось скопировать тестовый код");
        }
        self.copied_at = Some(Instant::now());
        self.checked_at = None;
        self.note = Some("Код скопирован. Вставьте его при оформлении тестового заказа.".into());
        Ok(())
    }

    fn can_poll(&self, now: Instant, focused: bool) -> bool {
        focused
            && !self.active
            && self
                .copied_at
                .is_some_and(|copied| now.duration_since(copied) < COPY_WINDOW)
    }

    pub(super) fn tick(&mut self, ctx: &egui::Context) {
        if let Some((copied, rx)) = &self.pending {
            let result = match rx.try_recv() {
                Ok(result) => result,
                Err(TryRecvError::Disconnected) => {
                    Err("Проверка тестовой лицензии прервалась".into())
                }
                Err(TryRecvError::Empty) => return,
            };
            if self.copied_at == Some(*copied) && copied.elapsed() < COPY_WINDOW {
                match result {
                    Ok(active) => {
                        self.active = active;
                        self.registered_copy = Some(*copied);
                        self.note = Some("Ожидается ручное подтверждение тестового заказа.".into());
                    }
                    Err(reason) => self.note = Some(reason),
                }
            }
            self.pending = None;
        }
        let now = Instant::now();
        if !self.can_poll(now, ctx.input(|input| input.focused)) {
            return;
        }
        if let Some(wait) = self
            .checked_at
            .and_then(|checked| CHECK_INTERVAL.checked_sub(now.duration_since(checked)))
        {
            ctx.request_repaint_after(wait);
            return;
        }
        let (Some(copied), Some(device)) = (self.copied_at, self.device.clone()) else {
            return;
        };
        let register = self.registered_copy != Some(copied);
        let port = self.port;
        let ctx = ctx.clone();
        let (tx, rx) = mpsc::channel();
        self.checked_at = Some(now);
        let worker = std::thread::Builder::new()
            .name("store-test".into())
            .spawn(move || {
                let result = check(port, &device, register);
                let _ = tx.send(result);
                ctx.request_repaint();
            });
        match worker {
            Ok(_) => self.pending = Some((copied, rx)),
            Err(error) => {
                self.note = Some(format!(
                    "Не запустилась проверка тестовой лицензии: {error}"
                ))
            }
        }
    }
}

fn check(port: u16, device: &Device, register: bool) -> Result<bool, String> {
    if register {
        post(port, "register", device)?;
    }
    let reply = post(port, "status", device)?;
    reply["active"]
        .as_bool()
        .ok_or_else(|| "Неизвестный статус тестовой лицензии".into())
}

fn post(port: u16, action: &str, device: &Device) -> Result<serde_json::Value, String> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let body = serde_json::to_vec(device).map_err(|err| err.to_string())?;
    let read = || -> std::io::Result<Vec<u8>> {
        let mut stream = TcpStream::connect_timeout(&addr, IO_TIMEOUT)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        write!(stream, "POST /unlocker-test/device/{action} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
        stream.write_all(&body)?;
        let mut response = Vec::new();
        stream.take(16_384).read_to_end(&mut response)?;
        Ok(response)
    };
    let reply = read().map_err(|err| format!("Нет связи с тестовой Витриной: {err}"))?;
    let split = reply
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or("Некорректный HTTP-ответ тестовой Витрины")?;
    let header = std::str::from_utf8(&reply[..split]).map_err(|err| err.to_string())?;
    let data: serde_json::Value =
        serde_json::from_slice(&reply[split + 4..]).map_err(|err| err.to_string())?;
    if header.split_whitespace().nth(1) != Some("200") {
        return Err(data["error"]
            .as_str()
            .unwrap_or("Тестовая Витрина отклонила запрос")
            .into());
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polling_requires_focus_a_recent_copy_and_no_confirmation() {
        let mut activation = Activation::new(18422);
        let copied = Instant::now();
        assert!(!activation.can_poll(copied, true));
        activation.copied_at = Some(copied);
        assert!(!activation.can_poll(copied, false));
        assert!(activation.can_poll(copied + COPY_WINDOW - Duration::from_secs(1), true));
        assert!(!activation.can_poll(copied + COPY_WINDOW, true));
        activation.active = true;
        assert!(!activation.can_poll(copied, true));
    }
}
