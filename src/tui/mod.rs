//! The terminal front end: the same switches as the window, for a machine that
//! cannot or should not open one — a server over SSH, a desktop whose graphics
//! driver draws nothing, a user who would rather type.
//!
//! Nothing here decides anything. The verdict on top is `gui::status` (the pure
//! function the window's card calls), every action is an `ops` command, the
//! report is `gui::report`. Only the drawing and the keys belong to this file,
//! so the two front ends cannot drift into saying different things.
//!
//! Where it runs (`main`): `--tui` anywhere; on Linux also any start with no
//! graphical session but a terminal (a server over SSH); on Windows also when no
//! renderer could open the window at all. On Windows the exe is a GUI-subsystem
//! program, which cmd and PowerShell do not wait for — sharing their console
//! would split every keystroke between the shell's prompt and this screen — so
//! it gets a console of its own, except over SSH where there is no desktop to
//! put one on (see `console`).

use std::io::Write as _;
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{
    self, Event as TermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
};
use ratatui::{DefaultTerminal, Frame};

use crate::auth;
use crate::gate;
use crate::gui::status::{self, Action, Facts, Tone};
use crate::ops::{self, Cap, Cmd, Event, Level, State, Status, Worker};
use crate::update::{self, ReleaseInfo};

/// How many log lines are kept, as in the window.
const LOG_LIMIT: usize = 400;
/// Below this the layout cannot hold the card, the list and the journal.
const MIN_W: u16 = 50;
const MIN_H: u16 = 18;

/// `--tui` (or `tui`, any number of dashes) anywhere on the command line.
pub fn requested() -> bool {
    std::env::args()
        .skip(1)
        .any(|a| a.trim_start_matches('-').eq_ignore_ascii_case("tui"))
}

/// Linux: a terminal and nothing to draw a window into — a server over SSH.
#[cfg(not(windows))]
pub fn only_terminal() -> bool {
    use std::io::IsTerminal;
    std::env::var_os("DISPLAY").is_none()
        && std::env::var_os("WAYLAND_DISPLAY").is_none()
        && std::io::stdin().is_terminal()
}

/// Runs until the user quits. `note` is shown first in the journal — why the
/// window did not open, when that is why we are here.
pub fn run(note: Option<String>) -> Result<(), String> {
    #[cfg(windows)]
    {
        console::open()?;
        // A console this process opened closes with it, and the panic text with
        // it. Replaces the window's hook too, if the window was tried first: its
        // relaunch-on-the-next-renderer has nothing left to do here. ratatui's
        // own hook (below) puts the terminal back before this runs.
        let _ = std::panic::take_hook();
        std::panic::set_hook(Box::new(|info| {
            crate::utils::message_box(
                "Antigravity Unlocker",
                &format!("Программа аварийно завершилась.\n\n{info}"),
            );
        }));
    }

    let mut terminal = ratatui::try_init().map_err(|e| format!("терминал недоступен: {e}"))?;
    // Bracketed paste makes a pasted key one event instead of 25 keystrokes.
    // Windows' console has no such mode; there a paste arrives as keys, which
    // the key field takes just as well.
    #[cfg(not(windows))]
    let _ = ratatui::crossterm::execute!(
        std::io::stdout(),
        ratatui::crossterm::event::EnableBracketedPaste
    );

    let result = App::new(note).run(&mut terminal);

    #[cfg(not(windows))]
    let _ = ratatui::crossterm::execute!(
        std::io::stdout(),
        ratatui::crossterm::event::DisableBracketedPaste
    );
    ratatui::restore();
    result
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(PartialEq)]
enum Screen {
    License,
    Main,
}

/// A line being typed into, drawn as a box over the list.
enum Input {
    Path { text: String, error: Option<String> },
    OwnProxy { text: String },
}

/// One selectable line of the main list.
#[derive(Clone, Copy, PartialEq)]
enum Row {
    /// The status card's one action, when it has one.
    Action(Action),
    Cap(Cap),
    /// The bypass master switch (`ops::bypass_order`).
    Bypass,
    Install(usize),
    /// The fold over «Настройки для опытных».
    Advanced,
    Provider(usize),
    OwnProxyText,
    Report,
}

struct App {
    screen: Screen,
    key: String,
    key_error: bool,
    key_next_attempt: Option<Instant>,

    update: Option<ReleaseInfo>,
    update_rx: Receiver<update::UpdateMsg>,

    worker: Worker,
    events: Receiver<Event>,
    status: Option<Status>,
    gate: gate::View,
    gate_at: Instant,
    gate_rx: Receiver<gate::Signal>,
    log: Vec<(Level, String)>,
    busy: Option<String>,

    list: ListState,
    /// The row the cursor is on, by what it is rather than where: rows come and
    /// go under it (the card's action appears and disappears, installs are
    /// found), and an index would then point a keystroke at the row that slid
    /// into its place - a different switch than the one on screen.
    selected: Row,
    advanced: bool,
    input: Option<Input>,
    /// A line in place of the key hints for a few seconds: what just happened.
    toast: Option<(String, Instant)>,
    quit: bool,
}

impl App {
    fn new(note: Option<String>) -> Self {
        let (up_tx, update_rx) = channel();
        update::spawn_watch(up_tx, std::sync::Arc::new(|| {}), false);
        // The loop below polls every 200 ms, so nothing needs waking.
        let (ev_tx, events) = channel();
        let worker = ops::spawn(ev_tx, Box::new(|| {}));
        let (gate_tx, gate_rx) = channel();
        gate::spawn_watch(gate_tx, Box::new(|| {}));

        let mut log = Vec::new();
        if let Some(note) = note {
            log.push((Level::Warn, note));
        }
        // `sudo ./ag_unlocker`: everything here is per user (the installs under
        // ~/.local/share, the systemd user unit, environment.d), and under sudo
        // "the user" is root. A server where root is the user sets no SUDO_USER.
        #[cfg(not(windows))]
        if let Some(user) = std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty()) {
            if crate::utils::is_admin() {
                log.push((
                    Level::Warn,
                    format!(
                        "Запущено через sudo: Antigravity ищется в домашней папке root, а не {user}. \
                         Запустите без sudo — права root не нужны."
                    ),
                ));
            }
        }
        let screen = first_screen();
        if screen == Screen::Main {
            worker.send(Cmd::Unlocked);
        }
        let mut list = ListState::default();
        list.select(Some(0));
        Self {
            screen,
            key: String::new(),
            key_error: false,
            key_next_attempt: None,
            update: None,
            update_rx,
            worker,
            events,
            status: None,
            gate: gate::View::default(),
            gate_at: Instant::now(),
            gate_rx,
            log,
            busy: None,
            list,
            selected: Row::Cap(Cap::ClientPatch),
            advanced: false,
            input: None,
            toast: None,
            quit: false,
        }
    }

    fn run(mut self, terminal: &mut DefaultTerminal) -> Result<(), String> {
        let mut drawn_at: Option<Instant> = None;
        let mut dirty = true;
        while !self.quit {
            dirty |= self.drain();
            // Ages on the card count up by themselves, so a quiet screen is
            // still redrawn once a second.
            if dirty || drawn_at.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
                terminal
                    .draw(|f| self.draw(f))
                    .map_err(|e| format!("терминал: {e}"))?;
                drawn_at = Some(Instant::now());
                dirty = false;
            }
            if event::poll(Duration::from_millis(200)).map_err(|e| format!("терминал: {e}"))?
            {
                match event::read().map_err(|e| format!("терминал: {e}"))? {
                    // Windows reports releases too; only a press is a keystroke.
                    TermEvent::Key(k) if k.kind != KeyEventKind::Release => self.on_key(k),
                    TermEvent::Paste(text) => self.on_paste(&text),
                    _ => {}
                }
                dirty = true;
            }
        }
        Ok(())
    }

    /// Takes in everything the worker and the watchers sent. True when anything
    /// arrived.
    fn drain(&mut self) -> bool {
        let mut any = false;
        while let Ok(msg) = self.update_rx.try_recv() {
            if let update::UpdateMsg::Available(rel) = msg {
                self.update = Some(rel);
            }
            any = true;
        }
        while let Ok(signal) = self.gate_rx.try_recv() {
            match signal {
                gate::Signal::Gate(view) => {
                    self.gate = view;
                    self.gate_at = Instant::now();
                }
                // The worker owns that measurement (I59), as in the window.
                gate::Signal::MeasureVpn => self.worker.send(Cmd::RemeasureVpn),
            }
            any = true;
        }
        while let Ok(ev) = self.events.try_recv() {
            match ev {
                Event::Log(level, line) => {
                    if self.log.len() >= LOG_LIMIT {
                        self.log.remove(0);
                    }
                    self.log.push((level, line));
                }
                Event::Status(s) => self.status = Some(*s),
                Event::Busy(what) => self.busy = what,
            }
            any = true;
        }
        any
    }

    fn facts(&self) -> Option<Facts> {
        let s = self.status.as_ref()?;
        Some(Facts::read(s, &self.gate, self.gate_at.elapsed()))
    }

    fn toast(&mut self, text: impl Into<String>) {
        self.toast = Some((text.into(), Instant::now()));
    }

    // -----------------------------------------------------------------------
    // Keys
    // -----------------------------------------------------------------------

    fn on_key(&mut self, k: KeyEvent) {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        // Raw mode turns Ctrl+C into a key; it still means "leave".
        if ctrl && matches!(k.code, KeyCode::Char('c') | KeyCode::Char('C')) {
            self.quit = true;
            return;
        }
        if self.screen == Screen::License {
            self.on_license_key(k, ctrl);
        } else if self.input.is_some() {
            self.on_input_key(k, ctrl);
        } else {
            self.on_main_key(k);
        }
    }

    fn on_paste(&mut self, text: &str) {
        let text = text.trim();
        if self.screen == Screen::License {
            self.key = text.to_string();
            self.key_error = false;
        } else if let Some(Input::Path { text: t, .. } | Input::OwnProxy { text: t }) =
            &mut self.input
        {
            t.push_str(text);
        }
    }

    fn on_license_key(&mut self, k: KeyEvent, ctrl: bool) {
        match k.code {
            KeyCode::Esc => self.quit = true,
            KeyCode::Enter => self.try_key(),
            KeyCode::Backspace => {
                self.key.pop();
                self.key_error = false;
            }
            KeyCode::Char('u') if ctrl => self.key.clear(),
            KeyCode::Char(c) if !ctrl && self.key.chars().count() < 64 => {
                self.key.push(c);
                self.key_error = false;
            }
            _ => {}
        }
    }

    fn try_key(&mut self) {
        let normalized = self
            .key
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .count();
        if normalized != 24 {
            self.key_error = true;
            return;
        }
        let now = Instant::now();
        if self.key_next_attempt.is_some_and(|t| t > now) {
            return;
        }
        if auth::verify_key(self.key.trim()) {
            self.screen = Screen::Main;
            self.worker.send(Cmd::Unlocked);
        } else {
            self.key_error = true;
            // The same brake the window has on a flood of guesses.
            self.key_next_attempt = Some(now + Duration::from_millis(500));
        }
    }

    fn on_input_key(&mut self, k: KeyEvent, ctrl: bool) {
        let Some(input) = &mut self.input else { return };
        let text = match input {
            Input::Path { text, .. } | Input::OwnProxy { text } => text,
        };
        match k.code {
            KeyCode::Esc => self.input = None,
            KeyCode::Enter => self.submit_input(),
            KeyCode::Backspace => {
                text.pop();
            }
            KeyCode::Char('u') if ctrl => text.clear(),
            KeyCode::Char(c) if !ctrl => text.push(c),
            _ => {}
        }
    }

    fn submit_input(&mut self) {
        match self.input.take() {
            Some(Input::Path { text, .. }) => {
                let cleaned = crate::clean_input_path(&text);
                if cleaned.is_empty() {
                    return;
                }
                match ops::resolve_manual_path(std::path::Path::new(&cleaned)) {
                    Some(root) => self.worker.send(Cmd::AddPath(root)),
                    None => {
                        self.input = Some(Input::Path {
                            text,
                            error: Some("По этому пути установка Antigravity не найдена.".into()),
                        })
                    }
                }
            }
            Some(Input::OwnProxy { text }) => {
                self.worker.send(Cmd::SetOwnProxy(text.trim().to_string()))
            }
            None => {}
        }
    }

    /// Where the cursor's row is now, and whether it is still there at all. When
    /// it is gone the cursor stays at the same height, on whatever row is there.
    fn cursor(&mut self, rows: &[Row]) -> (usize, bool) {
        let last = rows.len().saturating_sub(1);
        match rows.iter().position(|r| *r == self.selected) {
            Some(at) => (at, true),
            None => {
                let at = self.list.selected().unwrap_or(0).min(last);
                if let Some(r) = rows.get(at) {
                    self.selected = *r;
                }
                (at, false)
            }
        }
    }

    fn go(&mut self, rows: &[Row], at: usize) {
        if let Some(r) = rows.get(at) {
            self.selected = *r;
            self.list.select(Some(at));
        }
    }

    fn on_main_key(&mut self, k: KeyEvent) {
        let rows = self.rows();
        let last = rows.len().saturating_sub(1);
        let (at, still_there) = self.cursor(&rows);
        let row = rows.get(at).copied();
        // The row that was on screen under the cursor has just gone: a key that
        // acts on a row was aimed at it, not at its replacement.
        let acts_on_row = matches!(
            k.code,
            KeyCode::Enter
                | KeyCode::Char(' ')
                | KeyCode::Char('x')
                | KeyCode::Delete
                | KeyCode::Char('+')
                | KeyCode::Char('-')
        );
        if acts_on_row && !still_there {
            self.go(&rows, at);
            return;
        }
        match k.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Up | KeyCode::Char('k') => self.go(&rows, at.saturating_sub(1)),
            KeyCode::Down | KeyCode::Char('j') => self.go(&rows, (at + 1).min(last)),
            KeyCode::PageUp => self.go(&rows, at.saturating_sub(8)),
            KeyCode::PageDown => self.go(&rows, (at + 8).min(last)),
            KeyCode::Home => self.go(&rows, 0),
            KeyCode::End => self.go(&rows, last),
            KeyCode::Enter | KeyCode::Char(' ') => {
                if let Some(row) = row {
                    self.activate(row);
                }
            }
            // Only what the card offers right now, as in the window: «Включить
            // всё» closes Antigravity, and neither belongs to a stray keystroke
            // when the card says there is nothing to do.
            KeyCode::Char('a') => self.act_if_offered(Action::EnableAll),
            KeyCode::Char('r') => self.act_if_offered(Action::Repair),
            KeyCode::Char('o') => self.save_report(),
            KeyCode::Char('x') | KeyCode::Delete => {
                if let Some(Row::Install(i)) = row {
                    self.forget_install(i);
                }
            }
            KeyCode::Char('+') | KeyCode::Char('-') => {
                if let Some(Row::Provider(i)) = row {
                    self.move_provider(i, k.code == KeyCode::Char('-'));
                }
            }
            _ => {}
        }
    }

    fn busy_refusal(&mut self) -> bool {
        if let Some(what) = self.busy.clone() {
            self.toast(format!("Подождите — идёт: {what}"));
            return true;
        }
        false
    }

    fn activate(&mut self, row: Row) {
        match row {
            Row::Action(a) => self.act(a),
            Row::Cap(cap) => {
                if self.busy_refusal() {
                    return;
                }
                let state = self
                    .status
                    .as_ref()
                    .map(|s| s.get(cap).clone())
                    .unwrap_or(State::Off);
                if let State::Blocked(why) = &state {
                    self.toast(format!("Не включается: {why}"));
                    return;
                }
                if cap == Cap::OwnProxy && !state.is_on() && self.own_proxy_text().is_empty() {
                    self.input = Some(Input::OwnProxy {
                        text: String::new(),
                    });
                    return;
                }
                self.worker.send(Cmd::Set(cap, !state.is_on()));
            }
            Row::Bypass => {
                if self.busy_refusal() {
                    return;
                }
                let on = !self.status.as_ref().is_some_and(|s| s.bypass_on());
                for cap in ops::bypass_order(on) {
                    self.worker.send(Cmd::Set(cap, on));
                }
            }
            Row::Install(i) => {
                let text = self.install_path(i).unwrap_or_default();
                self.input = Some(Input::Path { text, error: None });
            }
            Row::Advanced => self.advanced = !self.advanced,
            Row::Provider(i) => {
                if self.busy_refusal() {
                    return;
                }
                if let Some(p) = self.status.as_ref().and_then(|s| s.providers.get(i)) {
                    self.worker
                        .send(Cmd::SetProvider(p.name.clone(), !p.enabled));
                }
            }
            Row::OwnProxyText => {
                self.input = Some(Input::OwnProxy {
                    text: self.own_proxy_text(),
                })
            }
            Row::Report => self.save_report(),
        }
    }

    fn act_if_offered(&mut self, action: Action) {
        let offered = self.facts().and_then(|f| status::headline(&f).action);
        match offered {
            Some(a) if a == action => self.act(action),
            Some(a) => self.toast(format!("Сейчас нужно другое: {}.", a.label())),
            None => self.toast(format!("«{}» сейчас не нужно.", action.label())),
        }
    }

    fn act(&mut self, action: Action) {
        if self.busy_refusal() {
            return;
        }
        match action {
            Action::EnableAll => self.worker.send(Cmd::EnableAll),
            Action::Repair => self.worker.send(Cmd::Repair),
            Action::Elevate => {
                #[cfg(windows)]
                if crate::utils::relaunch_elevated_with("--tui") {
                    self.quit = true;
                    return;
                }
                self.toast("Права администратора не получены.");
            }
        }
    }

    fn install_path(&self, i: usize) -> Option<String> {
        let row = self.status.as_ref()?.installs.get(i)?;
        row.path.as_ref().map(|p| p.display().to_string())
    }

    fn forget_install(&mut self, i: usize) {
        let Some(row) = self.status.as_ref().and_then(|s| s.installs.get(i)) else {
            return;
        };
        match (&row.path, row.manual) {
            (Some(p), true) => {
                let p = p.clone();
                self.worker.send(Cmd::ForgetPath(p));
            }
            _ => self.toast("Убрать можно только путь, указанный вручную."),
        }
    }

    fn move_provider(&mut self, i: usize, up: bool) {
        let Some(s) = self.status.as_ref() else {
            return;
        };
        let mut order: Vec<String> = s.providers.iter().map(|p| p.name.clone()).collect();
        let j = if up {
            i.checked_sub(1)
        } else {
            Some(i + 1).filter(|j| *j < order.len())
        };
        let Some(j) = j else { return };
        order.swap(i, j);
        // Moved locally too, so the selection can follow the row before the
        // worker's snapshot comes back with the same order.
        if let Some(s) = self.status.as_mut() {
            s.providers.swap(i, j);
        }
        self.selected = Row::Provider(j);
        self.worker.send(Cmd::ReorderProviders(order));
    }

    fn own_proxy_text(&self) -> String {
        self.status
            .as_ref()
            .map(|s| s.own_proxy_text.clone())
            .unwrap_or_default()
    }

    /// The window's «Сохранить отчёт». The file is the deliverable - a report
    /// pasted into a chat is a wall of text that arrives truncated - so it goes
    /// to the Desktop, and to the state directory when there is no Desktop to
    /// write to (a server). It is also offered to the terminal (OSC 52: Windows
    /// Terminal, iTerm2, kitty, WezTerm, tmux pass it on to the clipboard of the
    /// machine the user sits at), which is the only clipboard an SSH session has.
    fn save_report(&mut self) {
        let text = crate::gui::report::build(self.status.as_ref(), &self.gate);
        let saved = crate::utils::desktop_dir()
            .and_then(|dir| crate::utils::save_text_file(&dir, crate::utils::REPORT_FILE, &text))
            .or_else(|| {
                let dir = crate::dns_forwarder::log_dir();
                std::fs::create_dir_all(&dir).ok();
                crate::utils::save_text_file(&dir, crate::utils::REPORT_FILE, &text)
            });
        let copied = copy_out(&text);
        let msg = match (saved, copied) {
            (Some(path), Copied::Clipboard) => {
                format!("Отчёт сохранён: {} (и скопирован)", path.display())
            }
            (Some(path), Copied::Terminal) => format!(
                "Отчёт сохранён: {} (и передан терминалу для буфера обмена)",
                path.display()
            ),
            (None, Copied::Clipboard) => {
                "Файл сохранить не удалось — отчёт скопирован в буфер обмена.".to_string()
            }
            (None, Copied::Terminal) => {
                "Файл сохранить не удалось — отчёт передан терминалу для буфера обмена.".to_string()
            }
        };
        self.toast(msg);
    }

    // -----------------------------------------------------------------------
    // Rows
    // -----------------------------------------------------------------------

    fn rows(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        if let Some(a) = self.facts().and_then(|f| status::headline(&f).action) {
            rows.push(Row::Action(a));
        }
        rows.push(Row::Cap(Cap::ClientPatch));
        rows.push(Row::Bypass);
        rows.push(Row::Cap(Cap::Watchdog));
        let installs = self.status.as_ref().map_or(0, |s| s.installs.len());
        rows.extend((0..installs).map(Row::Install));
        rows.push(Row::Advanced);
        if self.advanced {
            rows.push(Row::Cap(Cap::Dns));
            let providers = self.status.as_ref().map_or(0, |s| s.providers.len());
            rows.extend((0..providers).map(Row::Provider));
            if providers > 0 {
                rows.push(Row::Cap(Cap::DnsRotation));
            }
            rows.push(Row::Cap(Cap::LocalProxy));
            rows.push(Row::Cap(Cap::BuiltinExits));
            rows.push(Row::Cap(Cap::VerifyTls));
            rows.push(Row::Cap(Cap::OwnProxy));
            rows.push(Row::OwnProxyText);
        }
        rows.push(Row::Report);
        rows
    }

    /// What the selected row does, for the line under the list.
    fn row_hint(&self, row: Row) -> String {
        match row {
            Row::Action(a) => format!("Enter — {}.", a.label()),
            Row::Cap(cap) => status::switch_text(cap).1.to_string(),
            Row::Bypass => status::BYPASS_TEXT.1.to_string(),
            Row::Install(i) => {
                let manual = self
                    .status
                    .as_ref()
                    .and_then(|s| s.installs.get(i))
                    .is_some_and(|r| r.manual);
                let full = self.install_path(i).unwrap_or_default();
                let mut s = "Enter — указать путь вручную".to_string();
                if manual {
                    s.push_str(", x — убрать указанный путь");
                }
                if !full.is_empty() {
                    s.push_str(&format!(". {full}"));
                }
                s
            }
            Row::Advanced => "Детали обхода: DNS-серверы, прокси, выходы.".into(),
            Row::Provider(_) => "Пробел — включить или выключить сервер, +/- — выше или ниже в списке.".into(),
            Row::OwnProxyText => {
                "Enter — изменить адрес: логин:пароль@адрес:порт (или адрес:порт без пароля).".into()
            }
            Row::Report => {
                "Всё, что нужно, чтобы понять, почему Antigravity отвечает или нет — одним текстом для группы.".into()
            }
        }
    }

    fn row_item(&self, row: Row, width: u16) -> ListItem<'static> {
        let busy = self.busy.is_some();
        match row {
            Row::Action(a) => ListItem::new(Line::from(vec![
                Span::styled("▶ ", Style::new().fg(Color::Cyan)),
                Span::styled(
                    a.label().to_string(),
                    Style::new().add_modifier(Modifier::BOLD),
                ),
            ])),
            Row::Cap(cap) => {
                let state = self
                    .status
                    .as_ref()
                    .map(|s| s.get(cap).clone())
                    .unwrap_or(State::Off);
                let indent = if matches!(cap, Cap::ClientPatch | Cap::Watchdog) {
                    ""
                } else {
                    "  "
                };
                switch_line(indent, status::switch_text(cap).0, &state, busy, width)
            }
            Row::Bypass => {
                let on = self.status.as_ref().is_some_and(|s| s.bypass_on());
                let state = if on { State::On } else { State::Off };
                switch_line("", status::BYPASS_TEXT.0, &state, busy, width)
            }
            Row::Install(i) => {
                let Some(r) = self.status.as_ref().and_then(|s| s.installs.get(i)) else {
                    return ListItem::new("");
                };
                let (dot, color, what) = match (&r.path, r.patched) {
                    (None, _) => (
                        "○",
                        Color::DarkGray,
                        "не найдено — Enter: указать путь".to_string(),
                    ),
                    (Some(p), patched) => (
                        "●",
                        match patched {
                            Some(true) => Color::Green,
                            Some(false) => Color::Gray,
                            None => Color::DarkGray,
                        },
                        crate::utils::mask_path(&p.display().to_string()),
                    ),
                };
                let tail = match (&r.path, r.patched) {
                    (Some(_), Some(true)) => " · пропатчен",
                    (Some(_), Some(false)) => " · не пропатчен",
                    (Some(_), None) => " · проверяю…",
                    (None, _) => "",
                };
                ListItem::new(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(format!("{dot} "), Style::new().fg(color)),
                    Span::raw(format!("{}  ", r.label)),
                    Span::styled(what, Style::new().fg(Color::DarkGray)),
                    Span::styled(tail, Style::new().fg(color)),
                ]))
            }
            Row::Advanced => ListItem::new(Line::styled(
                format!(
                    "{} Настройки для опытных",
                    if self.advanced { "▾" } else { "▸" }
                ),
                Style::new().fg(Color::Gray),
            )),
            Row::Provider(i) => {
                let Some(p) = self.status.as_ref().and_then(|s| s.providers.get(i)) else {
                    return ListItem::new("");
                };
                let state = if p.enabled { State::On } else { State::Off };
                let name = format!("{}. {}", i + 1, status::provider_name(&p.name));
                switch_line("      ", &name, &state, busy, width)
            }
            Row::OwnProxyText => {
                let text = self.own_proxy_text();
                let shown = if text.is_empty() {
                    "не задан".to_string()
                } else {
                    text
                };
                ListItem::new(Line::from(vec![
                    Span::raw("      Адрес прокси: "),
                    Span::styled(shown, Style::new().fg(Color::Gray)),
                ]))
            }
            Row::Report => ListItem::new(Line::from(vec![
                Span::styled("⎘ ", Style::new().fg(Color::Cyan)),
                Span::raw("Сохранить отчёт"),
            ])),
        }
    }

    // -----------------------------------------------------------------------
    // Drawing
    // -----------------------------------------------------------------------

    fn draw(&mut self, f: &mut Frame) {
        let area = f.area();
        if area.width < MIN_W || area.height < MIN_H {
            f.render_widget(
                Paragraph::new(format!(
                    "Окно терминала слишком маленькое: нужно хотя бы {MIN_W}×{MIN_H} (сейчас {}×{}).",
                    area.width, area.height
                ))
                .wrap(Wrap { trim: true }),
                area,
            );
            return;
        }
        match self.screen {
            Screen::License => self.draw_license(f, area),
            Screen::Main => self.draw_main(f, area),
        }
    }

    fn title_line(&self) -> Line<'static> {
        let mut spans = vec![Span::styled(
            format!(" Antigravity Unlocker 2 v{} ", update::current_version()),
            Style::new().add_modifier(Modifier::BOLD),
        )];
        if let Some(rel) = &self.update {
            spans.push(Span::styled(
                format!(
                    " ⬆ новая версия {}: {} ",
                    rel.display_version(),
                    update::RELEASES_LATEST_URL
                ),
                Style::new().fg(Color::Black).bg(Color::Yellow),
            ));
        }
        Line::from(spans)
    }

    fn draw_license(&mut self, f: &mut Frame, area: Rect) {
        let block = Block::new()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .title(self.title_line());
        let inner = block.inner(area);
        f.render_widget(block, area);

        let shown = if self.key.is_empty() {
            Span::styled(
                "XXXXXXXXXXXX-XXXXXXXXXXXX",
                Style::new().fg(Color::DarkGray),
            )
        } else {
            Span::raw(self.key.clone())
        };
        let mut lines = vec![
            Line::raw(""),
            Line::styled(
                "Лицензионный ключ",
                Style::new().add_modifier(Modifier::BOLD),
            ),
            Line::raw(""),
            Line::from(vec![
                Span::raw("  › "),
                shown,
                Span::styled("▏", Style::new().fg(Color::Cyan)),
            ]),
            Line::raw(""),
        ];
        if self.key_error {
            let normalized = self
                .key
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .count();
            let why = if normalized != 24 {
                "В ключе 24 буквы и цифры (дефис не считается)."
            } else {
                "Ключ не подходит к этой версии анлокера."
            };
            lines.push(Line::styled(why, Style::new().fg(Color::Red)));
            lines.push(Line::raw(""));
        }
        lines.push(Line::styled(
            format!(
                "Ключ можно взять в группе: {}",
                crate::gui::TELEGRAM_KEYS_URL
            ),
            Style::new().fg(Color::Gray),
        ));
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "Enter — продолжить · Ctrl+U — стереть · Esc — выход",
            Style::new().fg(Color::DarkGray),
        ));
        f.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }),
            inner.inner(ratatui::layout::Margin::new(2, 1)),
        );
    }

    fn draw_main(&mut self, f: &mut Frame, area: Rect) {
        let facts = self.facts();
        let headline = facts.as_ref().map(status::headline);

        // The card's height follows its text, so a long detail is never cut.
        let inner_w = area.width.saturating_sub(4);
        let card_h = match &headline {
            Some(h) => 2 + 1 + wrapped_height(&h.detail, inner_w) + u16::from(self.busy.is_some()),
            None => 3,
        }
        .min(area.height / 3);
        let log_h = if area.height >= 32 { 9 } else { 6 };
        let [top, card, list, hint, journal, keys] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(card_h),
            Constraint::Min(4),
            Constraint::Length(2),
            Constraint::Length(log_h),
            Constraint::Length(1),
        ])
        .areas(area);

        f.render_widget(Paragraph::new(self.title_line()), top);
        self.draw_card(f, card, headline.as_ref());

        let rows = self.rows();
        let (at, _) = self.cursor(&rows);
        self.list.select(Some(at));
        let items: Vec<ListItem> = rows.iter().map(|r| self.row_item(*r, list.width)).collect();
        let list_widget = List::new(items)
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("› ");
        f.render_stateful_widget(list_widget, list, &mut self.list);

        let selected = self.list.selected().and_then(|i| rows.get(i).copied());
        let hint_text = selected.map(|r| self.row_hint(r)).unwrap_or_default();
        f.render_widget(
            Paragraph::new(hint_text)
                .style(Style::new().fg(Color::DarkGray))
                .wrap(Wrap { trim: true }),
            hint,
        );

        self.draw_journal(f, journal);
        self.draw_keys(f, keys);

        if self.input.is_some() {
            self.draw_input(f, area);
        }
    }

    fn draw_card(&self, f: &mut Frame, area: Rect, headline: Option<&status::Headline>) {
        let Some(h) = headline else {
            f.render_widget(
                Paragraph::new("Проверяю систему…").block(Block::new().borders(Borders::ALL)),
                area,
            );
            return;
        };
        let color = match h.tone {
            Tone::Ok => Color::Green,
            Tone::Wait => Color::Cyan,
            Tone::Fixing => Color::Yellow,
            Tone::Action => Color::Red,
            Tone::Off => Color::Gray,
        };
        let mut lines = vec![Line::from(vec![
            Span::styled("● ", Style::new().fg(color)),
            Span::styled(h.title.clone(), Style::new().add_modifier(Modifier::BOLD)),
        ])];
        lines.push(Line::raw(h.detail.clone()));
        if let Some(what) = &self.busy {
            lines.push(Line::styled(
                format!("⏳ {what}"),
                Style::new().fg(Color::Yellow),
            ));
        }
        f.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: true }).block(
                Block::new()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::new().fg(color)),
            ),
            area,
        );
    }

    fn draw_journal(&self, f: &mut Frame, area: Rect) {
        let block = Block::new()
            .borders(Borders::TOP)
            .title(Span::styled(" Журнал ", Style::new().fg(Color::Gray)))
            .border_style(Style::new().fg(Color::DarkGray));
        let inner = block.inner(area);
        f.render_widget(block, area);
        // Newest at the bottom; only as many as fit once wrapped.
        let mut lines: Vec<Line> = Vec::new();
        let mut used = 0u16;
        for (level, text) in self.log.iter().rev() {
            let shown = if *level == Level::Step {
                format!("— {text}")
            } else {
                text.clone()
            };
            let h = wrapped_height(&shown, inner.width);
            if used + h > inner.height {
                break;
            }
            used += h;
            let color = match level {
                Level::Ok => Color::Green,
                Level::Warn => Color::Yellow,
                Level::Err => Color::Red,
                Level::Step => Color::Cyan,
                Level::Info => Color::Reset,
            };
            lines.push(Line::styled(shown, Style::new().fg(color)));
        }
        lines.reverse();
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }

    fn draw_keys(&mut self, f: &mut Frame, area: Rect) {
        if let Some((text, at)) = &self.toast {
            if at.elapsed() < Duration::from_secs(6) {
                f.render_widget(
                    Paragraph::new(text.clone()).style(Style::new().fg(Color::Cyan)),
                    area,
                );
                return;
            }
            self.toast = None;
        }
        let offered = match self.facts().and_then(|f| status::headline(&f).action) {
            Some(Action::EnableAll) => " · a — включить всё",
            Some(Action::Repair) => " · r — починить",
            _ => "",
        };
        let keys = format!("↑↓ выбор · Пробел/Enter — вкл/выкл{offered} · o — отчёт · q — выход");
        f.render_widget(
            Paragraph::new(keys).style(Style::new().fg(Color::DarkGray)),
            area,
        );
    }

    fn draw_input(&self, f: &mut Frame, area: Rect) {
        let (title, hint, text, error) = match &self.input {
            Some(Input::Path { text, error }) => (
                " Путь к Antigravity ",
                "Папка установки Antigravity, IDE или CLI. Можно указать вложенную — корень будет найден сам.",
                text,
                error.as_deref(),
            ),
            Some(Input::OwnProxy { text }) => (
                " Свой HTTP-прокси ",
                "Формат: логин:пароль@адрес:порт — или просто адрес:порт, если пароля нет. \
                 Например ivan:secret@203.0.113.9:3128. Только HTTP-прокси. \
                 Пустая строка — убрать прокси.",
                text,
                None,
            ),
            None => return,
        };
        let w = area.width.saturating_sub(8).min(90);
        // Borders, the wrapped hint, a blank line, the field, the error, the keys.
        let h = 2 + wrapped_height(hint, w.saturating_sub(2)) + 3 + u16::from(error.is_some());
        let popup = Rect {
            x: area.x + (area.width - w) / 2,
            y: area.y + area.height.saturating_sub(h) / 2,
            width: w,
            height: h,
        };
        let mut lines = vec![
            Line::styled(hint, Style::new().fg(Color::Gray)),
            Line::raw(""),
            Line::from(vec![
                Span::raw("› "),
                Span::raw(text.clone()),
                Span::styled("▏", Style::new().fg(Color::Cyan)),
            ]),
        ];
        if let Some(e) = error {
            lines.push(Line::styled(e.to_string(), Style::new().fg(Color::Red)));
        }
        lines.push(Line::styled(
            "Enter — применить · Esc — отмена",
            Style::new().fg(Color::DarkGray),
        ));
        f.render_widget(Clear, popup);
        f.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }).block(
                Block::new()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(title),
            ),
            popup,
        );
    }
}

/// One switch as a line: `[вкл ] Title — note`.
fn switch_line(
    indent: &str,
    title: &str,
    state: &State,
    busy: bool,
    width: u16,
) -> ListItem<'static> {
    let (badge, color) = match state {
        State::On => ("[вкл ]", Color::Green),
        State::Partial(_) => ("[вкл~]", Color::Yellow),
        State::Off | State::OffNote(_) => ("[выкл]", Color::DarkGray),
        State::Blocked(_) => ("[ -- ]", Color::Yellow),
    };
    let color = if busy { Color::DarkGray } else { color };
    let mut spans = vec![
        Span::raw(indent.to_string()),
        Span::styled(badge, Style::new().fg(color)),
        Span::raw(format!(" {title}")),
    ];
    if let Some(note) = state.note() {
        let used = (indent.chars().count() + 7 + title.chars().count() + 3) as u16;
        let room = width.saturating_sub(used + 2) as usize;
        if room > 8 {
            let note: String = if note.chars().count() > room {
                note.chars()
                    .take(room - 1)
                    .chain(std::iter::once('…'))
                    .collect()
            } else {
                note.to_string()
            };
            let note_color = if matches!(state, State::Blocked(_)) {
                Color::Yellow
            } else {
                Color::Gray
            };
            spans.push(Span::styled(
                format!(" — {note}"),
                Style::new().fg(note_color),
            ));
        }
    }
    ListItem::new(Line::from(spans))
}

/// Lines `text` takes when wrapped to `width` columns — close enough to what
/// `Paragraph` does to size a box around it.
fn wrapped_height(text: &str, width: u16) -> u16 {
    let width = usize::from(width.max(1));
    text.split('\n')
        .map(|line| {
            let n = line.chars().count();
            (n.max(1) + width - 1) / width
        })
        .sum::<usize>()
        .min(usize::from(u16::MAX)) as u16
}

fn first_screen() -> Screen {
    Screen::Main
}

enum Copied {
    Clipboard,
    Terminal,
}

/// Windows has a clipboard of its own to put the text on. Anywhere else this
/// may be a server with none, so the text goes to the terminal as OSC 52, which
/// a terminal that supports it copies on the machine the user sits at.
fn copy_out(text: &str) -> Copied {
    #[cfg(windows)]
    if crate::utils::set_clipboard_text(text) {
        return Copied::Clipboard;
    }
    let mut out = std::io::stdout();
    let _ = write!(out, "\x1b]52;c;{}\x07", base64(text.as_bytes()));
    let _ = out.flush();
    Copied::Terminal
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Windows: a console to draw in
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod console {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    extern "system" {
        fn AllocConsole() -> i32;
        fn AttachConsole(pid: u32) -> i32;
        fn FreeConsole() -> i32;
        fn SetStdHandle(which: u32, handle: *mut c_void) -> i32;
        fn SetConsoleTitleW(title: *const u16) -> i32;
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *mut c_void,
            disposition: u32,
            flags: u32,
            template: *mut c_void,
        ) -> *mut c_void;
    }

    const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;
    const STD_INPUT_HANDLE: u32 = (-10i32) as u32;
    const STD_OUTPUT_HANDLE: u32 = (-11i32) as u32;
    const STD_ERROR_HANDLE: u32 = (-12i32) as u32;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const OPEN_EXISTING: u32 = 3;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A console for the terminal UI.
    ///
    /// Its own window, normally: this is a GUI-subsystem exe, so the shell that
    /// started it has already gone back to its prompt, and sharing that console
    /// would hand every other keystroke to the shell.
    ///
    /// The console it was started from, when the caller says it waits
    /// (`--inline`: `tui.ps1` runs `Start-Process -Wait -NoNewWindow`, cmd
    /// `start /b /wait`), and over SSH, where there is no desktop for a window
    /// to appear on at all — there, too, the shell has to be told to wait.
    pub fn open() -> Result<(), String> {
        let over_ssh = std::env::var_os("SSH_CONNECTION").is_some()
            || std::env::var_os("SSH_CLIENT").is_some();
        let inline = over_ssh
            || std::env::args()
                .skip(1)
                .any(|a| a.trim_start_matches('-').eq_ignore_ascii_case("inline"));
        unsafe {
            let attached = inline && AttachConsole(ATTACH_PARENT_PROCESS) != 0;
            if !attached {
                FreeConsole();
                if AllocConsole() == 0 {
                    return Err("не удалось открыть консоль для терминального режима".into());
                }
            }
            // Whatever handles we inherited (none, for a GUI process, or a pipe
            // someone redirected) are pointed at this console: Rust's stdout
            // writes through WriteConsoleW when its handle is a console, which is
            // what keeps Cyrillic intact whatever the code page.
            for (which, name) in [
                (STD_INPUT_HANDLE, "CONIN$"),
                (STD_OUTPUT_HANDLE, "CONOUT$"),
                (STD_ERROR_HANDLE, "CONOUT$"),
            ] {
                let name = wide(name);
                let h = CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                );
                if !h.is_null() && h != (-1isize) as *mut c_void {
                    SetStdHandle(which, h);
                }
            }
            let title = wide("Antigravity Unlocker");
            SetConsoleTitleW(title.as_ptr());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard_alphabet_and_padding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64("ключ".as_bytes()), "0LrQu9GO0Yc=");
    }

    #[test]
    fn a_wrapped_line_counts_every_row_it_takes() {
        assert_eq!(wrapped_height("", 10), 1);
        assert_eq!(wrapped_height("abcdefghij", 10), 1);
        assert_eq!(wrapped_height("abcdefghijk", 10), 2);
        assert_eq!(wrapped_height("ab\ncd", 10), 2);
        // Cyrillic is one column per letter, not one per byte.
        assert_eq!(wrapped_height("ключключкл", 10), 1);
    }
}
