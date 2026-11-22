use crate::types::{DllInfo, OperationResult, Process};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use std::borrow::Cow;
use std::collections::{HashSet, VecDeque};
use std::sync::mpsc::{SyncSender, TrySendError};
use unicode_segmentation::UnicodeSegmentation;

pub enum Work {
    Discover,
    Validate(String),
    Inject(Box<Process>, String),
}
pub enum Message {
    Input(std::io::Result<Event>),
    Processes(Vec<Process>),
    Progress(String),
    Dll(String, DllInfo),
    Injection(String, OperationResult),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Operation {
    #[default]
    Idle,
    Discovering,
    Validating,
    Injecting,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitError {
    Busy,
    Disconnected,
    NotReady,
}
impl std::fmt::Display for SubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Busy => "Operation already in progress",
            Self::Disconnected => "Backend worker stopped",
            Self::NotReady => "Target or DLL is not ready for injection",
        })
    }
}
impl std::error::Error for SubmitError {}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum View {
    Main,
    Search,
    Path,
    Details,
    Diagnostics,
    Settings,
    Help,
    About,
    Confirm,
}
#[derive(Default)]
pub struct Editor {
    pub text: String,
    pub cursor: usize,
}
impl Editor {
    fn snap_cursor(&mut self) {
        self.cursor = self
            .text
            .grapheme_indices(true)
            .map(|(i, _)| i)
            .find(|&boundary| boundary >= self.cursor)
            .unwrap_or(self.text.len());
    }
    pub fn insert(&mut self, text: &str) {
        let clean =
            if text.chars().any(char::is_control) || text.chars().take(16385).count() > 16384 {
                Cow::Owned(
                    text.chars()
                        .filter(|c| !c.is_control())
                        .take(16384)
                        .collect::<String>(),
                )
            } else {
                Cow::Borrowed(text)
            };
        if self.text.len() + clean.len() <= 65536 {
            self.text.insert_str(self.cursor, &clean);
            self.cursor += clean.len();
            self.snap_cursor();
        }
    }
    pub fn key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char(c) => {
                let mut bytes = [0; 4];
                self.insert(c.encode_utf8(&mut bytes));
            }
            KeyCode::Left => {
                self.cursor = self.text[..self.cursor]
                    .grapheme_indices(true)
                    .next_back()
                    .map_or(0, |(i, _)| i);
            }
            KeyCode::Right => {
                if let Some(cluster) = self.text[self.cursor..].graphemes(true).next() {
                    self.cursor += cluster.len();
                }
            }
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.text.len(),
            KeyCode::Backspace if self.cursor > 0 => {
                let end = self.cursor;
                self.key(KeyCode::Left);
                self.text.drain(self.cursor..end);
                self.snap_cursor();
            }
            KeyCode::Delete => {
                if let Some(cluster) = self.text[self.cursor..].graphemes(true).next() {
                    self.text.drain(self.cursor..self.cursor + cluster.len());
                    self.snap_cursor();
                }
            }
            _ => {}
        }
    }
}
pub struct App {
    pub processes: Vec<Process>,
    pub visible: Vec<usize>,
    pub selected: usize,
    pub view: View,
    pub search: Editor,
    pub path: Editor,
    pub dll: DllInfo,
    pub validated_path: String,
    pub status: String,
    pub logs: VecDeque<String>,
    pub operation: Operation,
    pub show_wine: bool,
    pub ascii: bool,
    pub auto_refresh: bool,
    pub scroll: u16,
    pub quit: bool,
    pub uncertain: HashSet<String>,
}
impl Default for App {
    fn default() -> Self {
        Self {
            processes: Vec::new(),
            visible: Vec::new(),
            selected: 0,
            view: View::Main,
            search: Editor::default(),
            path: Editor::default(),
            dll: DllInfo::default(),
            validated_path: String::new(),
            status: "Scanning Wine / Proton processes...".into(),
            logs: VecDeque::new(),
            operation: Operation::Idle,
            show_wine: true,
            ascii: false,
            auto_refresh: false,
            scroll: 0,
            quit: false,
            uncertain: HashSet::new(),
        }
    }
}
impl App {
    pub fn busy(&self) -> bool {
        self.operation != Operation::Idle
    }
    pub fn target(&self) -> Option<&Process> {
        self.visible
            .get(self.selected)
            .and_then(|&i| self.processes.get(i))
    }
    pub fn filter(&mut self) {
        let previous = self.target().map(Process::identity);
        let query = self.search.text.to_lowercase();
        self.visible.clear();
        self.visible.extend(
            self.processes
                .iter()
                .enumerate()
                .filter(|(_, p)| {
                    (self.show_wine || p.runtime.packaging != "standard_wine")
                        && match query.as_str() {
                            "ready" => p.injectable && !self.uncertain.contains(&p.lifetime_key()),
                            "blocked" => {
                                !p.injectable || self.uncertain.contains(&p.lifetime_key())
                            }
                            _ => {
                                query.is_empty()
                                    || [
                                        &p.name,
                                        &p.runtime.packaging,
                                        &p.runtime.version,
                                        &p.architecture,
                                        &p.steam_app_id,
                                        &p.runtime.error_code,
                                    ]
                                    .iter()
                                    .any(|field| contains_folded(field, &query))
                                    || (query.bytes().all(|c| c.is_ascii_digit())
                                        && ((p.windows_pid != 0
                                            && p.windows_pid.to_string().contains(&query))
                                            || (p.linux_pid != 0
                                                && p.linux_pid.to_string().contains(&query))))
                            }
                        }
                })
                .map(|(i, _)| i),
        );
        self.selected = previous
            .and_then(|id| {
                self.visible
                    .iter()
                    .position(|&i| self.processes[i].identity() == id)
            })
            .unwrap_or(self.selected.min(self.visible.len().saturating_sub(1)));
    }
    pub fn log(&mut self, text: String) {
        if self.logs.len() == 500 {
            self.logs.pop_front();
        }
        self.logs.push_back(text.chars().take(8192).collect());
    }
    pub fn submit(&mut self, tx: &SyncSender<Work>, work: Work) -> Result<(), SubmitError> {
        if self.busy() {
            return Err(SubmitError::Busy);
        }
        let (operation, status) = match &work {
            Work::Discover => (
                Operation::Discovering,
                "Scanning Wine / Proton processes...",
            ),
            Work::Validate(_) => (Operation::Validating, "Validating DLL..."),
            Work::Inject(process, path) => {
                if self.view != View::Confirm
                    || !self.ready()
                    || self
                        .target()
                        .is_none_or(|p| p.identity() != process.identity())
                    || path != &self.validated_path
                {
                    return Err(SubmitError::NotReady);
                }
                (
                    Operation::Injecting,
                    "Injection in progress. Do not retry an unknown outcome.",
                )
            }
        };
        tx.try_send(work).map_err(|error| match error {
            TrySendError::Full(_) => SubmitError::Busy,
            TrySendError::Disconnected(_) => SubmitError::Disconnected,
        })?;
        self.operation = operation;
        self.status = status.into();
        Ok(())
    }
    pub fn ready(&self) -> bool {
        !self.busy()
            && self.dll.valid
            && self.validated_path == self.path.text
            && self.target().is_some_and(|p| {
                p.injectable
                    && p.architecture == self.dll.architecture
                    && !self.uncertain.contains(&p.lifetime_key())
            })
    }
    pub fn message(&mut self, message: Message, tx: &SyncSender<Work>) -> std::io::Result<()> {
        match message {
            Message::Progress(message) => {
                if self.operation == Operation::Discovering {
                    self.status = message;
                }
            }
            Message::Processes(rows) => {
                if self.operation != Operation::Discovering {
                    return Ok(());
                }
                let identity = self.target().map(Process::identity);
                self.processes = rows;
                self.filter();
                if let Some(id) = identity
                    && let Some(i) = self
                        .visible
                        .iter()
                        .position(|&i| self.processes[i].identity() == id)
                {
                    self.selected = i;
                }
                self.operation = Operation::Idle;
                self.status = format!("Discovery complete: {} processes", self.processes.len());
                self.log(self.status.clone());
            }
            Message::Dll(path, info) => {
                if self.operation != Operation::Validating {
                    return Ok(());
                }
                self.operation = Operation::Idle;
                if path == self.path.text {
                    self.status = if info.valid {
                        format!("Valid {} DLL", info.architecture)
                    } else {
                        info.error.clone()
                    };
                    self.validated_path = path;
                    self.dll = info;
                    self.log(self.status.clone());
                }
            }
            Message::Injection(key, result) => {
                if self.operation == Operation::Injecting {
                    self.operation = Operation::Idle;
                }
                if result.inconclusive {
                    self.uncertain.insert(key);
                    self.filter();
                }
                self.status = if result.inconclusive {
                    format!(
                        "Unknown outcome ({}): {}. Do not retry this process lifetime.",
                        result.error_code, result.message
                    )
                } else if result.success {
                    result.message
                } else {
                    format!("{}: {}", result.error_code, result.message)
                };
                self.log(self.status.clone());
            }
            Message::Input(event) => self.input(event?, tx),
        }
        Ok(())
    }
    pub fn input(&mut self, event: Event, tx: &SyncSender<Work>) {
        if let Event::Paste(text) = event {
            match self.view {
                View::Path => self.path.insert(&text),
                View::Search => {
                    self.search.insert(&text);
                    self.filter();
                }
                _ => {}
            }
            return;
        }
        let Event::Key(key) = event else {
            return;
        };
        if key.kind == KeyEventKind::Release {
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if self.view == View::Path || self.view == View::Search {
            match key.code {
                KeyCode::Esc => self.view = View::Main,
                KeyCode::Enter => {
                    if self.view == View::Path
                        && let Err(error) = self.submit(tx, Work::Validate(self.path.text.clone()))
                    {
                        self.status = error.to_string();
                        return;
                    }
                    self.view = View::Main;
                }
                _ if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    if self.view == View::Path {
                        self.path.key(key.code);
                    } else {
                        self.search.key(key.code);
                        self.filter();
                    }
                }
                _ => {}
            }
            return;
        }
        if self.view == View::Confirm {
            if key.code == KeyCode::Char('y') && self.ready() {
                if let Some(p) = self.target().cloned()
                    && let Err(error) =
                        self.submit(tx, Work::Inject(Box::new(p), self.path.text.clone()))
                {
                    self.status = error.to_string();
                    return;
                }
                self.view = View::Main;
                self.scroll = 0;
            } else if matches!(key.code, KeyCode::Esc | KeyCode::Char('n')) {
                self.view = View::Main;
                self.scroll = 0;
            }
            match key.code {
                KeyCode::Down => self.scroll = self.scroll.saturating_add(1),
                KeyCode::Up => self.scroll = self.scroll.saturating_sub(1),
                KeyCode::PageDown => self.scroll = self.scroll.saturating_add(10),
                KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
                _ => {}
            }
            return;
        }
        if self.view == View::Settings {
            match key.code {
                KeyCode::Char('w') => {
                    self.show_wine = !self.show_wine;
                    self.filter();
                }
                KeyCode::Char('a') => self.ascii = !self.ascii,
                KeyCode::Char('r') => self.auto_refresh = !self.auto_refresh,
                KeyCode::Esc | KeyCode::Char('q') => self.view = View::Main,
                _ => {}
            }
            return;
        }
        if self.view != View::Main {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.view = View::Main;
                    self.scroll = 0;
                }
                KeyCode::Down | KeyCode::Char('j') => self.scroll = self.scroll.saturating_add(1),
                KeyCode::Up | KeyCode::Char('k') => self.scroll = self.scroll.saturating_sub(1),
                KeyCode::PageDown => self.scroll = self.scroll.saturating_add(10),
                KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Down | KeyCode::Char('j') => self.selected = (self.selected+1).min(self.visible.len().saturating_sub(1)),
            KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
            KeyCode::PageDown => self.selected = (self.selected+10).min(self.visible.len().saturating_sub(1)),
            KeyCode::PageUp => self.selected = self.selected.saturating_sub(10),
            KeyCode::Char('/') => self.view = View::Search,
            KeyCode::Char('p') => self.view = View::Path,
            KeyCode::Char('r') => {
                if let Err(error) = self.submit(tx, Work::Discover) {
                    self.status = error.to_string();
                }
            }
            KeyCode::Char('d') => self.view = View::Details,
            KeyCode::Char('l') => self.view = View::Diagnostics,
            KeyCode::Char('s') => self.view = View::Settings,
            KeyCode::Char('?') => self.view = View::Help,
            KeyCode::Char('a') => self.view = View::About,
            KeyCode::Enter if self.ready() => self.view = View::Confirm,
            KeyCode::Enter => self.status = "Not ready: select a verified target and validate a compatible DLL (p); d for details".into(),
            _ => {}
        }
    }
}

fn contains_folded(text: &str, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    if text.is_ascii() && query.is_ascii() {
        text.as_bytes()
            .windows(query.len())
            .any(|part| part.eq_ignore_ascii_case(query.as_bytes()))
    } else {
        text.to_lowercase().contains(query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_editor_preserves_boundaries() {
        let mut e = Editor::default();
        e.insert("aé🦀z");
        e.key(KeyCode::Left);
        e.key(KeyCode::Backspace);
        assert_eq!(e.text, "aéz");
        e.key(KeyCode::Home);
        e.key(KeyCode::Delete);
        assert_eq!(e.text, "éz");
        e.key(KeyCode::Right);
        e.insert("ø");
        assert_eq!(e.text, "éøz");
    }
    #[test]
    fn editing_enter_never_injects() {
        let (tx, rx) = std::sync::mpsc::sync_channel(2);
        let mut app = App {
            view: View::Path,
            ..App::default()
        };
        app.input(
            Event::Key(crossterm::event::KeyEvent::new(
                KeyCode::Enter,
                KeyModifiers::NONE,
            )),
            &tx,
        );
        assert!(matches!(rx.try_recv(), Ok(Work::Validate(_))));
        assert!(rx.try_recv().is_err());
        assert!(app.view == View::Main);
    }
    #[test]
    fn unknown_outcome_blocks_retry_across_route_changes() {
        let (tx, _) = std::sync::mpsc::sync_channel(2);
        let mut app = App::default();
        let mut p = Process {
            windows_pid: 42,
            creation_time: "12345".into(),
            architecture: "x64".into(),
            injectable: true,
            ..Process::default()
        };
        p.runtime.prefix = "/private/prefix".into();
        let key = p.lifetime_key();
        app.path.insert("/test.dll");
        app.validated_path = app.path.text.clone();
        app.dll = DllInfo {
            valid: true,
            architecture: "x64".into(),
            error: String::new(),
        };
        app.operation = Operation::Discovering;
        app.message(Message::Processes(vec![p.clone()]), &tx)
            .unwrap();
        assert!(app.ready());
        app.message(
            Message::Injection(
                key,
                OperationResult {
                    inconclusive: true,
                    ..OperationResult::default()
                },
            ),
            &tx,
        )
        .unwrap();
        p.runtime.strategy = "app_launcher".into();
        p.runtime.namespace_key = "replacement-observation".into();
        app.operation = Operation::Discovering;
        app.message(Message::Processes(vec![p.clone()]), &tx)
            .unwrap();
        assert!(!app.ready());
        p.creation_time = "12346".into();
        app.operation = Operation::Discovering;
        app.message(Message::Processes(vec![p]), &tx).unwrap();
        assert!(app.ready());
    }
    #[test]
    fn stale_validation_cannot_authorize_edited_path() {
        let (tx, _) = std::sync::mpsc::sync_channel(2);
        let mut app = App::default();
        app.path.insert("/new.dll");
        app.operation = Operation::Validating;
        app.message(
            Message::Dll(
                "/old.dll".into(),
                DllInfo {
                    valid: true,
                    architecture: "x64".into(),
                    error: String::new(),
                },
            ),
            &tx,
        )
        .unwrap();
        assert!(!app.dll.valid);
        assert!(app.validated_path.is_empty());
    }
    use crossterm::event::KeyEvent;

    fn key(code: KeyCode) -> Event {
        Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }
    fn ready_app() -> App {
        let process = Process {
            name: "fixture.exe".into(),
            windows_pid: 42,
            creation_time: "12345".into(),
            image_path: "C:\\fixture.exe".into(),
            architecture: "x64".into(),
            injectable: true,
            ..Default::default()
        };
        let mut app = App {
            processes: vec![process],
            visible: vec![0],
            dll: DllInfo {
                valid: true,
                architecture: "x64".into(),
                error: String::new(),
            },
            validated_path: "/fixture.dll".into(),
            ..App::default()
        };
        app.path.insert("/fixture.dll");
        app
    }
    #[test]
    fn failed_confirmation_submission_preserves_error_and_does_not_inject() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        tx.send(Work::Discover).unwrap();
        let mut app = ready_app();
        app.view = View::Confirm;
        app.input(key(KeyCode::Char('y')), &tx);
        assert_eq!(app.operation, Operation::Idle);
        assert!(app.view == View::Confirm);
        assert_eq!(app.status, SubmitError::Busy.to_string());
        assert!(matches!(rx.try_recv(), Ok(Work::Discover)));
        assert!(rx.try_recv().is_err());
        drop(rx);
        app.input(key(KeyCode::Char('y')), &tx);
        assert_eq!(app.status, SubmitError::Disconnected.to_string());
        assert_eq!(app.operation, Operation::Idle);
    }
    #[test]
    fn confirmation_is_required_and_only_y_submits_exact_target() {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let mut app = ready_app();
        assert_eq!(
            app.submit(
                &tx,
                Work::Inject(
                    Box::new(app.target().unwrap().clone()),
                    app.path.text.clone()
                )
            ),
            Err(SubmitError::NotReady)
        );
        app.input(key(KeyCode::Enter), &tx);
        assert!(app.view == View::Confirm);
        assert!(rx.try_recv().is_err());
        app.input(key(KeyCode::Enter), &tx);
        assert!(rx.try_recv().is_err());
        app.input(key(KeyCode::Char('y')), &tx);
        match rx.try_recv().unwrap() {
            Work::Inject(process, path) => {
                assert_eq!(process.windows_pid, 42);
                assert_eq!(path, "/fixture.dll");
            }
            _ => panic!("Expected explicitly confirmed injection"),
        }
        assert_eq!(app.operation, Operation::Injecting);
        app.input(key(KeyCode::Char('r')), &tx);
        assert!(rx.try_recv().is_err());
        assert_eq!(app.operation, Operation::Injecting);
    }
    #[test]
    fn stale_noninjection_messages_do_not_clear_active_injection() {
        let (tx, _) = std::sync::mpsc::sync_channel(1);
        let mut app = ready_app();
        app.operation = Operation::Injecting;
        app.message(Message::Processes(Vec::new()), &tx).unwrap();
        app.message(Message::Dll(app.path.text.clone(), DllInfo::default()), &tx)
            .unwrap();
        assert_eq!(app.operation, Operation::Injecting);
        assert_eq!(app.target().unwrap().windows_pid, 42);
        assert!(app.dll.valid);
    }
    #[test]
    fn editor_deletes_graphemes_and_handles_joining_insertions() {
        let mut editor = Editor::default();
        editor.insert("e\u{301}👩‍💻🇫🇷");
        editor.key(KeyCode::Left);
        editor.key(KeyCode::Backspace);
        assert_eq!(editor.text, "e\u{301}🇫🇷");
        editor.key(KeyCode::Home);
        editor.key(KeyCode::Delete);
        assert_eq!(editor.text, "🇫🇷");
        editor.key(KeyCode::Delete);
        assert_eq!(editor.text, "");
        editor.insert("\u{301}x");
        editor.key(KeyCode::Home);
        editor.insert("");
        assert_eq!(editor.cursor, 0);
        editor.insert("e");
        assert_eq!(editor.cursor, "e\u{301}".len());
        editor.key(KeyCode::Backspace);
        assert_eq!(editor.text, "x");
    }
    #[test]
    fn filters_preserve_selection_and_expose_architecture_readiness_and_unicode() {
        let mut app = ready_app();
        app.processes.push(Process {
            name: "Pokémon.exe".into(),
            windows_pid: 43,
            architecture: "x64".into(),
            ..Process::default()
        });
        app.filter();
        app.selected = 1;
        app.search.insert("X64");
        app.filter();
        assert_eq!(app.target().unwrap().windows_pid, 43);
        app.search = Editor::default();
        app.search.insert("POKÉ");
        app.filter();
        assert_eq!(app.target().unwrap().windows_pid, 43);
        app.search = Editor::default();
        app.search.insert("ready");
        app.filter();
        assert_eq!(app.target().unwrap().windows_pid, 42);
        app.uncertain.insert(app.target().unwrap().lifetime_key());
        app.filter();
        assert!(app.visible.is_empty());
        app.search = Editor::default();
        app.search.insert("blocked");
        app.filter();
        assert_eq!(app.visible.len(), 2);
    }
    #[test]
    fn readiness_filters_are_exclusive_even_when_metadata_contains_the_keyword() {
        let mut app = ready_app();
        app.processes[0].name = "blocked.exe".into();
        app.processes.push(Process {
            name: "already-ready.exe".into(),
            windows_pid: 43,
            runtime: crate::types::Runtime {
                error_code: "already_loaded".into(),
                ..Default::default()
            },
            ..Default::default()
        });
        app.search.insert("READY");
        app.filter();
        assert_eq!(app.visible, vec![0]);
        app.search = Editor::default();
        app.search.insert("blocked");
        app.filter();
        assert_eq!(app.visible, vec![1]);
    }
    #[test]
    fn inconclusive_result_immediately_updates_readiness_filter() {
        let (tx, _) = std::sync::mpsc::sync_channel(1);
        let mut app = ready_app();
        app.search.insert("ready");
        app.filter();
        let lifetime = app.target().unwrap().lifetime_key();
        app.operation = Operation::Injecting;
        app.message(
            Message::Injection(
                lifetime,
                OperationResult {
                    inconclusive: true,
                    error_code: "helper_timeout".into(),
                    ..Default::default()
                },
            ),
            &tx,
        )
        .unwrap();
        assert!(app.visible.is_empty());
        assert!(!app.ready());
        app.search = Editor::default();
        app.search.insert("blocked");
        app.filter();
        assert_eq!(app.target().unwrap().windows_pid, 42);
    }
    #[test]
    fn standalone_wine_is_visible_without_changing_settings() {
        let (tx, _) = std::sync::mpsc::sync_channel(1);
        let mut app = ready_app();
        app.processes[0].runtime.packaging = "standard_wine".into();
        app.filter();
        assert_eq!(app.target().unwrap().windows_pid, 42);
        app.view = View::Settings;
        app.input(key(KeyCode::Char('w')), &tx);
        assert!(app.target().is_none());
    }
    #[test]
    fn progress_never_overwrites_an_injection_outcome_or_enables_work() {
        let (tx, _) = std::sync::mpsc::sync_channel(1);
        let mut app = ready_app();
        app.operation = Operation::Discovering;
        app.message(Message::Progress("Inspecting runtime".into()), &tx)
            .unwrap();
        assert_eq!(app.operation, Operation::Discovering);
        assert!(!app.ready());
        app.operation = Operation::Injecting;
        let status = app.status.clone();
        app.message(Message::Progress("Stale discovery progress".into()), &tx)
            .unwrap();
        assert_eq!(app.operation, Operation::Injecting);
        assert_eq!(app.status, status);
        app.operation = Operation::Idle;
        app.status = "Injection verified".into();
        app.message(Message::Progress("Stale discovery progress".into()), &tx)
            .unwrap();
        assert_eq!(app.status, "Injection verified");
    }
}
