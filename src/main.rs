#![forbid(unsafe_code)]
#[cfg(not(target_os = "linux"))]
compile_error!("ProtonNeedle supports Linux only");
mod app;
mod discovery;
mod helper;
mod runtime;
mod steam;
mod types;
mod ui;

use app::{App, Message, Work};
use crossterm::{
    event::{self, DisableBracketedPaste, EnableBracketedPaste},
    execute,
};
use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const EVENT_CAPACITY: usize = 64;

struct PasteGuard;
impl Drop for PasteGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), DisableBracketedPaste);
    }
}
fn main() -> io::Result<()> {
    let mut arguments = std::env::args().skip(1);
    let option = arguments.next();
    if arguments.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Use one option. See --help",
        ));
    }
    let passive = option.as_deref() == Some("--passive");
    match option.as_deref() {
        Some("--version") => {
            println!("ProtonNeedle {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("--help") => {
            println!(
                "proton-needle [--passive | --list | --version | --help]\nNo arguments: interactive TUI. --passive: TUI without helper/service calls. --list: passive Linux observations."
            );
            return Ok(());
        }
        Some("--passive") => {}
        Some("--list") => {
            for p in discovery::inspect_processes() {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    p.linux_pid, p.name, p.runtime.packaging, p.runtime.prefix, p.runtime.error
                );
            }
            return Ok(());
        }
        Some(other) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unknown argument: {other}"),
            ));
        }
        None => {}
    }
    ratatui::run(|terminal| -> io::Result<()> {
        execute!(io::stdout(), EnableBracketedPaste)?;
        let _paste = PasteGuard;
        let mut app = App::default();
        terminal.draw(|frame| ui::draw(frame, &app))?;
        let (tx, rx) = mpsc::sync_channel(EVENT_CAPACITY);
        let input_tx = tx.clone();
        thread::Builder::new()
            .name("terminal-input".into())
            .spawn(move || {
                loop {
                    let event = event::read();
                    let failed = event.is_err();
                    if input_tx.send(Message::Input(event)).is_err() || failed {
                        break;
                    }
                }
            })?;
        let (work_tx, work_rx) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let worker = thread::Builder::new()
            .name("runtime-worker".into())
            .spawn(move || {
                while let Ok(work) = work_rx.recv() {
                    let result = match work {
                        Work::Discover => {
                            let progress = |text: &str| {
                                let _ = tx.try_send(Message::Progress(text.into()));
                            };
                            Message::Processes(if passive {
                                discovery::inspect_processes_cancelled(&worker_cancelled, progress)
                            } else {
                                discovery::discover_processes_cancelled(&worker_cancelled, progress)
                            })
                        }
                        Work::Validate(path) => {
                            let dll = helper::validate_dll(&path);
                            Message::Dll(path, dll)
                        }
                        Work::Inject(process, path) => {
                            let key = process.lifetime_key();
                            Message::Injection(key, helper::inject_dll(&process, &path))
                        }
                    };
                    if tx.send(result).is_err() {
                        break;
                    }
                }
            })?;
        app.submit(&work_tx, Work::Discover)
            .map_err(io::Error::other)?;
        let mut refresh = Instant::now();
        let result = (|| {
            loop {
                let wait = if app.auto_refresh {
                    Duration::from_secs(10).saturating_sub(refresh.elapsed())
                } else {
                    Duration::from_secs(86400)
                };
                match rx.recv_timeout(wait) {
                    Ok(message) => app.message(message, &work_tx)?,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(io::Error::other("Application event channel stopped"));
                    }
                }
                if app.auto_refresh && refresh.elapsed() >= Duration::from_secs(10) {
                    if !app.busy()
                        && app.view == app::View::Main
                        && let Err(error) = app.submit(&work_tx, Work::Discover)
                    {
                        app.status = error.to_string();
                    }
                    refresh = Instant::now();
                }
                if app.quit {
                    break;
                }
                terminal.draw(|frame| ui::draw(frame, &app))?;
            }
            Ok(())
        })();
        // Discovery can stop between probes. Injection must finish.
        cancelled.store(true, Ordering::Relaxed);
        drop(work_tx);
        ratatui::restore();
        if !worker.is_finished() {
            let _ = writeln!(
                io::stderr(),
                "{}",
                match app.operation {
                    app::Operation::Injecting =>
                        "Waiting for the injection outcome. Do not retry this process lifetime.",
                    app::Operation::Discovering =>
                        "Cancelling discovery. Waiting for the current bounded probe to finish.",
                    app::Operation::Validating => "Waiting for DLL validation to finish.",
                    app::Operation::Idle => "Waiting for the backend worker to stop.",
                }
            );
        }
        while !worker.is_finished() {
            if let Ok(message) = rx.recv_timeout(Duration::from_millis(100)) {
                report_shutdown_result(message);
            }
        }
        for message in rx.try_iter().take(EVENT_CAPACITY) {
            report_shutdown_result(message);
        }
        drop(rx);
        if worker.join().is_err() {
            return Err(io::Error::other("Backend worker panicked"));
        }
        result
    })
}

fn report_shutdown_result(message: Message) {
    if let Message::Injection(_, result) = message {
        if result.inconclusive {
            let _ = writeln!(
                io::stderr(),
                "Unknown outcome ({}): {}. Do not retry this process lifetime.",
                result.error_code.escape_debug(),
                result.message.escape_debug()
            );
        } else if result.success {
            let _ = writeln!(io::stderr(), "{}", result.message.escape_debug());
        } else {
            let _ = writeln!(
                io::stderr(),
                "Injection failed ({}): {}",
                result.error_code.escape_debug(),
                result.message.escape_debug()
            );
        }
    }
}
