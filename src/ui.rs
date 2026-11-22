use crate::app::{App, Editor, View};
use crate::types::Process;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap},
};
use std::fmt::Write;
use unicode_segmentation::UnicodeSegmentation;

const MUTED: Color = Color::Rgb(140, 151, 164);
const ACCENT: Color = Color::Rgb(98, 190, 215);
const READY_COLOR: Color = Color::Rgb(112, 188, 149);
const UNKNOWN_COLOR: Color = Color::Rgb(218, 171, 95);
fn block<'a>(title: &'a str, ascii: bool) -> Block<'a> {
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Rgb(63, 78, 92)));
    if ascii {
        block.border_set(ratatui::symbols::border::Set {
            top_left: "+",
            top_right: "+",
            bottom_left: "+",
            bottom_right: "+",
            vertical_left: "|",
            vertical_right: "|",
            horizontal_top: "-",
            horizontal_bottom: "-",
        })
    } else {
        block
    }
}
fn editor(frame: &mut Frame, area: Rect, input: &Editor, title: &str, ascii: bool) {
    let width = area.width.saturating_sub(3) as usize;
    let before = &input.text[..input.cursor];
    let mut start = input.cursor;
    let mut caret = 0;
    for (index, cluster) in before.grapheme_indices(true).rev() {
        let cell_width = Span::raw(cluster).width();
        if caret + cell_width > width {
            break;
        }
        start = index;
        caret += cell_width;
    }
    frame.render_widget(
        Paragraph::new(&input.text[start..])
            .block(block(title, ascii))
            .style(Style::default().fg(ACCENT)),
        area,
    );
    if area.width > 2 && area.height > 1 {
        frame.set_cursor_position((area.x + 1 + (caret as u16).min(area.width - 2), area.y + 1));
    }
}

fn target_status<'a>(app: &App, process: &'a Process) -> (&'a str, Color) {
    if app.uncertain.contains(&process.lifetime_key()) {
        ("UNKNOWN: no retry", UNKNOWN_COLOR)
    } else if process.injectable {
        ("Ready", READY_COLOR)
    } else if !process.runtime.error_code.is_empty() {
        (&process.runtime.error_code, MUTED)
    } else {
        ("Not verified", MUTED)
    }
}

fn route_diagnostics(process: &Process) -> String {
    let mut text = String::new();
    let runtime = &process.runtime;
    if !runtime.error_code.is_empty() || !runtime.error.is_empty() {
        let _ = writeln!(text, "{}: {}", runtime.error_code, runtime.error);
    }
    for route in &runtime.route_probes {
        let code = if !route.code.is_empty() {
            route.code.as_str()
        } else if route.available {
            "available"
        } else {
            "unavailable"
        };
        let _ = writeln!(text, "{}: {}", route.strategy, code);
        if !route.message.is_empty() {
            let _ = writeln!(text, "  {}", route.message);
        }
    }
    if text.is_empty() {
        text.push_str("No route diagnostics available.\n");
    }
    text
}

fn process_details(app: &App) -> String {
    let Some(process) = app.target() else {
        return "No target selected".into();
    };
    let runtime = &process.runtime;
    let mut text = format!(
        "Name: {}\nWindows PID: {}\nLinux PID: {}\nLinux start ticks: {}\nWindows creation FILETIME: {}\n",
        process.name,
        process.windows_pid,
        process.linux_pid,
        process.host_start_ticks,
        process.creation_time
    );
    for (label, value) in [
        ("Image", process.image_path.as_str()),
        ("Architecture", &process.architecture),
        ("Steam AppID", &process.steam_app_id),
        ("Packaging", &runtime.packaging),
        ("Version", &runtime.version),
        ("Wine prefix", &runtime.prefix),
        ("Wine loader", &runtime.wine_binary),
        ("Proton", &runtime.proton_path),
        ("Execution", &runtime.strategy),
        ("Namespaces", &runtime.namespace_key),
        ("Detection", &process.detection),
    ] {
        let _ = writeln!(text, "{label}: {value}");
    }
    let _ = writeln!(
        text,
        "Anchor: {} / {}",
        runtime.anchor_pid, runtime.start_ticks
    );
    let _ = writeln!(
        text,
        "Service: {} / {}",
        runtime.service_bus, runtime.service_owner
    );
    let _ = writeln!(text, "Status: {}\n\nRoutes:", target_status(app, process).0);
    text.push_str(&route_diagnostics(process));
    text
}

fn diagnostics(app: &App) -> String {
    let mut text = String::new();
    if let Some(process) = app.target() {
        let _ = writeln!(
            text,
            "{} (Windows PID {}, Linux PID {})",
            process.name, process.windows_pid, process.linux_pid
        );
        text.push_str(&route_diagnostics(process));
    }
    if !app.logs.is_empty() {
        text.push_str("\nRecent operations:\n");
        for entry in &app.logs {
            let _ = writeln!(text, "{entry}");
        }
    }
    if text.is_empty() {
        text.push_str("No diagnostics yet.");
    }
    text
}
pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(
            Style::default()
                .bg(Color::Rgb(17, 22, 28))
                .fg(Color::Rgb(222, 230, 237)),
        ),
        area,
    );
    if area.width < 35 || area.height < 16 {
        frame.render_widget(
            Paragraph::new(format!(
                "ProtonNeedle {}\nResize terminal to at least 35 × 16\nCtrl-C Quit",
                env!("CARGO_PKG_VERSION")
            ))
            .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    let rows = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(3),
        Constraint::Min(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(2),
    ])
    .split(area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    " ProtonNeedle ",
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    concat!(env!("CARGO_PKG_VERSION"), "  /  Wine & Proton DLL loader"),
                    Style::default().fg(MUTED),
                ),
            ]),
            Line::from(Span::styled(
                " Explicit loading into already-running applications",
                Style::default().fg(MUTED),
            )),
        ]),
        rows[0],
    );
    if app.view == View::Search {
        editor(
            frame,
            rows[1],
            &app.search,
            " / Search | Enter done | Esc close ",
            app.ascii,
        );
    } else {
        frame.render_widget(
            Paragraph::new(format!(
                "{}{}",
                if app.search.text.is_empty() {
                    "/ Search processes"
                } else {
                    "Filter: "
                },
                app.search.text
            ))
            .block(block(" Processes ", app.ascii))
            .style(Style::default().fg(MUTED)),
            rows[1],
        );
    }
    let compact = area.width < 75;
    let table_rows = app.visible.iter().map(|&i| {
        let p = &app.processes[i];
        let pid = if p.windows_pid == 0 {
            format!("L{}", p.linux_pid)
        } else {
            p.windows_pid.to_string()
        };
        let (status, color) = target_status(app, p);
        if compact {
            Row::new(vec![
                Cell::from(p.name.as_str()),
                Cell::from(pid),
                Cell::from(status).style(Style::default().fg(color)),
            ])
        } else {
            Row::new(vec![
                Cell::from(p.name.as_str()),
                Cell::from(pid),
                Cell::from(p.runtime.packaging.as_str()),
                Cell::from(status).style(Style::default().fg(color)),
            ])
        }
    });
    let widths = if compact {
        vec![
            Constraint::Percentage(45),
            Constraint::Length(9),
            Constraint::Min(10),
        ]
    } else {
        vec![
            Constraint::Percentage(30),
            Constraint::Length(10),
            Constraint::Percentage(23),
            Constraint::Min(15),
        ]
    };
    let header = if compact {
        vec!["PROCESS", "PID", "STATUS"]
    } else {
        vec!["PROCESS", "PID", "RUNTIME", "STATUS"]
    };
    let table = Table::new(table_rows, widths)
        .header(Row::new(header).style(Style::default().fg(MUTED)))
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(30, 53, 67))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    let mut state = TableState::default().with_selected(if app.visible.is_empty() {
        None
    } else {
        Some(app.selected)
    });
    frame.render_stateful_widget(table, rows[2], &mut state);
    let target = app.target().map_or_else(
        || "No target selected. r Refresh, l Diagnostics".into(),
        |p| {
            format!(
                "{}  |  {}  |  AppID {}  |  {}",
                p.name,
                p.architecture,
                if p.steam_app_id.is_empty() {
                    "none"
                } else {
                    &p.steam_app_id
                },
                p.runtime.strategy
            )
        },
    );
    frame.render_widget(
        Paragraph::new(target).block(block(" Target | d Details ", app.ascii)),
        rows[3],
    );
    if app.view == View::Path {
        editor(
            frame,
            rows[4],
            &app.path,
            " DLL | Enter validate | Esc close ",
            app.ascii,
        );
    } else {
        frame.render_widget(
            Paragraph::new(if app.path.text.is_empty() {
                "p  Enter DLL path"
            } else {
                &app.path.text
            })
            .block(block(" DLL ", app.ascii)),
            rows[4],
        );
    }
    let footer = vec![
        Line::from(Span::styled(
            "Enter Inject  / Search  r Refresh  p DLL  d Details  l Logs  s Settings  ? Help  q Quit",
            Style::default().fg(MUTED),
        )),
        Line::from(format!(
            "{}{}",
            if app.busy() { "[working] " } else { "" },
            app.status
        )),
    ];
    frame.render_widget(Paragraph::new(footer), rows[5]);
    if matches!(app.view, View::Main | View::Search | View::Path) {
        return;
    }
    let modal = Rect::new(
        area.x + 2,
        area.y + 2,
        area.width.saturating_sub(4),
        area.height.saturating_sub(4),
    );
    frame.render_widget(Clear, modal);
    let (title, text) = match app.view {
        View::Details => (
            " Target details | Up/Down scroll | Esc close ",
            process_details(app),
        ),
        View::Diagnostics => (
            " Diagnostics | Up/Down scroll | Esc close ",
            diagnostics(app),
        ),
        View::Settings => (
            " Settings | session only | Esc close ",
            format!(
                "w  Show standalone Wine: {}\na  ASCII borders: {}\nr  Auto-refresh (10 seconds): {}\n\n\
             Only borders change. Unicode text is unchanged.\n\
             Refresh never injects. Press d for runtime details.",
                app.show_wine, app.ascii, app.auto_refresh
            ),
        ),
        View::Help => (
            " Keyboard help | Esc close ",
            concat!(
                "Up/Down or j/k  Select process\n",
                "PageUp/PageDown  Scroll selection or details\n",
                "/  Search name, PID, runtime, AppID, architecture, ready or blocked\n",
                "r  Refresh\np  Edit DLL path. Paste supported\n",
                "Home/End/Left/Right/Backspace/Delete  Edit input\n",
                "Enter in path editor  Validate DLL only\n",
                "Enter in process list  Open injection confirmation\n",
                "y in confirmation  Authorize injection\n",
                "d  Target and runtime details\nl  Diagnostics\ns  Settings\na  About\n",
                "q or Ctrl-C  Quit\nEsc  Close panel or input\n\n",
                "L-prefixed PIDs are Linux observations, not Windows identities.\n",
                "Unknown outcomes block retries for that target lifetime."
            )
            .into(),
        ),
        View::About => (
            " About | Esc close ",
            concat!(
                "ProtonNeedle ",
                env!("CARGO_PKG_VERSION"),
                "\n",
                "Linux Wine / Proton DLL loader\nMIT license (see LICENSE)\n\n",
                "Linux frontend: Rust, Ratatui and Crossterm.\n",
                "Windows helper: C++.\n",
                "Load only trusted DLLs into applications you control.\n",
                "No anti-cheat bypass, game launching or automatic injection."
            )
            .into(),
        ),
        View::Confirm => (
            " Confirm injection | Up/Down scroll ",
            app.target().map_or_else(
                || "No verified target selected".into(),
                |process| {
                    let mut text = format!(
                        "y Authorize loading | n / Esc Cancel\nWindows PID: {} | {} DLL\n",
                        process.windows_pid, app.dll.architecture
                    );
                    let _ = writeln!(
                        text,
                        "Runtime: {} / {}",
                        process.runtime.packaging, process.runtime.strategy
                    );
                    let _ = writeln!(text, "Target: {}", process.name);
                    text.push_str(
                        "Identity and DLL validated. Both are rechecked before loading.\n",
                    );
                    let _ = writeln!(text, "DLL: {}", app.path.text);
                    text.push_str("\nUnknown outcomes block further attempts for this lifetime.");
                    text
                },
            ),
        ),
        _ => unreachable!(),
    };
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .scroll((app.scroll, 0))
            .block(block(title, app.ascii))
            .style(
                Style::default()
                    .fg(Color::Rgb(222, 230, 237))
                    .bg(Color::Rgb(17, 22, 28)),
            ),
        modal,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};
    #[test]
    fn long_unicode_input_keeps_cursor_inside_editor() {
        let mut app = App {
            view: View::Path,
            ..App::default()
        };
        app.path
            .insert(&format!("/tmp/{}/mod.dll", "漢字".repeat(80)));
        let mut terminal = Terminal::new(TestBackend::new(50, 20)).unwrap();
        let frame = terminal.draw(|frame| draw(frame, &app)).unwrap();
        let text = frame
            .buffer
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("mod.dll"));
        assert!(text.contains("Enter validate"));
    }
    #[test]
    fn details_preserve_full_identity_and_scroll() {
        let mut app = App {
            view: View::Details,
            ..App::default()
        };
        app.processes.push(crate::types::Process {
            name: "fixture.exe".into(),
            windows_pid: 912,
            linux_pid: 0,
            creation_time: "134000123456789000".into(),
            ..Default::default()
        });
        app.filter();
        let mut terminal = Terminal::new(TestBackend::new(100, 32)).unwrap();
        let frame = terminal.draw(|frame| draw(frame, &app)).unwrap();
        let text = frame
            .buffer
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("Windows PID: 912"));
        assert!(text.contains("134000123456789000"));
        app.scroll = 4;
        let frame = terminal.draw(|frame| draw(frame, &app)).unwrap();
        let text = frame
            .buffer
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(!text.contains("Windows PID: 912"));
        assert!(text.contains("134000123456789000"));
    }
    #[test]
    fn confirmation_disambiguates_windows_pid_from_host_pid() {
        let mut app = App {
            view: View::Confirm,
            ..App::default()
        };
        app.processes.push(crate::types::Process {
            name: "same-name.exe".into(),
            windows_pid: 912,
            linux_pid: 731,
            ..Default::default()
        });
        app.dll.architecture = "x64".into();
        app.filter();
        let mut terminal = Terminal::new(TestBackend::new(100, 28)).unwrap();
        let frame = terminal.draw(|frame| draw(frame, &app)).unwrap();
        let text: String = frame
            .buffer
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("Windows PID: 912"));
        assert!(!text.contains("Windows PID: 731"));
        assert!(text.contains("x64 DLL"));
    }
    #[test]
    fn unknown_outcome_is_not_green_or_ready() {
        let mut app = App::default();
        app.processes.push(Process {
            name: "fixture.exe".into(),
            windows_pid: 42,
            creation_time: "12345".into(),
            architecture: "x64".into(),
            injectable: true,
            ..Default::default()
        });
        app.filter();
        app.path.insert("/fixture.dll");
        app.validated_path = app.path.text.clone();
        app.dll = crate::types::DllInfo {
            valid: true,
            architecture: "x64".into(),
            error: String::new(),
        };
        assert!(app.ready());
        app.uncertain.insert(app.target().unwrap().lifetime_key());
        assert!(!app.ready());
        let mut terminal = Terminal::new(TestBackend::new(110, 24)).unwrap();
        let frame = terminal.draw(|frame| draw(frame, &app)).unwrap();
        let row = frame
            .buffer
            .content
            .chunks(110)
            .find(|row| {
                row.iter()
                    .map(|cell| cell.symbol())
                    .collect::<String>()
                    .contains("UNKNOWN: no retry")
            })
            .unwrap();
        let cell = row.iter().find(|cell| cell.symbol() == "U").unwrap();
        assert_eq!(cell.fg, UNKNOWN_COLOR);
        assert_ne!(cell.fg, READY_COLOR);
    }
    #[test]
    fn diagnostics_expose_failures_from_each_route() {
        let mut app = App {
            view: View::Diagnostics,
            ..App::default()
        };
        app.processes.push(Process {
            name: "fixture.exe".into(),
            runtime: crate::types::Runtime {
                route_probes: vec![
                    crate::types::RouteProbe {
                        strategy: "direct_wine".into(),
                        code: "prefix_mismatch".into(),
                        message: "Wine prefix object changed".into(),
                        ..Default::default()
                    },
                    crate::types::RouteProbe {
                        strategy: "app_launcher".into(),
                        code: "owner_changed".into(),
                        message: "Launcher service owner changed".into(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
            ..Default::default()
        });
        app.filter();
        let mut terminal = Terminal::new(TestBackend::new(100, 28)).unwrap();
        let frame = terminal.draw(|frame| draw(frame, &app)).unwrap();
        let text: String = frame
            .buffer
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("prefix_mismatch"));
        assert!(text.contains("Wine prefix object changed"));
        assert!(text.contains("owner_changed"));
        assert!(text.contains("Launcher service owner changed"));
    }
}
