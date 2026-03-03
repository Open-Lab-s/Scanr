use std::collections::{HashMap, HashSet};
use std::io;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap};
use ratatui::{Frame, Terminal};

const FRAME_TIME: Duration = Duration::from_millis(33);

pub enum AppMode {
    Overview,
    Dependencies,
    Recommendations,
}

#[derive(Clone, Copy)]
enum Focus {
    Severity,
    Content,
}

enum ScanStatus {
    Idle,
    Scanning,
    Completed,
    Failed(String),
}

pub struct AppState {
    pub mode: AppMode,
    pub selected_index: usize,
    pub scan_result: scanr_sca::ScanResult,
    has_scan_data: bool,
    selected_severity: usize,
    focus: Focus,
    show_details: bool,
    should_quit: bool,
    project_path: PathBuf,
    scan_status: ScanStatus,
    spinner_index: usize,
    scan_receiver: Option<Receiver<Result<scanr_sca::ScanResult, String>>>,
}

impl AppState {
    fn new(project_path: PathBuf) -> Self {
        let resolved =
            std::fs::canonicalize(&project_path).unwrap_or_else(|_| project_path.clone());
        let display_path = normalize_windows_verbatim_path(resolved.display().to_string());
        let target = resolved
            .file_name()
            .and_then(|name| name.to_str())
            .map(ToString::to_string)
            .unwrap_or_else(|| display_path.clone());

        let empty_result = scanr_sca::ScanResult {
            target,
            path: display_path,
            total_dependencies: 0,
            dependencies: Vec::new(),
            vulnerabilities: Vec::new(),
            upgrade_recommendations: Vec::new(),
            risk_score: 0,
            severity_summary: scanr_sca::SeveritySummary::default(),
            risk_level: scanr_sca::RiskLevel::Low,
            queried_dependencies: 0,
            failed_queries: 0,
            offline_missing: 0,
            lookup_error: None,
            cache_events: Vec::new(),
        };

        Self {
            mode: AppMode::Overview,
            selected_index: 0,
            scan_result: empty_result,
            has_scan_data: false,
            selected_severity: 0,
            focus: Focus::Content,
            show_details: false,
            should_quit: false,
            project_path,
            scan_status: ScanStatus::Idle,
            spinner_index: 0,
            scan_receiver: None,
        }
    }

    fn row_count(&self) -> usize {
        if !self.has_scan_data {
            return 0;
        }
        match self.mode {
            AppMode::Overview => self.top_vulnerability_indices().len(),
            AppMode::Dependencies => self.scan_result.dependencies.len(),
            AppMode::Recommendations => self.scan_result.upgrade_recommendations.len(),
        }
    }

    fn clamp_selection(&mut self) {
        let count = self.row_count();
        if count == 0 {
            self.selected_index = 0;
            self.show_details = false;
            return;
        }
        if self.selected_index >= count {
            self.selected_index = count - 1;
        }
    }

    fn start_scan(&mut self) {
        if self.scan_receiver.is_some() {
            return;
        }

        let path = self.project_path.clone();
        let (tx, rx) = mpsc::channel::<Result<scanr_sca::ScanResult, String>>();
        self.scan_receiver = Some(rx);
        self.scan_status = ScanStatus::Scanning;
        self.spinner_index = 0;
        self.show_details = false;

        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            let result = match runtime {
                Ok(runtime) => {
                    let engine = scanr_sca::ScaEngine::new();
                    runtime
                        .block_on(engine.scan_detailed(&path))
                        .map_err(|error| error.to_string())
                }
                Err(error) => Err(format!("runtime initialization failed: {error}")),
            };
            let _ = tx.send(result);
        });
    }

    fn poll_scan_result(&mut self) {
        let Some(receiver) = self.scan_receiver.as_ref() else {
            return;
        };

        match receiver.try_recv() {
            Ok(Ok(scan_result)) => {
                self.scan_result = scan_result;
                self.has_scan_data = true;
                self.scan_status = ScanStatus::Completed;
                self.scan_receiver = None;
                self.selected_index = 0;
            }
            Ok(Err(error)) => {
                self.scan_status = ScanStatus::Failed(error);
                self.scan_receiver = None;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.scan_status = ScanStatus::Failed("scan worker disconnected".to_string());
                self.scan_receiver = None;
            }
        }
    }

    fn tick(&mut self) {
        if matches!(self.scan_status, ScanStatus::Scanning) {
            self.spinner_index = (self.spinner_index + 1) % 4;
        }
    }

    fn top_vulnerability_indices(&self) -> Vec<usize> {
        let mut indices = (0..self.scan_result.vulnerabilities.len()).collect::<Vec<_>>();
        indices.sort_by(|left, right| {
            let left_vuln = &self.scan_result.vulnerabilities[*left];
            let right_vuln = &self.scan_result.vulnerabilities[*right];
            severity_rank(left_vuln.severity)
                .cmp(&severity_rank(right_vuln.severity))
                .then(left_vuln.cve_id.cmp(&right_vuln.cve_id))
                .then(left_vuln.affected_version.cmp(&right_vuln.affected_version))
        });
        indices.into_iter().take(5).collect()
    }

    fn status_label(&self) -> String {
        match &self.scan_status {
            ScanStatus::Idle => "Idle".to_string(),
            ScanStatus::Scanning => format!("Scanning... {}", spinner_char(self.spinner_index)),
            ScanStatus::Completed => "Completed".to_string(),
            ScanStatus::Failed(error) => format!("Failed: {}", truncate_cell(error, 44)),
        }
    }
}

pub fn run_tui(project_path: PathBuf) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = AppState::new(project_path);

    let result = run_loop(&mut terminal, &mut app);

    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    result
}

fn run_loop<B: Backend>(terminal: &mut Terminal<B>, app: &mut AppState) -> io::Result<()> {
    while !app.should_quit {
        app.poll_scan_result();
        app.tick();
        app.clamp_selection();
        terminal.draw(|frame| render(frame, app))?;

        if event::poll(FRAME_TIME)? {
            loop {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => handle_key(app, key),
                    Event::Resize(_, _) => {}
                    _ => {}
                }

                if !event::poll(Duration::from_millis(0))? {
                    break;
                }
            }
        }
    }

    Ok(())
}

fn handle_key(app: &mut AppState, key: KeyEvent) {
    match (key.modifiers, key.code) {
        (_, KeyCode::Char('q')) => app.should_quit = true,
        (_, KeyCode::Esc) => {
            if app.show_details {
                app.show_details = false;
            } else if !matches!(app.mode, AppMode::Overview) {
                app.mode = AppMode::Overview;
                app.selected_index = 0;
            }
        }
        (KeyModifiers::CONTROL, KeyCode::Char('s')) => app.start_scan(),
        (KeyModifiers::CONTROL, KeyCode::Char('l')) => {
            app.mode = AppMode::Dependencies;
            app.selected_index = 0;
            app.show_details = false;
            app.focus = Focus::Content;
        }
        (KeyModifiers::CONTROL, KeyCode::Char('r')) => {
            app.mode = AppMode::Recommendations;
            app.selected_index = 0;
            app.show_details = false;
            app.focus = Focus::Content;
        }
        (_, KeyCode::Tab) => {
            app.focus = match app.focus {
                Focus::Severity => Focus::Content,
                Focus::Content => Focus::Severity,
            };
        }
        (_, KeyCode::Up) => match app.focus {
            Focus::Severity => app.selected_severity = app.selected_severity.saturating_sub(1),
            Focus::Content => app.selected_index = app.selected_index.saturating_sub(1),
        },
        (_, KeyCode::Down) => match app.focus {
            Focus::Severity => app.selected_severity = (app.selected_severity + 1).min(3),
            Focus::Content => {
                let rows = app.row_count();
                if rows > 0 {
                    app.selected_index = (app.selected_index + 1).min(rows - 1);
                }
            }
        },
        (_, KeyCode::Enter) => {
            if app.row_count() > 0 {
                app.show_details = !app.show_details;
            }
        }
        _ => {}
    }
}

fn render(frame: &mut Frame, app: &AppState) {
    let root = frame.size();
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(0)])
        .split(root);

    render_header(frame, app, vertical[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(30), Constraint::Min(0)])
        .split(vertical[1]);

    render_severity_panel(frame, app, body[0]);
    render_content_panel(frame, app, body[1]);

    if app.show_details {
        render_popup(frame, app);
    }
}

fn render_header(frame: &mut Frame, app: &AppState, area: Rect) {
    let mode = match app.mode {
        AppMode::Overview => "Overview",
        AppMode::Dependencies => "Dependencies",
        AppMode::Recommendations => "Recommendations",
    };
    let status_style = match &app.scan_status {
        ScanStatus::Idle => Style::default().fg(Color::Cyan),
        ScanStatus::Scanning => Style::default().fg(Color::Yellow),
        ScanStatus::Completed => Style::default().fg(Color::Green),
        ScanStatus::Failed(_) => Style::default().fg(Color::Red),
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(
                "Scanr v0.1.0",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw("  |  "),
            Span::raw(format!("Path: {}", app.scan_result.path)),
            Span::raw("  |  "),
            Span::styled(format!("Status: {}", app.status_label()), status_style),
        ]),
        Line::from(vec![
            Span::styled(
                "Ctrl+S Scan  |  Ctrl+L Deps  |  Ctrl+R Recs  |  Enter Details  |  Esc Back  |  q Quit",
                Style::default().fg(Color::Gray),
            ),
            Span::raw("  "),
            Span::styled(format!("[{mode}]"), Style::default().fg(Color::Cyan)),
        ]),
    ];

    let header = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Scanr"))
        .wrap(Wrap { trim: true });
    frame.render_widget(header, area);
}

fn render_severity_panel(frame: &mut Frame, app: &AppState, area: Rect) {
    let summary = &app.scan_result.severity_summary;
    let selected_style = Style::default().add_modifier(Modifier::REVERSED);

    let lines = vec![
        Line::from(Span::styled(
            format!("Total: {}", app.scan_result.total_dependencies),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        style_severity_line(
            format!("Critical: {}", summary.critical),
            Color::Red,
            app.selected_severity == 0,
            selected_style,
        ),
        style_severity_line(
            format!("High: {}", summary.high),
            Color::LightRed,
            app.selected_severity == 1,
            selected_style,
        ),
        style_severity_line(
            format!("Medium: {}", summary.medium),
            Color::Yellow,
            app.selected_severity == 2,
            selected_style,
        ),
        style_severity_line(
            format!("Low: {}", summary.low),
            Color::Blue,
            app.selected_severity == 3,
            selected_style,
        ),
        Line::from(Span::styled(
            format!(
                "Risk Level: {}",
                if app.has_scan_data {
                    app.scan_result.risk_level.to_string()
                } else {
                    "N/A".to_string()
                }
            ),
            match app.scan_result.risk_level {
                scanr_sca::RiskLevel::High => Style::default().fg(Color::Red),
                scanr_sca::RiskLevel::Moderate => Style::default().fg(Color::Yellow),
                scanr_sca::RiskLevel::Low => Style::default().fg(Color::Green),
            }
            .add_modifier(Modifier::BOLD),
        )),
    ];

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Severity Summary"),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(panel, area);
}

fn render_content_panel(frame: &mut Frame, app: &AppState, area: Rect) {
    if !app.has_scan_data {
        let mut lines = vec![
            Line::from(Span::styled(
                "No scan data yet.",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("Press Ctrl+S to start scan."),
        ];
        if matches!(app.scan_status, ScanStatus::Scanning) {
            lines.push(Line::from(""));
            lines.push(Line::from(format!(
                "Scanning dependencies and vulnerabilities {}",
                spinner_char(app.spinner_index)
            )));
        }
        if let ScanStatus::Failed(error) = &app.scan_status {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("Last scan failed: {error}"),
                Style::default().fg(Color::Red),
            )));
        }

        let empty = Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title("Overview"))
            .wrap(Wrap { trim: true });
        frame.render_widget(empty, area);
        return;
    }

    match app.mode {
        AppMode::Overview => render_overview(frame, app, area),
        AppMode::Dependencies => render_dependencies(frame, app, area),
        AppMode::Recommendations => render_recommendations(frame, app, area),
    }
}

fn render_overview(frame: &mut Frame, app: &AppState, area: Rect) {
    let indices = app.top_vulnerability_indices();
    if indices.is_empty() {
        let empty = Paragraph::new("No vulnerabilities found in latest scan.")
            .block(Block::default().borders(Borders::ALL).title("Overview"))
            .wrap(Wrap { trim: true });
        frame.render_widget(empty, area);
        return;
    }

    let rows = indices
        .iter()
        .enumerate()
        .map(|(idx, vulnerability_index)| {
            let vulnerability = &app.scan_result.vulnerabilities[*vulnerability_index];
            let package = package_name_from_description(&vulnerability.description);
            let style = if idx == app.selected_index {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(truncate_cell(&package, 20)),
                Cell::from(truncate_cell(&vulnerability.affected_version, 14)),
                Cell::from(truncate_cell(&vulnerability.cve_id, 20)),
                Cell::from(Span::styled(
                    vulnerability.severity.to_string(),
                    severity_style(vulnerability.severity),
                )),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(14),
            Constraint::Length(18),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new(vec!["Package", "Version", "CVE", "Sev"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().borders(Borders::ALL).title("Overview"));
    frame.render_widget(table, area);
}

fn render_dependencies(frame: &mut Frame, app: &AppState, area: Rect) {
    let dependencies = &app.scan_result.dependencies;
    if dependencies.is_empty() {
        let empty = Paragraph::new("No dependencies in latest scan.")
            .block(Block::default().borders(Borders::ALL).title("Dependencies"))
            .wrap(Wrap { trim: true });
        frame.render_widget(empty, area);
        return;
    }

    let vulnerable_names = vulnerable_dependency_names(&app.scan_result.vulnerabilities);
    let visible_rows = area.height.saturating_sub(4) as usize;
    let (start, end) = visible_window(dependencies.len(), app.selected_index, visible_rows);
    let rows = dependencies[start..end]
        .iter()
        .enumerate()
        .map(|(offset, dependency)| {
            let absolute = start + offset;
            let is_vulnerable = vulnerable_names.contains(&dependency.name);
            let style = if absolute == app.selected_index {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(truncate_cell(&dependency.name, 24)),
                Cell::from(truncate_cell(&dependency.version, 14)),
                Cell::from(if dependency.direct {
                    "Direct"
                } else {
                    "Transitive"
                }),
                Cell::from(Span::styled(
                    if is_vulnerable { "Yes" } else { "No" },
                    if is_vulnerable {
                        Style::default().fg(Color::Red)
                    } else {
                        Style::default().fg(Color::Green)
                    },
                )),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();

    let table = Table::new(
        rows,
        [
            Constraint::Length(24),
            Constraint::Length(14),
            Constraint::Length(12),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new(vec!["Package", "Version", "Type", "Vuln"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Dependencies ({})", dependencies.len())),
    );
    frame.render_widget(table, area);
}

fn render_recommendations(frame: &mut Frame, app: &AppState, area: Rect) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(5)])
        .split(area);
    let recommendations = &app.scan_result.upgrade_recommendations;

    if recommendations.is_empty() {
        let empty = Paragraph::new("No upgrade recommendations in latest scan.")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Recommendations"),
            )
            .wrap(Wrap { trim: true });
        frame.render_widget(empty, sections[0]);
        let details = Paragraph::new("Select a recommendation row to view details.")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Recommendation Details"),
            )
            .wrap(Wrap { trim: true });
        frame.render_widget(details, sections[1]);
        return;
    }

    let visible_rows = sections[0].height.saturating_sub(4) as usize;
    let (start, end) = visible_window(recommendations.len(), app.selected_index, visible_rows);
    let rows = recommendations[start..end]
        .iter()
        .enumerate()
        .map(|(offset, recommendation)| {
            let absolute = start + offset;
            let style = if absolute == app.selected_index {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(truncate_cell(&recommendation.package_name, 24)),
                Cell::from(truncate_cell(&recommendation.current_version, 14)),
                Cell::from(truncate_cell(&recommendation.suggested_version, 18)),
                Cell::from(Span::styled(
                    if recommendation.major_bump {
                        "Yes"
                    } else {
                        "No"
                    },
                    if recommendation.major_bump {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::Green)
                    },
                )),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();

    let table = Table::new(
        rows,
        [
            Constraint::Length(24),
            Constraint::Length(14),
            Constraint::Length(16),
            Constraint::Length(10),
        ],
    )
    .header(
        Row::new(vec!["Package", "Current", "Target", "Break"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Recommendations"),
    );
    frame.render_widget(table, sections[0]);

    let details = recommendation_details(app);
    let detail_box = Paragraph::new(details)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Recommendation Details"),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(detail_box, sections[1]);
}

fn render_popup(frame: &mut Frame, app: &AppState) {
    let popup = centered_rect(80, 70, frame.size());
    frame.render_widget(Clear, popup);
    let details = Paragraph::new(detail_text(app))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Details (Enter/Esc closes)"),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(details, popup);
}

fn detail_text(app: &AppState) -> String {
    match app.mode {
        AppMode::Overview => {
            let indices = app.top_vulnerability_indices();
            let Some(vulnerability_index) = indices.get(app.selected_index) else {
                return "No vulnerability selected.".to_string();
            };
            let vulnerability = &app.scan_result.vulnerabilities[*vulnerability_index];
            let mut lines = vec![
                format!(
                    "Package: {}",
                    package_name_from_description(&vulnerability.description)
                ),
                format!("Version: {}", vulnerability.affected_version),
                format!("CVE: {}", vulnerability.cve_id),
                format!("Severity: {}", vulnerability.severity),
                format!("Description: {}", vulnerability.description),
            ];
            if let Some(remediation) = &vulnerability.remediation {
                lines.push(format!("Remediation: {remediation}"));
            }
            if !vulnerability.references.is_empty() {
                lines.push("References:".to_string());
                for reference in vulnerability.references.iter().take(8) {
                    lines.push(format!("- {reference}"));
                }
            }
            lines.join("\n")
        }
        AppMode::Dependencies => {
            let Some(dependency) = app.scan_result.dependencies.get(app.selected_index) else {
                return "No dependency selected.".to_string();
            };
            let mapping = dependency_cve_map(&app.scan_result.vulnerabilities);
            let cves = mapping.get(&dependency.name).cloned().unwrap_or_default();
            let mut lines = vec![
                format!("Name: {}", dependency.name),
                format!("Version: {}", dependency.version),
                format!(
                    "Type: {}",
                    if dependency.direct {
                        "Direct"
                    } else {
                        "Transitive"
                    }
                ),
                format!("Vulnerable: {}", if cves.is_empty() { "No" } else { "Yes" }),
            ];
            if cves.is_empty() {
                lines.push("Associated CVEs: none".to_string());
            } else {
                lines.push("Associated CVEs:".to_string());
                for cve in cves {
                    lines.push(format!("- {cve}"));
                }
            }
            lines.join("\n")
        }
        AppMode::Recommendations => recommendation_details(app),
    }
}

fn recommendation_details(app: &AppState) -> String {
    let Some(recommendation) = app
        .scan_result
        .upgrade_recommendations
        .get(app.selected_index)
    else {
        return "No recommendation selected.".to_string();
    };
    format!(
        "Package: {}\nCurrent Version: {}\nRecommended Version: {}\nBreaking Change: {}\n\nUpgrade '{}' to '{}' to address known issues.",
        recommendation.package_name,
        recommendation.current_version,
        recommendation.suggested_version,
        if recommendation.major_bump {
            "Yes"
        } else {
            "No"
        },
        recommendation.package_name,
        recommendation.suggested_version
    )
}

fn dependency_cve_map(
    vulnerabilities: &[scanr_sca::Vulnerability],
) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::<String, Vec<String>>::new();
    for vulnerability in vulnerabilities {
        let package = package_name_from_description(&vulnerability.description);
        if package.is_empty() {
            continue;
        }
        map.entry(package)
            .or_default()
            .push(vulnerability.cve_id.clone());
    }
    for cves in map.values_mut() {
        cves.sort();
        cves.dedup();
    }
    map
}

fn vulnerable_dependency_names(vulnerabilities: &[scanr_sca::Vulnerability]) -> HashSet<String> {
    vulnerabilities
        .iter()
        .map(|vulnerability| package_name_from_description(&vulnerability.description))
        .filter(|name| !name.is_empty())
        .collect()
}

fn visible_window(total: usize, selected: usize, capacity: usize) -> (usize, usize) {
    if total == 0 || capacity == 0 {
        return (0, 0);
    }
    let mut start = selected.saturating_sub(capacity / 2);
    if start + capacity > total {
        start = total.saturating_sub(capacity);
    }
    let end = (start + capacity).min(total);
    (start, end)
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn style_severity_line(
    label: String,
    color: Color,
    selected: bool,
    selected_style: Style,
) -> Line<'static> {
    let style = if selected {
        Style::default().fg(color).patch(selected_style)
    } else {
        Style::default().fg(color)
    };
    Line::from(Span::styled(label, style))
}

fn severity_rank(severity: scanr_sca::Severity) -> u8 {
    match severity {
        scanr_sca::Severity::Critical => 0,
        scanr_sca::Severity::High => 1,
        scanr_sca::Severity::Medium => 2,
        scanr_sca::Severity::Low => 3,
        scanr_sca::Severity::Unknown => 4,
    }
}

fn severity_style(severity: scanr_sca::Severity) -> Style {
    match severity {
        scanr_sca::Severity::Critical => Style::default().fg(Color::Red),
        scanr_sca::Severity::High => Style::default().fg(Color::LightRed),
        scanr_sca::Severity::Medium => Style::default().fg(Color::Yellow),
        scanr_sca::Severity::Low => Style::default().fg(Color::Blue),
        scanr_sca::Severity::Unknown => Style::default().fg(Color::Gray),
    }
}

fn spinner_char(index: usize) -> &'static str {
    match index % 4 {
        0 => "-",
        1 => "\\",
        2 => "|",
        _ => "/",
    }
}

fn package_name_from_description(description: &str) -> String {
    description
        .split_once(':')
        .map(|(name, _)| name.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn truncate_cell(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        return value.to_string();
    }
    if max_len <= 1 {
        return ".".to_string();
    }
    let mut output = String::new();
    for (index, ch) in value.chars().enumerate() {
        if index >= max_len - 1 {
            break;
        }
        output.push(ch);
    }
    output.push('~');
    output
}

fn normalize_windows_verbatim_path(path: String) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = path.strip_prefix(r"\\?\") {
        return rest.to_string();
    }
    path
}
