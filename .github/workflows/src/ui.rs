// src/ui.rs
use crate::engine::{run_crack, CrackMode};
use crate::parser::{load_lines, parse_targets};
use crate::scanner::{scan_targets, AliveHost};
use crate::GlobalState;
use anyhow::Result;
use eframe::egui;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

pub async fn run_ui(state: GlobalState) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1400.0, 900.0])
            .with_min_inner_size([1000.0, 700.0]),
        ..Default::default()
    };

    eframe::run_native(
        "RDP Hunter v6.0 — Rust Edition",
        options,
        Box::new(|_cc| Box::new(RdpHunterApp::new(Arc::new(state)))),
    )
    .map_err(|e| anyhow::anyhow!("UI error: {}", e))
}

struct RdpHunterApp {
    state: Arc<GlobalState>,
    tab: Tab,
    // Scanner
    scan_input: String,
    scan_port: u16,
    scan_workers: usize,
    scan_timeout: u64,
    scan_alive: Vec<AliveHost>,
    scan_progress: Arc<AtomicU64>,
    scan_total: u64,
    scan_running: bool,
    // Config
    hosts_file: String,
    users_file: String,
    passwords_file: String,
    domain: String,
    port: u16,
    timeout: u64,
    workers: usize,
    mode: CrackMode,
    stop_on_hit: bool,
    crack_running: bool,
    // Hits
    hits: Vec<HitRow>,
    // Log
    log: Vec<String>,
    log_rx: Option<mpsc::UnboundedReceiver<String>>,
    log_tx: Option<mpsc::UnboundedSender<String>>,
}

#[derive(PartialEq)]
enum Tab {
    Scanner,
    Config,
    Hits,
    Console,
}

struct HitRow {
    time: String,
    host: String,
    user: String,
    password: String,
}

impl RdpHunterApp {
    fn new(state: Arc<GlobalState>) -> Self {
        let (log_tx, log_rx) = mpsc::unbounded_channel();
        Self {
            state,
            tab: Tab::Scanner,
            scan_input: String::new(),
            scan_port: 3389,
            scan_workers: 1000,
            scan_timeout: 2,
            scan_alive: Vec::new(),
            scan_progress: Arc::new(AtomicU64::new(0)),
            scan_total: 0,
            scan_running: false,
            hosts_file: String::new(),
            users_file: String::new(),
            passwords_file: String::new(),
            domain: String::new(),
            port: 3389,
            timeout: 15,
            workers: 50,
            mode: CrackMode::Spray,
            stop_on_hit: true,
            crack_running: false,
            hits: Vec::new(),
            log: Vec::new(),
            log_rx: Some(log_rx),
            log_tx: Some(log_tx),
        }
    }

    fn log(&mut self, msg: impl Into<String>) {
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        self.log.push(format!("[{}] {}", ts, msg.into()));
        if self.log.len() > 5000 {
            self.log.drain(0..1000);
        }
    }
}

impl eframe::App for RdpHunterApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll log channel
        if let Some(rx) = &mut self.log_rx {
            while let Ok(msg) = rx.try_recv() {
                self.log(msg);
            }
        }

        // Poll scan progress
        if self.scan_running {
            let done = self.scan_progress.load(Ordering::Relaxed);
            if done >= self.scan_total && self.scan_total > 0 {
                self.scan_running = false;
            }
        }

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading(
                    egui::RichText::new("RDP HUNTER v6.0")
                        .size(28.0)
                        .color(egui::Color32::from_rgb(79, 209, 255))
                        .strong(),
                );
                ui.label(
                    egui::RichText::new("— Rust Edition — Memory-safe, blazing fast")
                        .italics()
                        .color(egui::Color32::from_rgb(120, 140, 170)),
                );
            });
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!(
                    "Tried: {}   Hits: {}   Errors: {}   {}",
                    self.state.tried.load(Ordering::Relaxed),
                    self.state.hits.load(Ordering::Relaxed),
                    self.state.errors.load(Ordering::Relaxed),
                    if self.state.stop.load(Ordering::Relaxed) { "[STOPPED]" } else { "" }
                ));
                if ui.button("⟲ Reset stats").clicked() {
                    self.state.tried.store(0, Ordering::Relaxed);
                    self.state.hits.store(0, Ordering::Relaxed);
                    self.state.errors.store(0, Ordering::Relaxed);
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.selectable_label(self.tab == Tab::Scanner, "🔍 Scanner").clicked() {
                    self.tab = Tab::Scanner;
                }
                if ui.selectable_label(self.tab == Tab::Config, "⚙ Config").clicked() {
                    self.tab = Tab::Config;
                }
                if ui.selectable_label(self.tab == Tab::Hits, "🎯 Hits").clicked() {
                    self.tab = Tab::Hits;
                }
                if ui.selectable_label(self.tab == Tab::Console, "📜 Console").clicked() {
                    self.tab = Tab::Console;
                }
            });
            ui.separator();

            match self.tab {
                Tab::Scanner => self.render_scanner(ui, ctx),
                Tab::Config => self.render_config(ui, ctx),
                Tab::Hits => self.render_hits(ui),
                Tab::Console => self.render_console(ui),
            }
        });

        ctx.request_repaint();
    }
}

impl RdpHunterApp {
    fn render_scanner(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.label("Targets (IP / CIDR / Range / File path):");
        ui.text_edit_singleline(&mut self.scan_input);

        ui.horizontal(|ui| {
            ui.label("Port:");
            ui.add(egui::DragValue::new(&mut self.scan_port).range(1..=65535));
            ui.label("Workers:");
            ui.add(egui::DragValue::new(&mut self.scan_workers).range(1..=5000));
            ui.label("Timeout (s):");
            ui.add(egui::DragValue::new(&mut self.scan_timeout).range(1..=30));
        });

        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.scan_running, egui::Button::new("⚡ START SCAN"))
                .clicked()
            {
                let targets = parse_targets(&self.scan_input);
                if targets.is_empty() {
                    self.log("No valid targets");
                } else {
                    self.scan_alive.clear();
                    self.scan_total = targets.len() as u64;
                    self.scan_progress.store(0, Ordering::Relaxed);
                    self.state.stop.store(false, Ordering::Relaxed);
                    self.scan_running = true;

                    let (tx, mut rx) = mpsc::unbounded_channel::<AliveHost>();
                    let progress = self.scan_progress.clone();
                    let stop = self.state.stop.clone();
                    let port = self.scan_port;
                    let workers = self.scan_workers;
                    let timeout_s = self.scan_timeout;

                    // Bridge tokio to UI: spawn task that updates vec via channel
                    let ctx_clone = ctx.clone();
                    let log_tx = self.log_tx.clone().unwrap();
                    let alive_shared = Arc::new(parking_lot::Mutex::new(Vec::<AliveHost>::new()));
                    let alive_clone = alive_shared.clone();

                    std::thread::spawn(move || {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        rt.block_on(async move {
                            let (tx2, mut rx2) = mpsc::unbounded_channel();
                            let handle = tokio::spawn(async move {
                                scan_targets(targets, port, workers, timeout_s, stop, tx, progress).await;
                            });
                            while let Some(h) = rx.recv().await {
                                let _ = log_tx.send(format!("[+] ALIVE {} ({})", h.host, h.banner));
                                alive_clone.lock().push(h);
                                ctx_clone.request_repaint();
                            }
                            let _ = handle.await;
                        });
                    });

                    // Pull existing alive hosts into our UI vec
                    self.scan_alive = alive_shared.lock().clone();
                }
            }

            if ui
                .add_enabled(self.scan_running, egui::Button::new("■ STOP"))
                .clicked()
            {
                self.state.stop.store(true, Ordering::Relaxed);
                self.scan_running = false;
            }

            if ui.button("→ Send alive to Config").clicked() {
                if !self.scan_alive.is_empty() {
                    let path = "alive_hosts.txt";
                    let content: String = self
                        .scan_alive
                        .iter()
                        .map(|h| h.host.clone())
                        .collect::<Vec<_>>()
                        .join("\n");
                    std::fs::write(path, content).ok();
                    self.hosts_file = path.to_string();
                    self.tab = Tab::Config;
                    self.log(format!("Sent {} hosts to Config", self.scan_alive.len()));
                }
            }
        });

        // Progress
        let done = self.scan_progress.load(Ordering::Relaxed);
        let total = self.scan_total;
        if total > 0 {
            let frac = (done as f32 / total as f32).clamp(0.0, 1.0);
            ui.add(egui::ProgressBar::new(frac).text(format!("{}/{}", done, total)));
        }

        ui.separator();
        ui.label(format!("Alive hosts: {}", self.scan_alive.len()));

        egui::ScrollArea::vertical().show(ui, |ui| {
            for h in &self.scan_alive {
                ui.label(format!("  {} — {}", h.host, h.banner));
            }
        });
    }

    fn render_config(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) {
        ui.horizontal(|ui| {
            ui.label("Hosts file:");
            ui.text_edit_singleline(&mut self.hosts_file);
            if ui.button("📁").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.hosts_file = path.display().to_string();
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("Users file:");
            ui.text_edit_singleline(&mut self.users_file);
            if ui.button("📁").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.users_file = path.display().to_string();
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("Passwords file:");
            ui.text_edit_singleline(&mut self.passwords_file);
            if ui.button("📁").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.passwords_file = path.display().to_string();
                }
            }
        });

        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Port:");
            ui.add(egui::DragValue::new(&mut self.port).range(1..=65535));
            ui.label("Domain:");
            ui.text_edit_singleline(&mut self.domain);
            ui.label("Workers:");
            ui.add(egui::DragValue::new(&mut self.workers).range(1..=500));
            ui.label("Timeout (s):");
            ui.add(egui::DragValue::new(&mut self.timeout).range(5..=180));
        });
        ui.horizontal(|ui| {
            ui.label("Mode:");
            ui.selectable_value(&mut self.mode, CrackMode::Spray, "Spray (password-first)");
            ui.selectable_value(&mut self.mode, CrackMode::Cartesian, "Cartesian (user-first)");
            ui.checkbox(&mut self.stop_on_hit, "Stop target on first hit");
        });

        ui.separator();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.crack_running, egui::Button::new("▶ START CRACKING"))
                .clicked()
            {
                let hosts = load_lines(&self.hosts_file).unwrap_or_default();
                let users = load_lines(&self.users_file).unwrap_or_default();
                let passwords = load_lines(&self.passwords_file).unwrap_or_default();

                if hosts.is_empty() || users.is_empty() || passwords.is_empty() {
                    self.log("[!] Missing input files");
                } else {
                    self.state.stop.store(false, Ordering::Relaxed);
                    self.state.tried.store(0, Ordering::Relaxed);
                    self.state.hits.store(0, Ordering::Relaxed);
                    self.state.errors.store(0, Ordering::Relaxed);
                    self.crack_running = true;
                    self.log(format!(
                        "Starting crack: {} hosts × {} users × {} passwords = {} combos",
                        hosts.len(),
                        users.len(),
                        passwords.len(),
                        hosts.len() * users.len() * passwords.len()
                    ));

                    let state = self.state.clone();
                    let domain = self.domain.clone();
                    let port = self.port;
                    let timeout = self.timeout;
                    let workers = self.workers;
                    let mode = self.mode;
                    let stop_on_hit = self.stop_on_hit;
                    let log_tx = self.log_tx.clone().unwrap();

                    std::thread::spawn(move || {
                        let rt = tokio::runtime::Runtime::new().unwrap();
                        rt.block_on(async move {
                            let stats = run_crack(
                                hosts, users, passwords, domain, port, timeout,
                                workers, mode, stop_on_hit, state,
                            )
                            .await;
                            let _ = log_tx.send(format!(
                                "DONE — tried: {}, hits: {}, errors: {}",
                                stats.tried, stats.hits, stats.errors
                            ));
                        });
                    });
                }
            }

            if ui
                .add_enabled(self.crack_running, egui::Button::new("■ STOP"))
                .clicked()
            {
                self.state.stop.store(true, Ordering::Relaxed);
                self.crack_running = false;
            }
        });
    }

    fn render_hits(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("🔄 Reload hits.txt").clicked() {
                self.reload_hits();
            }
            if ui.button("🗑 Clear").clicked() {
                std::fs::write(
                    "hits.txt",
                    "# timestamp | host | user:password\n",
                )
                .ok();
                self.hits.clear();
            }
        });
        ui.separator();

        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("hits_grid").striped(true).show(ui, |ui| {
                ui.strong("Time");
                ui.strong("Host");
                ui.strong("User");
                ui.strong("Password");
                ui.end_row();

                for h in &self.hits {
                    ui.label(&h.time);
                    ui.label(&h.host);
                    ui.label(&h.user);
                    ui.colored_label(egui::Color32::from_rgb(0, 255, 156), &h.password);
                    ui.end_row();
                }
            });
        });
    }

    fn render_console(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for line in &self.log {
                    ui.label(line);
                }
            });
    }

    fn reload_hits(&mut self) {
        self.hits.clear();
        if let Ok(content) = std::fs::read_to_string("hits.txt") {
            for line in content.lines() {
                if line.starts_with('#') || line.trim().is_empty() {
                    continue;
                }
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() != 3 {
                    continue;
                }
                let creds: Vec<&str> = parts[2].splitn(2, ':').collect();
                self.hits.push(HitRow {
                    time: parts[0].trim().to_string(),
                    host: parts[1].trim().to_string(),
                    user: creds.get(0).unwrap_or(&"").to_string(),
                    password: creds.get(1).unwrap_or(&"").to_string(),
                });
            }
        }
    }
}