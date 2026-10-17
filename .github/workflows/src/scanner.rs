// src/scanner.rs
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

// X.224 Connection Request for RDP
const X224_REQUEST: &[u8] = &[
    0x03, 0x00, 0x00, 0x13,
    0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone)]
pub struct AliveHost {
    pub host: String,
    pub banner: String,
}

pub async fn scan_targets(
    hosts: Vec<Ipv4Addr>,
    port: u16,
    concurrency: usize,
    timeout_secs: u64,
    stop: Arc<AtomicBool>,
    tx: mpsc::UnboundedSender<AliveHost>,
    progress: Arc<AtomicU64>,
) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut handles = Vec::new();

    for host in hosts {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let tx = tx.clone();
        let stop = stop.clone();
        let progress = progress.clone();

        handles.push(tokio::spawn(async move {
            let _permit = permit;
            if stop.load(Ordering::Relaxed) {
                return;
            }

            match probe_host(host, port, timeout_secs).await {
                Some(banner) => {
                    let _ = tx.send(AliveHost {
                        host: host.to_string(),
                        banner,
                    });
                }
                None => {}
            }
            progress.fetch_add(1, Ordering::Relaxed);
        }));
    }

    for h in handles {
        let _ = h.await;
    }
}

async fn probe_host(host: Ipv4Addr, port: u16, timeout_secs: u64) -> Option<String> {
    let addr = format!("{}:{}", host, port);
    let stream = timeout(
        Duration::from_secs(timeout_secs),
        TcpStream::connect(&addr),
    )
    .await
    .ok()?
    .ok()?;

    let mut stream = stream;
    stream.write_all(X224_REQUEST).await.ok()?;

    let mut buf = [0u8; 256];
    let n = timeout(
        Duration::from_secs(timeout_secs),
        stream.read(&mut buf),
    )
    .await
    .ok()?
    .ok()?;

    if n < 12 {
        return None;
    }

    match buf[11] {
        0x02 => Some("NLA".to_string()),
        0x03 => Some("NLA+SSL".to_string()),
        _ => Some("RDP".to_string()),
    }
}