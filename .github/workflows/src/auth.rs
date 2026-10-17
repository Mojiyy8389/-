// src/auth.rs
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use anyhow::Result;
use tokio::process::Command;
use tokio::time::timeout;

#[derive(Debug, Clone, PartialEq)]
pub enum AuthResult {
    Success,
    Invalid,
    Network,
    Timeout,
    NoFreeRdp,
    Error(String),
}

pub struct FreeRdp {
    path: PathBuf,
}

impl FreeRdp {
    pub fn find() -> Option<Self> {
        // Common paths for wfreerdp and xfreerdp
        let candidates = [
            "wfreerdp.exe", "wfreerdp",
            "xfreerdp", "xfreerdp.exe",
            r"C:\Program Files\FreeRDP\wfreerdp.exe",
            r"C:\Program Files\FreeRDP\xfreerdp.exe",
            r"C:\Program Files (x86)\FreeRDP\wfreerdp.exe",
            r"C:\FreeRDP\wfreerdp.exe",
            r"C:\FreeRDP\bin\wfreerdp.exe",
            "/usr/bin/xfreerdp",
            "/usr/local/bin/xfreerdp",
            "/usr/bin/xfreerdp3",
        ];

        for c in &candidates {
            let p = PathBuf::from(c);
            if p.exists() {
                return Some(Self { path: p });
            }
            if let Ok(found) = which::which(c) {
                return Some(Self { path: found });
            }
        }
        None
    }

    pub async fn try_auth(
        &self,
        host: &str,
        user: &str,
        password: &str,
        domain: &str,
        port: u16,
        timeout_secs: u64,
    ) -> AuthResult {
        for sec in &["nla", "tls", "rdp"] {
            let mut cmd = Command::new(&self.path);
            cmd.arg(format!("/v:{}:{}", host, port))
                .arg(format!("/u:{}", user))
                .arg(format!("/p:{}", password))
                .arg("/cert:ignore")
                .arg(format!("/sec:{}", sec))
                .arg(format!("/timeout:{}", timeout_secs * 1000))
                .arg("+auth-only")
                .arg("/log-level:OFF");

            if !domain.is_empty() {
                cmd.arg(format!("/d:{}", domain));
            }

            cmd.stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stdin(Stdio::null());

            let fut = cmd.output();
            let result = timeout(Duration::from_secs(timeout_secs + 5), fut).await;

            match result {
                Ok(Ok(output)) => {
                    if output.status.success() {
                        return AuthResult::Success;
                    }
                    let combined = format!(
                        "{} {}",
                        String::from_utf8_lossy(&output.stdout).to_lowercase(),
                        String::from_utf8_lossy(&output.stderr).to_lowercase()
                    );
                    if combined.contains("authentication failure")
                        || combined.contains("logon failure")
                        || combined.contains("wrong password")
                        || combined.contains("invalid credentials")
                        || combined.contains("account is disabled")
                    {
                        return AuthResult::Invalid;
                    }
                    if combined.contains("not supported")
                        || combined.contains("unable to connect")
                        || combined.contains("connect failed")
                    {
                        continue; // try next security protocol
                    }
                    if combined.contains("timeout") || combined.contains("timed out") {
                        return AuthResult::Timeout;
                    }
                    continue;
                }
                Ok(Err(_)) => continue,
                Err(_) => return AuthResult::Timeout,
            }
        }
        AuthResult::Invalid
    }
}