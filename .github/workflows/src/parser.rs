// src/parser.rs
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use anyhow::Result;
use ipnet::Ipv4Net;

pub fn parse_targets(raw: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();

    if raw.is_empty() {
        return out;
    }

    // If it's a file, read it
    let content = if Path::new(raw).is_file() {
        fs::read_to_string(raw).unwrap_or_default()
    } else {
        raw.to_string()
    };

    for token in content.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
        let token = token.trim();
        if token.is_empty() || token.starts_with('#') {
            continue;
        }

        // CIDR
        if token.contains('/') {
            if let Ok(net) = token.parse::<Ipv4Net>() {
                for ip in net.hosts() {
                    out.push(ip);
                    if out.len() > 500_000 {
                        return out;
                    }
                }
            }
            continue;
        }

        // Range
        if token.contains('-') && token.matches('.').count() == 6 {
            let parts: Vec<&str> = token.split('-').collect();
            if parts.len() == 2 {
                if let (Ok(a), Ok(b)) = (
                    parts[0].trim().parse::<Ipv4Addr>(),
                    parts[1].trim().parse::<Ipv4Addr>(),
                ) {
                    let start = u32::from(a);
                    let end = u32::from(b);
                    if start <= end && (end - start) < 100_000 {
                        for i in start..=end {
                            out.push(Ipv4Addr::from(i));
                        }
                    }
                }
            }
            continue;
        }

        // Single IP
        if let Ok(ip) = token.split(':').next().unwrap_or("").parse::<Ipv4Addr>() {
            out.push(ip);
        }
    }

    out
}

pub fn load_lines(path: &str) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect())
}