// src/main.rs
mod auth;
mod scanner;
mod parser;
mod ui;
mod engine;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use anyhow::Result;

pub struct GlobalState {
    pub stop: Arc<AtomicBool>,
    pub tried: Arc<AtomicU64>,
    pub hits: Arc<AtomicU64>,
    pub errors: Arc<AtomicU64>,
}

impl GlobalState {
    pub fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            tried: Arc::new(AtomicU64::new(0)),
            hits: Arc::new(AtomicU64::new(0)),
            errors: Arc::new(AtomicU64::new(0)),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let app_state = GlobalState::new();
    ui::run_ui(app_state).await
}