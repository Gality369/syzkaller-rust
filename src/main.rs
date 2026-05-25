#![allow(dead_code, unused_imports)]

mod avoidance;
mod config;
mod corpus;
mod crash;
mod description;
mod exec;
#[allow(
    unused_imports,
    dead_code,
    clippy::all,
    non_snake_case,
    non_camel_case_types
)]
mod flatrpc_generated;
mod fuzzer;
mod manager;
mod program;
mod protocol;
mod qemu;
mod ssh;

use std::env;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <config.json>", args[0]);
        std::process::exit(1);
    }

    let cfg = match config::Config::load(&args[1]) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    log::info!("Starting syzkaller-rust with config: {:?}", cfg);

    if let Err(e) = manager::run(cfg) {
        log::error!("Manager failed: {}", e);
        std::process::exit(1);
    }
}
