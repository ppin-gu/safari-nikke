//! Command-line scan, for testing: `cargo run --example scan -- [--full | FOLDER] [--json] [--redact]`

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use sng_core::model::Mode;
use sng_core::{report, scan, Env};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    let redact = args.iter().any(|a| a == "--redact");
    let folders: Vec<PathBuf> = args.iter().filter(|a| !a.starts_with("--")).map(PathBuf::from).collect();
    let mode = if !folders.is_empty() {
        Mode::Folder
    } else if args.iter().any(|a| a == "--full") {
        Mode::Full
    } else {
        Mode::Quick
    };
    let env = Env::current();
    let r = scan(&env, mode, &folders, &AtomicBool::new(false), &|phase, n, _| {
        eprintln!("{phase} {n}")
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&r).unwrap());
    } else {
        let t = report::text(&r);
        println!("{}", if redact { report::Redact::from_env(&env).apply(&t) } else { t });
    }
}
