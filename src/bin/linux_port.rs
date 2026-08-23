use std::env;
use std::path::PathBuf;

#[path = "../asar.rs"]
mod asar;
#[path = "../patch_binary.rs"]
mod patch_binary;
#[path = "../patch_ide.rs"]
mod patch_ide;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: linux_port <app.asar> <app-output-dir> <language_server-copy>");
        std::process::exit(2);
    }

    let app_asar = PathBuf::from(&args[1]);
    let app_dir = PathBuf::from(&args[2]);
    let language_server = PathBuf::from(&args[3]);

    if !asar::extract_asar(&app_asar, &app_dir) {
        eprintln!("failed to extract ASAR");
        std::process::exit(3);
    }

    let desktop_main = app_dir.join("dist").join("main.js");
    if let Err(error) = patch_ide::patch_desktop(&app_dir, &desktop_main) {
        eprintln!("failed to patch desktop main.js: {error}");
        std::process::exit(4);
    }

    if let Err(error) = patch_binary::patch_binary(&app_dir, &language_server) {
        eprintln!("failed to patch language_server: {error}");
        std::process::exit(5);
    }

    println!("patched desktop_main={}", desktop_main.display());
    println!("patched language_server={}", language_server.display());
}
