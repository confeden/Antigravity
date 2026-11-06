//! Linux-only private server preparation and exec; stdout belongs to the server.

#[path = "../binary_profile.rs"]
mod binary_profile;
#[cfg(target_os = "linux")]
#[path = "../wsl_direct/private_server.rs"]
mod private_server;

#[cfg(target_os = "linux")]
fn main() {
    let mut args = std::env::args_os().skip(1);
    let first = args.next();
    if first.as_deref() == Some(std::ffi::OsStr::new("--vendor-serve")) {
        // Internal adapter only: both inherited output streams belong to the
        // final server. These fixed nonzero codes identify the failing stage
        // without sending a diagnostic into the vendor's port parser.
        const INPUT_FAILED: i32 = 71;
        const PREPARATION_FAILED: i32 = 72;
        const EXEC_FAILED: i32 = 73;
        const UPDATE_PENDING: i32 = 74;
        let parsed = (|| -> Result<_, String> {
            if args.next().as_deref() != Some(std::ffi::OsStr::new("--profile")) { return Err("profile missing".into()); }
            let eligibility = bit(args.next())?;
            let transport = bit(args.next())?;
            let automatic = bit(args.next())?;
            let source = args.next().ok_or("source missing")?;
            if args.next().as_deref() != Some(std::ffi::OsStr::new("--")) { return Err("server argument boundary missing".into()); }
            Ok((source, eligibility, transport, automatic, args.collect::<Vec<_>>()))
        })();
        let (source, eligibility, transport, automatic, server_args) = match parsed {
            Ok(values) => values,
            Err(_) => std::process::exit(INPUT_FAILED),
        };
        let prepared = match private_server::prepare_vendor_profile(std::path::Path::new(&source), eligibility, transport, automatic) {
            Ok(prepared) => prepared,
            Err(error) if error.starts_with("update-pending:") => std::process::exit(UPDATE_PENDING),
            Err(_) => std::process::exit(PREPARATION_FAILED),
        };
        if prepared.exec(&source, &server_args).is_err() {
            std::process::exit(EXEC_FAILED);
        }
        return;
    }
    let prepare_only = first.as_deref() == Some(std::ffi::OsStr::new("--prepare-only"));
    let mut source = if prepare_only { args.next() } else { first };
    let profile = if prepare_only && source.as_deref() == Some(std::ffi::OsStr::new("--profile")) {
        let profile = bit(args.next()).and_then(|eligibility| bit(args.next()).map(|transport| (eligibility, transport)));
        source = args.next();
        Some(profile)
    } else { None };
    let result = source
        .ok_or_else(|| "source-invalid: missing source argument".to_owned())
        .and_then(|source| {
            let server_args: Vec<_> = args.collect();
            if prepare_only && !server_args.is_empty() {
                return Err("source-invalid: prepare-only accepts exactly one source".into());
            }
            let prepared = match profile {
                Some(profile) => {
                    let (eligibility, transport) = profile?;
                    private_server::prepare_selected_profile(std::path::Path::new(&source), eligibility, transport)?
                }
                None => private_server::prepare(std::path::Path::new(&source))?,
            };
            if prepare_only {
                println!("{}", prepared.manifest());
                Ok(())
            } else {
                prepared.exec(&source, &server_args)
            }
        });
    if let Err(error) = result {
        eprintln!("ag-wsl-launch: {error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn bit(value: Option<std::ffi::OsString>) -> Result<bool, String> {
    match value.as_deref() {
        Some(value) if value == std::ffi::OsStr::new("1") => Ok(true),
        Some(value) if value == std::ffi::OsStr::new("0") => Ok(false),
        _ => Err("source-invalid: explicit profile bit required".into()),
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ag-wsl-launch: source-invalid: Linux is required");
    std::process::exit(1);
}
