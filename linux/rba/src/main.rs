//! `rba`: operator and integration interface to `rbad`.
//!
//! Every subcommand is a thin request to the daemon over its control socket. The
//! CLI performs no authentication decision of its own: it cannot, because it
//! holds no keys and trusts nothing.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use rba_protocol::pairing::CodeEntry;
use rbad::ipc::{ControlRequest, ControlResponse};

#[cfg(target_os = "linux")]
mod pam;

const DEFAULT_SOCKET: &str = rbad::config::DEFAULT_SOCKET;

fn usage_text() -> String {
    format!(
        "rba {}\n\
         \n\
         USAGE:\n\
         \x20   rba [--socket PATH] <COMMAND> [OPTIONS]\n\
         \n\
         COMMANDS:\n\
         \x20   devices                   show paired authenticators\n\
         \x20   status                    daemon status\n\
         \x20   pair                      pair a device; one side shows the code, the other types it\n\
         \x20   auth --user U             ask a device to authenticate a Linux user\n\
         \x20   unpair --device D         remove trust for a device (owner or root)\n\
         \x20   revoke --device D         revoke an authenticator immediately (root only)\n\
         \x20   enable <backend>          enable a host integration (gdm, polkit, sudo) [linux]\n\
         \x20   disable <backend>         roll back a host integration [linux]\n\
         \x20   version                   print the product and protocol version\n\
         \x20   help                      show this help\n\
         \n\
         PAIRING:\n\
         \x20   rba pair --code NNNNNN       pair using an operator-chosen code\n\
         \x20   rba pair --code-entry device  host shows the code; type it on the device (default)\n\
         \x20   rba pair --code-entry host    device shows the code; type it in this terminal\n\
         \x20   --owner USER                  account the device may authenticate (default: you)\n\
         \x20   --allow-root                  also allow this device to authenticate root (explicit)\n\
         \n\
         OPTIONS:\n\
         \x20   --socket PATH    control socket (default {DEFAULT_SOCKET})\n\
         \x20   --user NAME      Linux user to authenticate (defaults to $USER)\n\
         \x20   --purpose P      purpose, e.g. sudo, login, polkit  (default authenticate)\n\
         \x20   --service S      PAM service / polkit action       (default rba)\n\
         \x20   --operation O    authenticate or authorize         (default authenticate)\n\
         \x20   -s, --device D   device name or id (default: any connected authenticator)\n\
         \x20   --timeout MS     how long to wait                     (default 90000)\n\
         \x20   -h, --help       show this help\n\
         \x20   -V, --version    print the product and protocol version\n\
         \n\
         ENVIRONMENT:\n\
         \x20   RBA_SOCKET       control socket (default {DEFAULT_SOCKET})\n\
         \n\
         A device authenticates only the account it was paired for. Root is denied\n\
         unless pairing used --allow-root. The 'auth' command performs no\n\
         cryptography here: it asks the daemon, which verifies a signature over a\n\
         fresh challenge against the registered device public key.\n",
        rba_protocol::VERSION
    )
}

/// Print help to stderr as part of a usage error.
fn usage() -> ! {
    eprint!("{}", usage_text());
    std::process::exit(2)
}

/// Print help to stdout for an explicit `rba help` or `--help`.
fn help() -> ! {
    print!("{}", usage_text());
    std::process::exit(0)
}

/// `rba` with no command prints help and exits 1, like `adb`.
fn no_args() -> ! {
    print!("{}", usage_text());
    std::process::exit(1)
}

struct Args {
    socket: PathBuf,
    command: String,
    backend: Option<String>,
    user: Option<String>,
    purpose: String,
    service: String,
    operation: String,
    device: Option<String>,
    code: Option<String>,
    code_entry: CodeEntry,
    owner: Option<String>,
    allow_root: bool,
    dry_run: bool,
    verbose: bool,
    timeout_ms: u64,
}

fn parse() -> Args {
    let mut args = Args {
        socket: std::env::var_os("RBA_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET)),
        command: String::new(),
        backend: None,
        user: None,
        purpose: "authenticate".into(),
        service: "rba".into(),
        operation: "authenticate".into(),
        device: None,
        code: None,
        code_entry: CodeEntry::Device,
        owner: None,
        allow_root: false,
        dry_run: false,
        verbose: false,
        timeout_ms: rbad::server::DEFAULT_AUTH_TIMEOUT_MS,
    };
    let mut it = std::env::args().skip(1).peekable();
    if it.peek().is_none() {
        no_args();
    }
    // The subcommand may appear anywhere, so that both
    // `rba pair --socket X` and `rba --socket X pair` work.
    while let Some(a) = it.next() {
        if !a.starts_with('-') {
            if args.command.is_empty() {
                args.command = a;
                continue;
            }
            if args.backend.is_none() && (args.command == "enable" || args.command == "disable") {
                args.backend = Some(a);
                continue;
            }
            eprintln!("rba: unexpected argument {a:?}");
            usage();
        }
        let mut v = |f: &str| {
            it.next().unwrap_or_else(|| {
                eprintln!("rba: {f} needs a value");
                std::process::exit(2)
            })
        };
        match a.as_str() {
            "--socket" => args.socket = PathBuf::from(v("--socket")),
            "--user" => args.user = Some(v("--user")),
            "--purpose" => args.purpose = v("--purpose"),
            "--service" => args.service = v("--service"),
            "--operation" => args.operation = v("--operation"),
            "-s" | "--device" => args.device = Some(v("--device")),
            "--code" => args.code = Some(v("--code")),
            "--code-entry" => {
                let value = v("--code-entry");
                args.code_entry = match value.as_str() {
                    "device" => CodeEntry::Device,
                    "host" => CodeEntry::Host,
                    other => {
                        eprintln!("rba: --code-entry must be device or host, got {other:?}");
                        usage();
                    }
                };
            }
            "--owner" => args.owner = Some(v("--owner")),
            "--allow-root" => args.allow_root = true,
            "--dry-run" => args.dry_run = true,
            "--verbose" => args.verbose = true,
            "--timeout" => args.timeout_ms = v("--timeout").parse().unwrap_or(90_000),
            "-h" | "--help" => help(),
            "-V" | "--version" => version(),
            other => {
                eprintln!("rba: unknown option {other:?}");
                usage()
            }
        }
    }
    args
}

/// Sends one control request and returns the response.
fn request(args: &Args, req: &ControlRequest) -> Result<ControlResponse, String> {
    let stream = std::os::unix::net::UnixStream::connect(&args.socket).map_err(|e| {
        let hint = match e.kind() {
            std::io::ErrorKind::PermissionDenied => {
                "hint: the control socket is not accessible; check `systemctl status rbad`."
            }
            std::io::ErrorKind::NotFound => "hint: is the service running? (systemctl status rbad)",
            std::io::ErrorKind::ConnectionRefused => {
                "hint: rbad is not accepting connections; check `systemctl status rbad`"
            }
            _ => "hint: check `systemctl status rbad`",
        };
        format!(
            "cannot reach rbad at {}: {e}\n{hint}",
            args.socket.display()
        )
    })?;
    let mut stream = stream;
    let line = serde_json::to_string(req).map_err(|e| e.to_string())?;
    stream
        .write_all(format!("{line}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    let mut reader = std::io::BufReader::new(&stream);
    let mut reply = String::new();
    reader.read_line(&mut reply).map_err(|e| e.to_string())?;
    if reply.trim().is_empty() {
        return Err("the daemon closed the connection without replying".into());
    }
    serde_json::from_str(reply.trim()).map_err(|e| format!("malformed reply: {e}"))
}

/// Best-effort cancel of the open pairing session, used on Ctrl-C.
fn send_cancel(socket: &std::path::Path) {
    if let Ok(mut stream) = std::os::unix::net::UnixStream::connect(socket) {
        if let Ok(line) = serde_json::to_string(&ControlRequest::CancelPairing) {
            let _ = stream.write_all(format!("{line}\n").as_bytes());
            let _ = stream.flush();
        }
    }
}

/// On Ctrl-C, cancel the pairing session so it does not linger until it expires,
/// then exit with the conventional SIGINT status.
fn install_pairing_cancel(socket: PathBuf) {
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        rt.block_on(async {
            if tokio::signal::ctrl_c().await.is_ok() {
                send_cancel(&socket);
                eprintln!("\nrba: pairing cancelled");
                std::process::exit(130);
            }
        });
    });
}

fn fail(resp: &ControlResponse) -> ! {
    eprintln!("rba: {}", resp.error.as_deref().unwrap_or("request failed"));
    if let Some(code) = &resp.code {
        eprintln!("rba: code: {code}");
    }
    std::process::exit(1)
}

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "root".into())
}

fn cmd_devices(args: &Args) {
    let resp = request(args, &ControlRequest::List).unwrap_or_else(|e| {
        eprintln!("rba: {e}");
        std::process::exit(1)
    });
    if !resp.ok {
        fail(&resp);
    }
    let devices = resp
        .result
        .as_ref()
        .and_then(|r| r.get("devices"))
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default();
    // adb-style: a constant header, then fixed-width rows. An empty list is just
    // the header.
    println!("List of authenticators paired");
    if devices.is_empty() {
        return;
    }
    println!();
    println!(
        "{:<22} {:<12} {:<10} {:<12} {:<14} LINK",
        "DEVICE", "ID", "STATE", "USERS", "ROOT"
    );
    for d in &devices {
        let name = d
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("(unnamed)");
        let id = d.get("device_id").and_then(|v| v.as_str()).unwrap_or("-");
        let status = d.get("status").and_then(|v| v.as_str()).unwrap_or("?");
        let users = d
            .get("users")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "-".into());
        let root = if d
            .get("allow_root")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            "allowed"
        } else {
            "denied"
        };
        let link = if d
            .get("available")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            "available"
        } else {
            "not connected"
        };
        println!(
            "{:<22} {:<12} {:<10} {:<12} {:<14} {}",
            name.chars().take(22).collect::<String>(),
            id.chars().take(12).collect::<String>(),
            status,
            users.chars().take(12).collect::<String>(),
            root,
            link
        );
    }
}

fn cmd_status(args: &Args) {
    let resp = request(args, &ControlRequest::Status).unwrap_or_else(|e| {
        eprintln!("rba: {e}");
        std::process::exit(1)
    });
    if !resp.ok {
        fail(&resp);
    }
    if let Some(r) = &resp.result {
        println!(
            "host          {}",
            r.get("host_name").and_then(|v| v.as_str()).unwrap_or("-")
        );
        println!(
            "host id       {}",
            r.get("host_id").and_then(|v| v.as_str()).unwrap_or("-")
        );
        println!(
            "host key      {}",
            r.get("host_key_id").and_then(|v| v.as_str()).unwrap_or("-")
        );
        println!(
            "paired        {}",
            r.get("paired_devices")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
        );
        println!(
            "connected     {}",
            r.get("connected_devices")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
        );
        match r.get("pairing") {
            Some(p) if p.get("seconds_remaining").is_some() => {
                println!(
                    "pairing       open, {}s remaining",
                    p.get("seconds_remaining")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0)
                );
            }
            _ => println!("pairing       closed"),
        }
    }
    #[cfg(target_os = "linux")]
    {
        // Local integration state: which PAM stacks reference pam_rba.
        println!();
        println!("integrations:");
        for (name, path) in [
            ("gdm", "/etc/pam.d/gdm-password"),
            ("polkit", "/etc/pam.d/polkit-1"),
            ("sudo", "/etc/pam.d/sudo"),
        ] {
            let enabled = std::fs::read_to_string(path)
                .map(|s| s.contains("pam_rba.so"))
                .unwrap_or(false);
            println!(
                "  {:<8} {}",
                name,
                if enabled { "enabled" } else { "disabled" }
            );
        }
    }
}

/// Interactive pairing.
///
/// In `device` mode the host displays the code and the device must type it. In
/// `host` mode the device displays the code and this terminal must type it. The
/// endpoint that displays the code never accepts a bare confirmation.
fn cmd_pair(args: &Args) {
    let resp = request(
        args,
        &ControlRequest::Pair {
            code: args.code.clone(),
            code_entry: Some(args.code_entry.as_str().to_string()),
            timeout_ms: Some(args.timeout_ms.max(1000)),
            owner: args.owner.clone(),
            allow_root: args.allow_root,
        },
    )
    .unwrap_or_else(|e| {
        eprintln!("rba: {e}");
        std::process::exit(1)
    });
    if !resp.ok {
        fail(&resp);
    }
    install_pairing_cancel(args.socket.clone());
    let remaining = resp
        .result
        .as_ref()
        .and_then(|r| r.get("seconds_remaining"))
        .and_then(|v| v.as_i64())
        .unwrap_or(120);
    // adb-like: one progress line, then the code. No box art and no host [y/N] —
    // running `pair` is already the operator's decision.
    eprintln!("Waiting for device... ({remaining}s)");

    // Wait until the device has submitted and both sides can derive the code.
    let code = loop {
        let st = match request(args, &ControlRequest::PairingCode) {
            Ok(r) if r.ok => r,
            Ok(r) => fail(&r),
            Err(e) => {
                eprintln!("rba: {e}");
                std::process::exit(1)
            }
        };
        let phase = st
            .result
            .as_ref()
            .and_then(|r| r.get("phase"))
            .and_then(|p| p.as_str())
            .unwrap_or("");
        let candidate = st
            .result
            .as_ref()
            .and_then(|r| r.get("code"))
            .and_then(|c| c.as_str())
            .unwrap_or("");
        if (phase.eq_ignore_ascii_case("awaitingconfirmation")
            || phase.eq_ignore_ascii_case("confirmed"))
            && !candidate.is_empty()
        {
            break candidate.to_string();
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };

    let confirmation = match args.code_entry {
        CodeEntry::Device => {
            // The host shows the code; the device operator types it. There is no
            // host [y/N]: the device's typed code is the human gate, so the
            // confirmation is sent automatically.
            println!("Code: {code}  type this on the device");
            None
        }
        CodeEntry::Host => {
            // The device shows the code; the host operator types it, like
            // `adb pair`.
            let entered = loop {
                print!("Enter pairing code: ");
                let _ = std::io::stdout().flush();
                let mut answer = String::new();
                match std::io::stdin().read_line(&mut answer) {
                    Ok(0) | Err(_) => {
                        eprintln!("\nrba: no code read; pairing cancelled");
                        std::process::exit(1);
                    }
                    Ok(_) => {}
                }
                let entered: String = answer.chars().filter(|c| c.is_ascii_digit()).collect();
                if entered == code {
                    break entered;
                }
                println!("Code mismatch; try again.");
            };
            Some(entered)
        }
    };

    // Send the confirmation automatically; there is no host prompt.
    match request(args, &ControlRequest::ConfirmPairing { code: confirmation }) {
        Ok(r) if r.ok => {}
        Ok(r) => fail(&r),
        Err(e) => {
            eprintln!("rba: {e}");
            std::process::exit(1)
        }
    }

    // Wait for the daemon to finish the host side and the device to confirm.
    // The device sends PAIRING_CONFIRMED after it persists its record; only then
    // is the pairing fully complete and safe to claim as "Paired".
    let confirmed = loop {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let Ok(r) = request(args, &ControlRequest::PairingConfirmed) else {
            continue;
        };
        if r.ok {
            let Some(val) = r.result else { break false };
            break val.as_bool().unwrap_or(false);
        }
        // If the pairing session has expired, give up.
        let Some(res) = &r.result else { continue };
        let still_open = res
            .get("pairing")
            .and_then(|p| p.get("seconds_remaining"))
            .is_some();
        if !still_open {
            break false;
        }
    };

    if confirmed {
        // Device has confirmed its side; now safe to print the final result.
        let model = args.device.as_deref().unwrap_or("");
        if !model.is_empty() {
            println!("Paired {} model.", model);
        } else {
            println!("Paired.");
        }
    } else {
        eprintln!("rba: pairing timed out or cancelled");
        std::process::exit(1);
    }
}

fn cmd_auth(args: &Args) {
    let user = args.user.clone().unwrap_or_else(current_user);
    let req = ControlRequest::Authenticate {
        user: user.clone(),
        purpose: args.purpose.clone(),
        service: args.service.clone(),
        operation: args.operation.clone(),
        device: args.device.clone(),
        timeout_ms: Some(args.timeout_ms),
    };
    let device_label = args
        .device
        .clone()
        .unwrap_or_else(|| "any connected authenticator".into());
    eprintln!("Waiting for authentication on {device_label} for {user}…");
    let resp = match request(args, &req) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("rba: {e}");
            std::process::exit(1)
        }
    };
    if !resp.ok {
        fail(&resp);
    }
    let r = resp.result.unwrap_or(serde_json::Value::Null);
    println!("Authenticated.");
    println!(
        "  device    {}",
        r.get("device").and_then(|v| v.as_str()).unwrap_or("-")
    );
    println!(
        "  user      {}",
        r.get("user").and_then(|v| v.as_str()).unwrap_or(&user)
    );
    println!("  purpose   {}", args.purpose);
    println!(
        "  request   {}",
        r.get("request_id").and_then(|v| v.as_str()).unwrap_or("-")
    );
}

fn cmd_revoke(args: &Args) {
    let Some(device) = args.device.clone() else {
        eprintln!("rba: --device is required");
        std::process::exit(2);
    };
    match request(args, &ControlRequest::Revoke { device }) {
        Ok(r) if r.ok => println!("Revoked."),
        Ok(r) => fail(&r),
        Err(e) => {
            eprintln!("rba: {e}");
            std::process::exit(1)
        }
    }
}

fn cmd_unpair(args: &Args) {
    let Some(device) = args.device.clone() else {
        eprintln!("rba: --device is required");
        std::process::exit(2);
    };
    match request(args, &ControlRequest::Unpair { device }) {
        Ok(r) if r.ok => println!("Unpaired."),
        Ok(r) => fail(&r),
        Err(e) => {
            eprintln!("rba: {e}");
            std::process::exit(1)
        }
    }
}

#[cfg(target_os = "linux")]
fn cmd_enable(args: &Args) {
    // Require root
    if unsafe { libc::getuid() } != 0 {
        eprintln!("rba: enable requires root (run with sudo or pkexec)");
        std::process::exit(1);
    }
    let backend_name = match &args.backend {
        Some(b) => b.as_str(),
        None => {
            eprintln!("rba: missing backend (gdm, polkit, sudo)");
            std::process::exit(2);
        }
    };
    let backend = match pam::find_backend(backend_name) {
        Some(b) => b,
        None => {
            eprintln!("rba: unknown backend {backend_name:?} (gdm, polkit, sudo)");
            std::process::exit(2);
        }
    };
    let timeout_ms = (args.timeout_ms.min(60000).max(1000)) as u32;
    let (old, new) = match pam::plan_enable(backend, timeout_ms) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("rba: {e}");
            std::process::exit(1);
        }
    };
    if args.dry_run {
        print!("{}", pam::diff(backend, &old, &new));
        println!("\nDry run only; no files changed.");
        return;
    }
    print!("{}", pam::diff(backend, &old, &new));
    print!("\nApply? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err()
        || !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes")
    {
        println!("Aborted; no files changed.");
        std::process::exit(1);
    }
    if let Err(e) = pam::apply_enable(backend, timeout_ms, &old, &new) {
        eprintln!("rba: {e}");
        std::process::exit(1);
    }
    println!("Enabled {} (timeout {}ms).", backend.name, timeout_ms);
    println!("Rollback: rba disable {}", backend.name);
}

#[cfg(target_os = "linux")]
fn cmd_disable(args: &Args) {
    if unsafe { libc::getuid() } != 0 {
        eprintln!("rba: disable requires root (run with sudo or pkexec)");
        std::process::exit(1);
    }
    let backend_name = match &args.backend {
        Some(b) => b.as_str(),
        None => {
            eprintln!("rba: missing backend (gdm, polkit, sudo)");
            std::process::exit(2);
        }
    };
    let backend = match pam::find_backend(backend_name) {
        Some(b) => b,
        None => {
            eprintln!("rba: unknown backend {backend_name:?} (gdm, polkit, sudo)");
            std::process::exit(2);
        }
    };
    if args.dry_run {
        println!("Would roll back {}.", backend.target);
        return;
    }
    if let Err(e) = pam::apply_rollback(backend) {
        eprintln!("rba: {e}");
        std::process::exit(1);
    }
    println!("Disabled {}.", backend.name);
}

fn cmd_version() {
    println!(
        "Remote Biometric Authenticator (rba) {}",
        rba_protocol::VERSION
    );
    println!("Protocol version {}", rba_protocol::PROTOCOL_VERSION);
    if let Ok(path) = std::env::current_exe() {
        println!("Installed as {}", path.display());
    }
}

fn version() -> ! {
    cmd_version();
    std::process::exit(0)
}

fn main() {
    let args = parse();
    if args.command.is_empty() {
        no_args();
    }
    match args.command.as_str() {
        "devices" => cmd_devices(&args),
        "status" => cmd_status(&args),
        "pair" => cmd_pair(&args),
        "auth" => cmd_auth(&args),
        "revoke" => cmd_revoke(&args),
        "unpair" => cmd_unpair(&args),
        #[cfg(target_os = "linux")]
        "enable" => cmd_enable(&args),
        #[cfg(target_os = "linux")]
        "disable" => cmd_disable(&args),
        "version" => cmd_version(),
        "help" => help(),
        other => {
            eprintln!("rba: unknown command {other:?}");
            usage()
        }
    }
}
