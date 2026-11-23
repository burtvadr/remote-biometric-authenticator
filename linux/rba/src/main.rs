//! `rba`: operator and integration interface to `rbad`.
//!
//! Every subcommand is a thin request to the daemon over its control socket. The
//! CLI performs no authentication decision of its own: it cannot, because it
//! holds no keys and trusts nothing.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use rba_protocol::pairing::CodeEntry;
use rbad::ipc::{ControlRequest, ControlResponse};

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
         \x20   revoke --device D         revoke an authenticator immediately (root only)\n\
         \x20   version                   print the product and protocol version\n\
         \x20   help                      show this help\n\
         \n\
         PAIRING:\n\
         \x20   rba pair --code NNNNNN       pair using an operator-chosen code\n\
         \x20   rba pair --code-entry device  host shows the code; type it on the device (default)\n\
         \x20   rba pair --code-entry host    device shows the code; type it in this terminal\n\
         \n\
         OPTIONS:\n\
         \x20   --socket PATH    control socket (default {DEFAULT_SOCKET})\n\
         \x20   --user NAME      Linux user to authenticate (defaults to $USER)\n\
         \x20   --purpose P      purpose, e.g. sudo, login, polkit  (default authenticate)\n\
         \x20   --service S      PAM service / polkit action       (default rba)\n\
         \x20   --operation O    authenticate or authorize         (default authenticate)\n\
         \x20   -s, --device D   device name or id (default: any connected authenticator)\n\
         \x20   --timeout MS     how long to wait                     (default 90000)\n\
         \x20   --yes            skip the host confirmation prompt (never the code entry)\n\
         \x20   -h, --help       show this help\n\
         \x20   -V, --version    print the product and protocol version\n\
         \n\
         ENVIRONMENT:\n\
         \x20   RBA_SOCKET       control socket (default {DEFAULT_SOCKET})\n\
         \n\
         The 'auth' command performs no cryptography here: it asks the daemon,\n\
         which verifies a signature over a fresh challenge against the registered\n\
         device public key.\n",
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
    user: Option<String>,
    purpose: String,
    service: String,
    operation: String,
    device: Option<String>,
    code: Option<String>,
    code_entry: CodeEntry,
    timeout_ms: u64,
    assume_yes: bool,
}

fn parse() -> Args {
    let mut args = Args {
        socket: std::env::var_os("RBA_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET)),
        command: String::new(),
        user: None,
        purpose: "authenticate".into(),
        service: "rba".into(),
        operation: "authenticate".into(),
        device: None,
        code: None,
        code_entry: CodeEntry::Device,
        timeout_ms: rbad::server::DEFAULT_AUTH_TIMEOUT_MS,
        assume_yes: false,
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
            "--timeout" => args.timeout_ms = v("--timeout").parse().unwrap_or(90_000),
            "--yes" | "-y" => args.assume_yes = true,
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
        format!(
            "cannot reach rbad at {}: {e}\nhint: is the service running? (systemctl status rbad)",
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
    if devices.is_empty() {
        println!("No authenticators are paired.");
        println!();
        println!("Pair one with:  rba pair");
        return;
    }
    println!("Paired authenticators:");
    println!();
    for d in &devices {
        let status = d.get("status").and_then(|v| v.as_str()).unwrap_or("?");
        let avail = if d
            .get("available")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            "available"
        } else {
            "not connected"
        };
        println!(
            "  {}",
            d.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("(unnamed)")
        );
        println!(
            "    id:      {}",
            d.get("device_id").and_then(|v| v.as_str()).unwrap_or("-")
        );
        let key = d.get("key_id").and_then(|v| v.as_str()).unwrap_or("");
        println!(
            "    key:     SHA256:{}...",
            key.chars().take(16).collect::<String>()
        );
        println!("    status:  {status}");
        println!("    link:    {avail}");
        println!(
            "    paired:  {}",
            d.get("summary")
                .and_then(|v| v.as_str())
                .and_then(|s| s.lines().find(|l| l.contains("paired:")))
                .map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string())
                .unwrap_or_default()
        );
        println!();
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
        },
    )
    .unwrap_or_else(|e| {
        eprintln!("rba: {e}");
        std::process::exit(1)
    });
    if !resp.ok {
        fail(&resp);
    }
    let chosen = resp
        .result
        .as_ref()
        .and_then(|r| r.get("chosen_code"))
        .and_then(|c| c.as_str())
        .map(|s| s.to_string());
    let remaining = resp
        .result
        .as_ref()
        .and_then(|r| r.get("seconds_remaining"))
        .and_then(|v| v.as_i64())
        .unwrap_or(120);
    println!("Pairing open for {remaining}s.");
    match args.code_entry {
        CodeEntry::Device => {
            if chosen.is_some() {
                println!(
                    "You chose a code; it will be shown here and must be typed on the device."
                );
            } else {
                println!("Start pairing on the device now.");
            }
        }
        CodeEntry::Host => {
            println!(
                "Start pairing on the device now. The device displays the code; this terminal will not."
            );
            if chosen.is_some() {
                println!("You chose the code, but still type it from the device when asked.");
            }
        }
    }
    println!();

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
            println!("Pairing code (shown only here; enter it on the device):");
            println!();
            println!("      ┌────────────────┐");
            println!("      │  {code}  │");
            println!("      └────────────────┘");
            println!();
            if args.assume_yes {
                println!(
                    "--yes given: skipping the host confirmation prompt. The device still requires the code."
                );
            } else {
                print!("Send this pairing to the device? [y/N] ");
                let _ = std::io::stdout().flush();
                let mut answer = String::new();
                if std::io::stdin().read_line(&mut answer).is_err() {
                    println!("\nno confirmation read; aborting pairing");
                    std::process::exit(1);
                }
                if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
                    println!("Pairing not confirmed; nothing was stored.");
                    std::process::exit(1);
                }
            }
            None
        }
        CodeEntry::Host => {
            println!("The device is displaying the pairing code. Type it here:");
            let entered = loop {
                print!("Code: ");
                let _ = std::io::stdout().flush();
                let mut answer = String::new();
                match std::io::stdin().read_line(&mut answer) {
                    Ok(0) => {
                        println!("\nno code read; aborting pairing");
                        std::process::exit(1);
                    }
                    Ok(_) => {}
                    Err(_) => {
                        println!("\nno code read; aborting pairing");
                        std::process::exit(1);
                    }
                }
                let entered: String = answer.chars().filter(|c| c.is_ascii_digit()).collect();
                if entered == code {
                    break entered;
                }
                println!("That code does not match the device. Try again.");
            };
            Some(entered)
        }
    };

    match request(args, &ControlRequest::ConfirmPairing { code: confirmation }) {
        Ok(r) if r.ok => {}
        Ok(r) => fail(&r),
        Err(e) => {
            eprintln!("rba: {e}");
            std::process::exit(1)
        }
    }
    println!("Confirming pairing…");

    match args.code_entry {
        CodeEntry::Device => {
            println!("Host record saved. Enter the code on the device to finish pairing.")
        }
        CodeEntry::Host => {
            println!("Host record saved. Approve the pairing on the device to finish.")
        }
    }

    // Wait for the daemon to finish the host side. The device may still be asking
    // for its own confirmation; that is deliberately independent.
    for _ in 0..150 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let Ok(r) = request(args, &ControlRequest::Status) else {
            continue;
        };
        let Some(res) = &r.result else { continue };
        let still_open = res
            .get("pairing")
            .and_then(|p| p.get("seconds_remaining"))
            .is_some();
        if !still_open {
            println!("Host side pairing finished.");
            return;
        }
    }
    println!("Host did not finish pairing; check `rba status`.");
    std::process::exit(1);
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
        "version" => cmd_version(),
        "help" => help(),
        other => {
            eprintln!("rba: unknown command {other:?}");
            usage()
        }
    }
}
