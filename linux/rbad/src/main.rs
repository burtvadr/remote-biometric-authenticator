//! `rbad` entry point.
//!
//! Usage:
//! ```text
//! rbad [--state-dir DIR] [--socket PATH] [--audit-log PATH]
//!             [--port N] [--transport wifi|ble] [--no-mdns]
//!             [--device HOST:PORT] [--foreground] [--check]
//! ```
//!
//! `--check` validates the configuration and exits without listening, which is
//! what a package post-install script should run.

use std::sync::Arc;

use rba_protocol::types::Transport;
use rbad::config::Config;
use rbad::{server, Daemon};

fn usage() -> ! {
    eprintln!(
        "rbad {}\n\
         \n\
         USAGE:\n    rbad [OPTIONS]\n\
         \n\
         OPTIONS:\n\
         \x20   --state-dir DIR    root-only state directory (default /var/lib/rba)\n\
         \x20   --socket PATH      control socket (default /run/rba/control.sock)\n\
         \x20   --audit-log PATH   audit log (default /var/log/rba/audit.log)\n\
         \x20   --port N           TCP port for the Wi-Fi transport (default 47123)\n\
         \x20   --transport T      transport preference: wifi or ble\n\
         \x20   --device HOST:PORT fixed device endpoint, used when mDNS is unavailable\n\
         \x20   --host-name NAME   operator-visible host label (default from the hostname)\n\
         \x20   --no-mdns          do not advertise over DNS-SD\n\
         \x20   --check            validate configuration and exit\n\
         \x20   -h, --help         show this help\n",
        rba_protocol::VERSION
    );
    std::process::exit(2)
}

struct Args {
    config: Config,
    check: bool,
}

fn parse_args() -> Args {
    let mut config = Config::default();
    let mut check = false;
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        let mut value = |flag: &str| -> String {
            match argv.next() {
                Some(v) => v,
                None => {
                    eprintln!("rbad: {flag} requires a value");
                    std::process::exit(2)
                }
            }
        };
        match arg.as_str() {
            "--state-dir" => config.state_dir = value("--state-dir").into(),
            "--socket" => config.socket_path = value("--socket").into(),
            "--audit-log" => config.audit_log = value("--audit-log").into(),
            "--port" => {
                let p: u16 = value("--port").parse().unwrap_or_else(|_| {
                    eprintln!("rbad: --port must be a number");
                    std::process::exit(2)
                });
                config.tcp_port = p;
                config.bind_addr.set_port(p);
            }
            "--transport" => {
                config.transport = match value("--transport").as_str() {
                    "wifi" => Transport::Wifi,
                    "ble" | "bluetooth" => Transport::Ble,
                    other => {
                        eprintln!("rbad: unknown transport {other:?} (want wifi or ble)");
                        std::process::exit(2)
                    }
                }
            }
            "--bind" => {
                let s = value("--bind");
                match s.parse() {
                    Ok(a) => config.bind_addr = a,
                    Err(_) => {
                        eprintln!("rbad: --bind must be an IP:PORT address");
                        std::process::exit(2)
                    }
                }
            }
            "--device" => {
                let s = value("--device");
                match s.rsplit_once(':') {
                    Some((h, p)) => match p.parse() {
                        Ok(port) => {
                            config.device_endpoint = Some(rbad::config::SocketEndpoint {
                                host: h.to_string(),
                                port,
                            })
                        }
                        Err(_) => {
                            eprintln!("rbad: --device must be HOST:PORT");
                            std::process::exit(2)
                        }
                    },
                    None => {
                        eprintln!("rbad: --device must be HOST:PORT");
                        std::process::exit(2)
                    }
                }
            }
            "--host-name" => config.host_name = Some(value("--host-name")),
            "--no-mdns" => config.advertise_mdns = false,
            "--check" => check = true,
            "-h" | "--help" => usage(),
            other => {
                eprintln!("rbad: unknown option {other:?}");
                usage()
            }
        }
    }
    Args { config, check }
}

fn main() {
    let args = parse_args();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("rbad: cannot start the async runtime: {e}");
            std::process::exit(1);
        }
    };

    if args.check {
        // --check must work before anything privileged exists, so it does not
        // open the audit log or bind any socket.
        let daemon = match Daemon::bootstrap_check(args.config.clone()) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("rbad: {e}");
                std::process::exit(1);
            }
        };
        println!(
            "configuration ok\n  state dir : {}\n  socket    : {}\n  audit log : {}\n  host id   : {}\n  paired    : {}",
            daemon.config.state_dir.display(),
            daemon.config.socket_path.display(),
            daemon.config.audit_log.display(),
            daemon.engine.host.host_id,
            daemon.engine.list_devices().len()
        );
        return;
    }

    let daemon = match Daemon::bootstrap(args.config.clone(), false) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("rbad: {e}");
            std::process::exit(1);
        }
    };

    let config = daemon.config.clone();
    let engine = daemon.engine.clone();

    runtime.block_on(async move {
        let (tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                let _ = tx.send(true);
            }
        });
        eprintln!(
            "rbad {} listening: control {} , {} , transport {:?}",
            rba_protocol::VERSION,
            config.socket_path.display(),
            config.bind_addr,
            config.transport
        );
        let engine = Arc::clone(&engine);
        if let Err(e) = server::run(engine, config, rx).await {
            eprintln!("rbad: {e}");
            std::process::exit(1);
        }
    });
}
