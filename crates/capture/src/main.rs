//! `silentsnake-capture`: stage A capture engine. Events go to stdout as JSON lines.

#![forbid(unsafe_code)]

use silentsnake_capture::engine::EngineConfig;
use silentsnake_capture::privilege;
use silentsnake_capture::source::{self, RunConfig, RunError, Source};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "\
silentsnake-capture: SilentSnake stage A capture engine (libpcap)

USAGE:
    silentsnake-capture [OPTIONS]

Events are written to stdout as JSON lines (schema silentsnake.capture/1). Nothing is
written to disk. Do not redirect the output to a file: stage A has no encryption yet.

OPTIONS:
    -i, --interface NAME    Live capture on NAME (default: any = all interfaces)
    -r, --read FILE         Read a pcap/pcapng file instead (needs no privileges)
    -f, --filter EXPR       BPF filter, e.g. \"tcp port 443 or udp port 53\"
        --duration SECS     Stop after SECS seconds
        --count N           Stop after N packets
        --stats SECS        Live stats event interval (default 30; 0 = off)
        --max-flows N       Flow table bound (default 65536)
        --local-addr IP     Treat IP as this machine (repeatable; for --read)
        --list-interfaces   List capture interfaces and exit
    -h, --help              Show this help
    -V, --version           Show the version

Live capture needs CAP_NET_RAW on this binary (never root):
    sudo setcap cap_net_raw=ep \"$(command -v silentsnake-capture)\"
";

enum Cli {
    Run(Box<RunConfig>),
    List,
    Help,
    Version,
}

fn value<'a>(
    args: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<&'a String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}

fn number<T: std::str::FromStr>(s: &str, flag: &str) -> Result<T, String> {
    s.parse()
        .map_err(|_| format!("{flag}: not a valid number: {}", s.escape_default()))
}

fn parse(args: &[String], identity: privilege::Identity) -> Result<Cli, String> {
    let mut interface: Option<String> = None;
    let mut read: Option<PathBuf> = None;
    let mut cfg = RunConfig {
        source: Source::Live {
            interface: "any".into(),
        },
        filter: None,
        duration: None,
        max_packets: None,
        stats_interval: Some(Duration::from_secs(30)),
        local_addrs: Vec::new(),
        engine: EngineConfig::default(),
        identity,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => return Ok(Cli::Help),
            "-V" | "--version" => return Ok(Cli::Version),
            "--list-interfaces" => return Ok(Cli::List),
            "-i" | "--interface" => interface = Some(value(&mut it, a)?.clone()),
            "-r" | "--read" => read = Some(PathBuf::from(value(&mut it, a)?)),
            "-f" | "--filter" => cfg.filter = Some(value(&mut it, a)?.clone()),
            "--duration" => {
                cfg.duration = Some(Duration::from_secs(number(value(&mut it, a)?, a)?))
            }
            "--count" => cfg.max_packets = Some(number(value(&mut it, a)?, a)?),
            "--stats" => {
                let s: u64 = number(value(&mut it, a)?, a)?;
                cfg.stats_interval = (s > 0).then(|| Duration::from_secs(s));
            }
            "--max-flows" => {
                let n: usize = number(value(&mut it, a)?, a)?;
                if !(16..=10_000_000).contains(&n) {
                    return Err("--max-flows must be between 16 and 10000000".into());
                }
                cfg.engine.max_flows = n;
            }
            "--local-addr" => {
                let v = value(&mut it, a)?;
                let ip: IpAddr = v.parse().map_err(|_| {
                    format!("--local-addr: not an IP address: {}", v.escape_default())
                })?;
                cfg.local_addrs.push(ip);
            }
            other => return Err(format!("unknown argument: {}", other.escape_default())),
        }
    }
    cfg.source = match (interface, read) {
        (Some(_), Some(_)) => return Err("use either --interface or --read, not both".into()),
        (_, Some(path)) => Source::File { path },
        (Some(interface), None) => Source::Live { interface },
        (None, None) => cfg.source,
    };
    Ok(Cli::Run(Box::new(cfg)))
}

fn main() -> ExitCode {
    // Least privilege first, before touching any capture handle (fails closed).
    let identity = match privilege::current().and_then(|id| privilege::check(&id).map(|()| id)) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("silentsnake-capture: {e}");
            return ExitCode::from(3);
        }
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = match parse(&args, identity) {
        Ok(Cli::Run(cfg)) => cfg,
        Ok(Cli::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Cli::Version) => {
            println!("silentsnake-capture {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Ok(Cli::List) => {
            return match pcap::Device::list() {
                Ok(devs) => {
                    for d in devs {
                        let flags = match (d.flags.is_loopback(), d.flags.is_up()) {
                            (true, _) => "loopback",
                            (false, true) => "up",
                            (false, false) => "down",
                        };
                        println!("{}\t{flags}\t{}", d.name, d.desc.unwrap_or_default());
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("silentsnake-capture: cannot list interfaces: {e}");
                    ExitCode::FAILURE
                }
            };
        }
        Err(e) => {
            eprintln!("silentsnake-capture: {e}\nRun with --help for usage.");
            return ExitCode::from(2);
        }
    };
    let live = matches!(cfg.source, Source::Live { .. });
    match source::run(&cfg, std::io::stdout().lock()) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("silentsnake-capture: {e}");
            if live && matches!(e, RunError::Open(_)) && !identity.has_cap_net_raw() {
                eprintln!(
                    "Live capture needs CAP_NET_RAW on this binary (not root):\n  \
                     sudo setcap cap_net_raw=ep \"$(command -v silentsnake-capture)\"\n\
                     Reading a file with --read needs no privileges."
                );
            }
            ExitCode::FAILURE
        }
    }
}
