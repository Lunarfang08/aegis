#![forbid(unsafe_code)]
use aegis_core::*;
use clap::{Parser, Subcommand};
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(
    name = "aegis",
    version,
    about = "Offline AI governance evidence compiler"
)]
struct Cli {
    #[arg(long, global = true)]
    strict: bool,
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    no_color: bool,
    #[arg(long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Inspect(Input),
    Verify(Input),
    Map(Input),
    Report(ReportArgs),
    Mappings {
        #[command(subcommand)]
        command: MappingCommand,
    },
    Schema {
        #[arg(value_parser = ["evidence", "mapping", "report", "request", "trust-store"])]
        name: String,
    },
}
#[derive(Subcommand)]
enum MappingCommand {
    List,
}
#[derive(clap::Args)]
struct Input {
    path: PathBuf,
    #[arg(long, default_value = "nist-ai-rmf")]
    framework: String,
    #[arg(long)]
    trust_store: Option<PathBuf>,
    #[arg(long, default_value = "Untitled AI system")]
    system: String,
}
#[derive(clap::Args)]
struct ReportArgs {
    #[command(flatten)]
    input: Input,
    #[arg(long, default_value = "html", value_parser = ["md", "html", "json"])]
    format: String,
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}
fn load(input: &Input) -> Result<Request, String> {
    if !input.path.exists() {
        return Err("Input path does not exist".into());
    }
    let mut files = Vec::new();
    let mut total = 0u64;
    let trust_path = input
        .trust_store
        .as_ref()
        .map(fs::canonicalize)
        .transpose()
        .map_err(|e| e.to_string())?;
    let base = if input.path.is_dir() {
        input.path.as_path()
    } else {
        input.path.parent().unwrap_or(std::path::Path::new("."))
    };
    for entry in walkdir::WalkDir::new(&input.path)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_type().is_symlink() {
            return Err(format!(
                "Symlinks are not accepted: {}",
                entry.path().display()
            ));
        }
        if !entry.file_type().is_file() {
            continue;
        }
        if trust_path
            .as_ref()
            .is_some_and(|t| fs::canonicalize(entry.path()).ok().as_ref() == Some(t))
        {
            continue;
        }
        let size = entry.metadata().map_err(|e| e.to_string())?.len();
        total += size;
        if size > MAX_FILE as u64 || total > MAX_TOTAL as u64 || files.len() >= MAX_FILES {
            return Err("Input exceeds 10 MB/file, 100 MB total, or 1,000 files".into());
        }
        let name = entry
            .path()
            .strip_prefix(base)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(entry.path()).map_err(|e| e.to_string())?;
        // Core uses the same transport representation in native and browser builds.
        files.push(
            serde_json::from_value(serde_json::json!({"name":name,"data":encode(&bytes)}))
                .map_err(|e| e.to_string())?,
        );
    }
    let trust_store = input
        .trust_store
        .as_ref()
        .map(|p| {
            fs::read_to_string(p)
                .map_err(|e| e.to_string())
                .and_then(|s| {
                    serde_json::from_str(&s).map_err(|e| format!("Invalid trust store: {e}"))
                })
        })
        .transpose()?
        .unwrap_or_default();
    Ok(Request {
        files,
        trust_store,
        framework: input.framework.clone(),
        system: input.system.clone(),
    })
}
// Base64 transport encoding without an additional CLI dependency.
fn encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = ((c[0] as u32) << 16)
            | ((c.get(1).copied().unwrap_or(0) as u32) << 8)
            | c.get(2).copied().unwrap_or(0) as u32;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if c.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
fn run(cli: &Cli) -> Result<i32, String> {
    match &cli.command {
        Command::Mappings { .. } => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&frameworks()).map_err(|e| e.to_string())?
                );
            } else if !cli.quiet {
                for f in frameworks() {
                    println!("{}\t{}\t{}", f.id, f.version, f.status);
                }
            }
            Ok(0)
        }
        Command::Schema { name } => {
            let schema = match name.as_str() {
                "evidence" => schemars::schema_for!(Evidence),
                "mapping" => schemars::schema_for!(Framework),
                "request" => schemars::schema_for!(Request),
                "trust-store" => schemars::schema_for!(TrustStore),
                _ => schemars::schema_for!(Report),
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).map_err(|e| e.to_string())?
            );
            Ok(0)
        }
        command => {
            let (input, mode) = match command {
                Command::Inspect(i) => (i, "inspect"),
                Command::Verify(i) => (i, "verify"),
                Command::Map(i) => (i, "map"),
                Command::Report(a) => (&a.input, "report"),
                _ => unreachable!(),
            };
            let report = analyze(load(input)?)?;
            if let Command::Report(args) = command {
                let output = render(&report, &args.format)?;
                if let Some(path) = &args.output {
                    // Do not overwrite any input or the explicitly supplied trust store.
                    let target = if path.exists() {
                        fs::canonicalize(path).map_err(|e| e.to_string())?
                    } else {
                        let parent = path
                            .parent()
                            .filter(|p| !p.as_os_str().is_empty())
                            .unwrap_or(std::path::Path::new("."));
                        fs::canonicalize(parent)
                            .map_err(|e| e.to_string())?
                            .join(path.file_name().ok_or("Output must name a file")?)
                    };
                    if target.starts_with(fs::canonicalize(&input.path).map_err(|e| e.to_string())?)
                        || input
                            .trust_store
                            .as_ref()
                            .is_some_and(|p| fs::canonicalize(p).ok().as_ref() == Some(&target))
                    {
                        return Err(
                            "Report output must be outside the input path and trust store".into(),
                        );
                    }
                    fs::write(path, output).map_err(|e| e.to_string())?;
                    if !cli.quiet {
                        println!("Report written to {}", path.display());
                    }
                } else if !cli.quiet {
                    println!("{output}");
                }
            } else if cli.json {
                println!("{}", render(&report, "json")?);
            } else if !cli.quiet {
                println!(
                    "AEGIS / {}\n{} · draft mappings\n",
                    report.system, report.framework.title
                );
                println!(
                    "{} files · {} accepted · {} rejected · {} evidence items",
                    report.summary.files,
                    report.summary.accepted,
                    report.summary.rejected,
                    report.summary.evidence
                );
                for i in &report.inputs {
                    println!(
                        "  {}  {}{}",
                        if i.accepted { "ACCEPTED" } else { "REJECTED" },
                        i.name,
                        i.reason
                            .as_ref()
                            .map(|r| format!(" — {r}"))
                            .unwrap_or_default()
                    );
                }
                if mode != "inspect" {
                    for e in &report.evidence {
                        println!("  {}  {}", e.status.to_uppercase(), e.title);
                        for c in &e.checks {
                            println!("    {} / {}: {}", c.name, c.status, c.reason);
                        }
                    }
                    if mode != "verify" {
                        for c in &report.controls {
                            println!("  {}  {} · {}", c.status.to_uppercase(), c.id, c.title);
                        }
                    }
                }
                println!("\nWhat this does not prove\n{}", report.limitations);
            }
            Ok(exit_code(&report, mode, cli.strict))
        }
    }
}
fn main() {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            if cli.json {
                eprintln!("{}", serde_json::json!({"error":e}));
            } else {
                eprintln!("aegis: {e}");
            }
            std::process::exit(3);
        }
    }
}
