use anisette_rs::{
    Error, Result,
    engine::provision,
    factory::Factory,
    identity::{MachineIdentity, WindowsHardware},
    native_adi::NativeEngine,
    native_otp::{ExportedOtpState, NativeOtpProgram},
    store::{StateStore, read_private_bytes},
    transport::AppleTransport,
};
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::{
    fs::File,
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    version,
    about = "Native Windows anisette provisioning and header generation"
)]
struct Cli {
    /// Directory containing identity and provisioned state.
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    /// Optional research factory configuration.
    #[arg(long, global = true)]
    factory: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Derive anisette identity metadata from Windows hardware values.
    Identity {
        #[arg(long)]
        hardware: PathBuf,
    },
    /// Report native capabilities, or validate an explicit research factory.
    Doctor,
    /// Provision the configured identity with Apple.
    Provision {
        #[arg(long)]
        apple_root: PathBuf,
        /// Explicit Windows hardware inputs for a fresh native identity.
        #[arg(long)]
        hardware: Option<PathBuf>,
    },
    /// Generate anisette headers.
    Headers {
        /// Optional proof reference to validate for compatibility.
        #[arg(long, requires = "exported_state")]
        circuit: Option<PathBuf>,
        #[arg(long)]
        exported_state: Option<PathBuf>,
    },
    /// Serve anisette headers over loopback HTTP.
    Serve {
        #[arg(long, default_value = "127.0.0.1")]
        host: IpAddr,
        #[arg(long, default_value_t = 6970)]
        port: u16,
    },
}

fn state_path(override_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return Ok(path);
    }
    if let Some(path) = std::env::var_os("ANISETTE_RS_HOME") {
        return Ok(path.into());
    }
    let base = std::env::var_os("XDG_DATA_HOME").map_or_else(
        || {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .ok_or(Error::State("HOME is not set"))
                .map(|path| path.join(".local/share"))
        },
        |path| Ok(PathBuf::from(path)),
    )?;
    Ok(base.join("anisette-rs"))
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(Error::State("input file size or type"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(Error::State("input file too large"));
    }
    Ok(bytes)
}

fn hardware(path: &Path) -> Result<WindowsHardware> {
    serde_json::from_slice(&read_bounded(path, 64 * 1024)?).map_err(|_| Error::Identity)
}

fn json(value: &impl Serialize) -> Result<()> {
    let bytes =
        serde_json::to_vec_pretty(value).map_err(|_| Error::State("cannot encode output"))?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&bytes)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

fn open_factory(path: Option<PathBuf>) -> Result<Factory> {
    Factory::open(&path.ok_or(Error::State("--factory is required"))?)
}

fn provision_store(state_dir: Option<PathBuf>, identity: &MachineIdentity) -> Result<StateStore> {
    let store = StateStore::open(&state_path(state_dir)?)?;
    match store.identity() {
        Ok(stored) if stored == *identity => {}
        Ok(_) => return Err(Error::State("stored identity does not match factory")),
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            store.initialize(identity)?;
        }
        Err(error) => return Err(error),
    }
    Ok(store)
}

fn existing_store(state_dir: Option<PathBuf>, identity: &MachineIdentity) -> Result<StateStore> {
    let store = StateStore::open(&state_path(state_dir)?)?;
    if store.identity()? != *identity {
        return Err(Error::State("stored identity does not match factory"));
    }
    Ok(store)
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Identity { hardware: path } => json(&hardware(&path)?.identity()?),
        Command::Doctor => {
            if let Some(path) = cli.factory {
                open_factory(Some(path))?;
            }
            json(&serde_json::json!({
                "status": "ready",
                "provisioning": true,
                "header_generation": true
            }))
        }
        Command::Provision {
            apple_root,
            hardware: hardware_path,
        } if cli.factory.is_none() => {
            let store = StateStore::open(&state_path(cli.state_dir)?)?;
            if store.is_provisioned()? {
                let mut engine = match hardware_path {
                    Some(path) => NativeEngine::for_hardware(&hardware(&path)?)?,
                    None => NativeEngine::stored(),
                };
                store.load()?.headers(&mut engine)?;
                return json(&serde_json::json!({"provisioned":true,"reused":true}));
            }
            let inputs = hardware(&hardware_path.ok_or(Error::State(
                "--hardware is required for fresh native provisioning",
            ))?)?;
            let identity = inputs.identity()?;
            match store.identity() {
                Ok(saved) if saved == identity => {}
                Ok(_) => {
                    return Err(Error::State(
                        "stored identity does not match hardware inputs",
                    ));
                }
                Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                    store.initialize(&identity)?
                }
                Err(error) => return Err(error),
            }
            let mut engine = NativeEngine::for_hardware(&inputs)?;
            let mut transport = AppleTransport::new(&read_bounded(&apple_root, 64 * 1024)?)?;
            let device = provision(&mut engine, &mut transport, identity)?;
            store.commit(&device)?;
            json(&serde_json::json!({"provisioned":true,"reused":false}))
        }
        Command::Provision { apple_root, .. } => {
            let mut factory = open_factory(cli.factory)?;
            let store = provision_store(cli.state_dir, factory.identity())?;
            if store.is_provisioned()? {
                return json(&serde_json::json!({"provisioned": true, "reused": true}));
            }
            let mut transport = AppleTransport::new(&read_bounded(&apple_root, 64 * 1024)?)?;
            let device = provision(&mut factory, &mut transport, store.identity()?)?;
            store.commit(&device)?;
            json(&serde_json::json!({"provisioned": true, "reused": false}))
        }
        Command::Serve { host, port } if cli.factory.is_none() => {
            anisette_rs::server::require_loopback(host)?;
            let store = StateStore::open(&state_path(cli.state_dir)?)?;
            let service =
                anisette_rs::server::NativeService::new(NativeEngine::stored(), store.load()?)?;
            anisette_rs::server::serve(SocketAddr::new(host, port), service)
        }
        Command::Serve { host, port } => {
            anisette_rs::server::require_loopback(host)?;
            let factory = open_factory(cli.factory)?;
            let store = existing_store(cli.state_dir, factory.identity())?;
            let service = anisette_rs::server::NativeService::new(factory, store.load()?)?;
            anisette_rs::server::serve(SocketAddr::new(host, port), service)
        }
        Command::Headers {
            circuit,
            exported_state: Some(state),
        } => {
            let program = match circuit {
                Some(path) => {
                    NativeOtpProgram::from_json(&read_private_bytes(&path, 64 * 1024 * 1024)?)?
                }
                None => NativeOtpProgram::new(),
            };
            let state = ExportedOtpState::from_json(&read_private_bytes(&state, 64 * 1024)?)?;
            let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
            json(&program.headers_at(&state, now)?)
        }
        Command::Headers {
            circuit: None,
            exported_state: None,
        } if cli.factory.is_none() => {
            let store = StateStore::open(&state_path(cli.state_dir)?)?;
            json(&store.load()?.headers(&mut NativeEngine::stored())?)
        }
        Command::Headers {
            circuit: None,
            exported_state: None,
        } => {
            let mut factory = open_factory(cli.factory)?;
            let store = existing_store(cli.state_dir, factory.identity())?;
            json(&store.load()?.headers(&mut factory)?)
        }
        Command::Headers { .. } => unreachable!("clap requires both standalone header inputs"),
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("anisette-rs: {error}");
            ExitCode::FAILURE
        }
    }
}
