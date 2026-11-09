//! State files contain identity and provisioning secrets and are never logged.

use crate::{Error, Result, engine::ProvisionedDevice, identity::MachineIdentity};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const MAX_STATE: u64 = 2 * 1024 * 1024;

pub struct StateStore {
    root: PathBuf,
    _lock: File,
}

fn private_file(file: &File) -> Result<()> {
    let info = file.metadata()?;
    // SAFETY: geteuid has no arguments or pointer preconditions.
    if !info.is_file() || info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o777 != 0o600 {
        return Err(Error::State(
            "files must be regular, owned by this user, and mode 0600",
        ));
    }
    Ok(())
}

pub fn read_private_bytes(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    private_file(&file)?;
    if file.metadata()?.len() > limit {
        return Err(Error::State("file is too large"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(Error::State("file is too large"));
    }
    Ok(bytes)
}

impl StateStore {
    pub fn open(path: &Path) -> Result<Self> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)?;
        let info = fs::symlink_metadata(path)?;
        // SAFETY: geteuid has no arguments or pointer preconditions.
        if !info.is_dir()
            || info.uid() != unsafe { libc::geteuid() }
            || info.mode() & 0o777 != 0o700
        {
            return Err(Error::State(
                "directory must be real, owned by this user, and mode 0700",
            ));
        }
        let root = fs::canonicalize(path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(root.join(".lock"))?;
        private_file(&lock)?;
        // SAFETY: lock owns a live descriptor; flock takes no borrowed pointers.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Err(Error::Locked);
            }
            return Err(Error::Io(err));
        }
        Ok(Self { root, _lock: lock })
    }

    pub(crate) fn read<T: DeserializeOwned>(&self, name: &str) -> Result<T> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(self.root.join(name))?;
        private_file(&file)?;
        if file.metadata()?.len() > MAX_STATE {
            return Err(Error::State("file is too large"));
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(MAX_STATE + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_STATE {
            return Err(Error::State("file is too large"));
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::State("invalid JSON or state schema"))
    }

    pub(crate) fn write<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(value).map_err(|_| Error::State("cannot encode state"))?,
        );
        if bytes.len() as u64 > MAX_STATE {
            return Err(Error::State("file is too large"));
        }
        let destination = self.root.join(name);
        match fs::symlink_metadata(&destination) {
            Ok(info) if !info.is_file() => {
                return Err(Error::State("destination must be a regular file"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let temp = self
            .root
            .join(format!(".{name}.{}.tmp", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)?;
        let result = (|| {
            private_file(&file)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temp, destination)?;
            File::open(&self.root)?.sync_all()?;
            Ok(())
        })();
        if temp.try_exists()? {
            fs::remove_file(temp)?;
        }
        result
    }

    pub fn initialize(&self, identity: &MachineIdentity) -> Result<()> {
        identity.validate()?;
        match fs::symlink_metadata(self.root.join("identity.json")) {
            Ok(_) => {
                return Err(Error::State(
                    "identity already exists; refusing to replace it",
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::Io(e)),
        }
        self.write("identity.json", identity)
    }

    pub fn identity(&self) -> Result<MachineIdentity> {
        let identity: MachineIdentity = self.read("identity.json")?;
        identity.validate()?;
        Ok(identity)
    }

    pub fn load(&self) -> Result<ProvisionedDevice> {
        let device: ProvisionedDevice = self.read("device.json")?;
        device.validate()?;
        if device.identity != self.identity()? {
            return Err(Error::State("provisioning identity mismatch"));
        }
        Ok(device)
    }

    pub fn commit(&self, device: &ProvisionedDevice) -> Result<()> {
        device.validate()?;
        if device.identity != self.identity()? {
            return Err(Error::State("provisioning identity mismatch"));
        }
        self.write("device.json", device)
    }

    pub fn is_provisioned(&self) -> Result<bool> {
        match fs::symlink_metadata(self.root.join("device.json")) {
            Ok(_) => {
                self.load()?;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::Io(e)),
        }
    }
}
