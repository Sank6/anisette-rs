use super::{decode_file, encode_file, hardware_binding, provisioning};
use crate::{
    Error, Result,
    engine::{AdiEngine, Otp, SecretBytes, StartedProvisioning},
    identity::{MachineIdentity, WindowsHardware},
    native_otp::{ExportedOtpState, NativeOtpProgram},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs::File, io::Read};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    native_version: u32,
    identity: MachineIdentity,
    hardware: [u8; 20],
    file: SecretBytes,
}

#[derive(Deserialize)]
struct StateKind {
    native_version: Option<u32>,
}

pub struct NativeEngine {
    identity: Option<MachineIdentity>,
    hardware: Option<[u8; 20]>,
    random: Option<File>,
    sessions: BTreeMap<u32, provisioning::Start>,
    sequence: u32,
}

impl NativeEngine {
    pub fn for_hardware(hardware: &WindowsHardware) -> Result<Self> {
        Ok(Self {
            identity: Some(hardware.identity()?),
            hardware: Some(hardware_binding(hardware)?),
            random: Some(File::open("/dev/urandom")?),
            sessions: BTreeMap::new(),
            sequence: 0,
        })
    }
    pub fn stored() -> Self {
        Self {
            identity: None,
            hardware: None,
            random: None,
            sessions: BTreeMap::new(),
            sequence: 0,
        }
    }
    fn random<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut bytes = [0; N];
        self.random
            .as_mut()
            .ok_or(Error::Engine)?
            .read_exact(&mut bytes)?;
        Ok(bytes)
    }
}

impl AdiEngine for NativeEngine {
    fn start(&mut self, identity: &MachineIdentity, spim: &[u8]) -> Result<StartedProvisioning> {
        if self.identity.as_ref() != Some(identity) || self.sessions.len() >= 32 {
            return Err(Error::Identity);
        }
        provisioning::verify_challenge(spim)?;
        let mut selector = Zeroizing::new(self.random::<32>()?);
        for byte in selector.iter_mut() {
            let mut attempts = 0;
            while *byte == 0 {
                if attempts >= 4096 {
                    return Err(Error::Engine);
                }
                *byte = self.random::<1>()?[0];
                attempts += 1;
            }
        }
        let body = Zeroizing::new(self.random::<84>()?);
        let nonce = self.random::<16>()?;
        let seconds = u32::try_from(time::OffsetDateTime::now_utc().unix_timestamp())
            .map_err(|_| Error::State("unsupported provisioning clock"))?;
        let start = provisioning::begin(
            spim,
            &self.hardware.ok_or(Error::Identity)?,
            &selector,
            &body,
            seconds,
            &nonce,
        )?;
        self.sequence = self.sequence.checked_add(1).ok_or(Error::Engine)?;
        let cpim = SecretBytes::new(start.cpim.to_vec());
        let session = self.sequence;
        self.sessions.insert(session, start);
        Ok(StartedProvisioning { session, cpim })
    }

    fn finish(&mut self, session: u32, ptm: &[u8], trust_key: &[u8]) -> Result<SecretBytes> {
        let start = self.sessions.remove(&session).ok_or(Error::Engine)?;
        let profile = provisioning::finish(&start, ptm, trust_key)?;
        let prefix = self.random::<32>()?;
        let iv = self.random::<16>()?;
        let hardware = self.hardware.ok_or(Error::Identity)?;
        let file = encode_file(&profile, &hardware, &prefix, &iv)?;
        let state = Stored {
            native_version: 1,
            identity: self.identity.clone().ok_or(Error::Identity)?,
            hardware,
            file: SecretBytes::new(file),
        };
        Ok(SecretBytes::new(
            serde_json::to_vec(&state).map_err(|_| Error::State("cannot encode native state"))?,
        ))
    }

    fn destroy(&mut self, session: u32) {
        self.sessions.remove(&session);
    }

    fn otp_at(
        &mut self,
        identity: &MachineIdentity,
        state: &[u8],
        unix_seconds: u64,
    ) -> Result<Otp> {
        identity.validate()?;
        if state.len() > crate::MAX_BLOB
            || self
                .identity
                .as_ref()
                .is_some_and(|expected| expected != identity)
        {
            return Err(Error::Identity);
        }
        let kind: StateKind =
            serde_json::from_slice(state).map_err(|_| Error::State("invalid engine material"))?;
        if kind.native_version.is_some() {
            let stored: Stored = serde_json::from_slice(state)
                .map_err(|_| Error::State("invalid native engine material"))?;
            if stored.native_version != 1
                || &stored.identity != identity
                || self
                    .hardware
                    .is_some_and(|expected| expected != stored.hardware)
            {
                return Err(Error::Identity);
            }
            let profile = decode_file(stored.file.as_ref(), &stored.hardware)?;
            return Ok(Otp {
                machine: SecretBytes::new(profile.machine().to_vec()),
                otp: SecretBytes::new(profile.otp_at(unix_seconds)?.to_vec()),
            });
        }
        let exported = ExportedOtpState::from_json(state)?;
        if exported.identity() != identity {
            return Err(Error::Identity);
        }
        NativeOtpProgram::new().generate_at(&exported, unix_seconds)
    }
}
