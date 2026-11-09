//! Provisioning orchestration and secret-bearing runtime types.

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{collections::BTreeMap, fmt};
use zeroize::Zeroizing;

use crate::{
    CLIENT_INFO, Error, MAX_BLOB, Result, identity::MachineIdentity, protocol,
    transport::ProvisioningTransport,
};

/// Opaque engine/server bytes. Debug is redacted and owned bytes are zeroed on drop.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for SecretBytes {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let encoded = Zeroizing::new(STANDARD.encode(self.as_ref()));
        s.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let encoded = Zeroizing::new(String::deserialize(d)?);
        let bytes = STANDARD
            .decode(encoded.as_bytes())
            .map_err(|_| de::Error::custom("invalid opaque state"))?;
        if bytes.is_empty() || bytes.len() > MAX_BLOB {
            return Err(de::Error::custom("invalid opaque state size"));
        }
        Ok(Self::new(bytes))
    }
}

pub struct StartedProvisioning {
    pub session: u32,
    pub cpim: SecretBytes,
}

pub struct Otp {
    pub machine: SecretBytes,
    pub otp: SecretBytes,
}

pub trait AdiEngine {
    fn start(&mut self, identity: &MachineIdentity, spim: &[u8]) -> Result<StartedProvisioning>;
    fn finish(&mut self, session: u32, ptm: &[u8], trust_key: &[u8]) -> Result<SecretBytes>;
    fn destroy(&mut self, session: u32);
    fn otp_at(
        &mut self,
        identity: &MachineIdentity,
        state: &[u8],
        unix_seconds: u64,
    ) -> Result<Otp>;
}

struct Session<'a, E: AdiEngine> {
    engine: &'a mut E,
    id: u32,
}
impl<E: AdiEngine> Drop for Session<'_, E> {
    fn drop(&mut self) {
        if self.id != 0 {
            self.engine.destroy(self.id);
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionedDevice {
    pub identity: MachineIdentity,
    pub routing_info: u64,
    pub engine_state: SecretBytes,
}

impl ProvisionedDevice {
    pub fn validate(&self) -> Result<()> {
        if self.engine_state.as_ref().is_empty() || self.engine_state.as_ref().len() > MAX_BLOB {
            return Err(Error::State("invalid engine material"));
        }
        self.identity.validate()
    }

    pub fn headers<E: AdiEngine>(&self, engine: &mut E) -> Result<BTreeMap<String, String>> {
        self.validate()?;
        let timestamp = time::OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .map_err(|_| Error::Protocol)?;
        let now = timestamp
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| Error::Protocol)?;
        let unix_seconds = timestamp.unix_timestamp() as u64;
        let otp = engine.otp_at(&self.identity, self.engine_state.as_ref(), unix_seconds)?;
        Ok(format_headers(&self.identity, self.routing_info, &otp, now))
    }
}

pub(crate) fn format_headers(
    identity: &MachineIdentity,
    routing_info: u64,
    otp: &Otp,
    now: String,
) -> BTreeMap<String, String> {
    [
        ("X-Apple-I-Client-Time", now.clone()),
        ("X-Apple-Client-Time", now),
        ("X-Apple-I-MD", STANDARD.encode(otp.otp.as_ref())),
        ("X-Apple-I-MD-M", STANDARD.encode(otp.machine.as_ref())),
        ("X-Apple-I-MD-LU", identity.local_user.clone()),
        ("X-Apple-I-MD-RINFO", routing_info.to_string()),
        ("X-Apple-I-SRL-NO", "0".into()),
        ("X-Apple-I-TimeZone", "UTC".into()),
        ("X-Apple-Locale", "en_US".into()),
        ("X-MMe-Client-Info", CLIENT_INFO.into()),
        ("X-Mme-Device-Id", identity.device_id.clone()),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v))
    .collect()
}

pub fn provision<E: AdiEngine, T: ProvisioningTransport>(
    engine: &mut E,
    transport: &mut T,
    identity: MachineIdentity,
) -> Result<ProvisionedDevice> {
    identity.validate()?;
    let start = transport.post(
        protocol::START_PATH,
        &identity,
        protocol::start_request()?.as_ref(),
    )?;
    let spim = protocol::parse_start(start.as_ref())?;
    let started = engine.start(&identity, spim.as_ref())?;
    let session = Session {
        engine,
        id: started.session,
    };
    let body = protocol::finish_request(started.cpim.as_ref())?;
    let finish = transport.post(protocol::FINISH_PATH, &identity, body.as_ref())?;
    let finish = protocol::parse_finish(finish.as_ref())?;
    let engine_state =
        session
            .engine
            .finish(session.id, finish.ptm.as_ref(), finish.trust_key.as_ref())?;
    let device = ProvisionedDevice {
        identity,
        routing_info: finish.routing_info,
        engine_state,
    };
    drop(session);
    Ok(device)
}
