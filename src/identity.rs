use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsHardware {
    pub mac_address: Vec<u8>,
    pub volume_serial: u32,
    pub product_id: Vec<u8>,
    pub processor_name: Vec<u8>,
    pub bios_version: Vec<u8>,
    pub computer_name: String,
    pub hardware_profile_guid: String,
}

// Omitting Debug prevents identity values from leaking through derived logging.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineIdentity {
    pub device_id: String,
    pub legacy_device_id: String,
    pub local_user: String,
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn widen_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().flat_map(|b| [*b, 0]).collect()
}

fn prefix(bytes: &[u8], upper: bool) -> String {
    let hash = Md5::digest(bytes);
    hex(&hash[..4], upper)
}

pub(crate) fn hex(bytes: &[u8], upper: bool) -> String {
    let alphabet = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(alphabet[(b >> 4) as usize] as char);
        out.push(alphabet[(b & 15) as usize] as char);
    }
    out
}

impl WindowsHardware {
    pub fn identity(&self) -> Result<MachineIdentity> {
        if self.mac_address.len() > 32
            || [&self.product_id, &self.processor_name, &self.bios_version]
                .iter()
                .any(|s| s.len() > 4096 || s.last() == Some(&0))
            || [&self.computer_name, &self.hardware_profile_guid]
                .iter()
                .any(|s| s.len() > 4096 || s.contains('\0'))
        {
            return Err(Error::Identity);
        }
        let volume = self.volume_serial.to_le_bytes();
        let name = utf16le(&self.computer_name);
        let guid = utf16le(&self.hardware_profile_guid);
        let modern: [&[u8]; 7] = [
            &self.mac_address,
            &volume,
            &self.product_id,
            &self.processor_name,
            &self.bios_version,
            &name,
            &guid,
        ];
        let device_id = modern
            .iter()
            .map(|s| prefix(s, true))
            .collect::<Vec<_>>()
            .join(".");
        let legacy_device_id = [
            prefix(&self.mac_address, false),
            prefix(&volume, false),
            prefix(&widen_bytes(&self.bios_version), false),
            prefix(&widen_bytes(&self.processor_name), false),
            prefix(&self.product_id, false),
        ]
        .concat();
        let local_user = hex(&Md5::digest(device_id.as_bytes())[..8], true);
        Ok(MachineIdentity {
            device_id,
            legacy_device_id,
            local_user,
        })
    }
}

impl MachineIdentity {
    pub fn validate(&self) -> Result<()> {
        let upper_hex = |s: &str, n| {
            s.len() == n
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
        };
        let parts: Vec<_> = self.device_id.split('.').collect();
        if parts.len() != 7
            || !parts.iter().all(|s| upper_hex(s, 8))
            || self.legacy_device_id.len() != 40
            || !self
                .legacy_device_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !upper_hex(&self.local_user, 16)
            || self.local_user != hex(&Md5::digest(self.device_id.as_bytes())[..8], true)
        {
            return Err(Error::Identity);
        }
        Ok(())
    }
}
