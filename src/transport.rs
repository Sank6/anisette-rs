use crate::{
    CLIENT_INFO, Error, MAX_BLOB, Result, USER_AGENT, engine::SecretBytes,
    identity::MachineIdentity,
};
use reqwest::{Certificate, blocking::Client, redirect::Policy};
use sha2::{Digest, Sha256};
use std::{io::Read, time::Duration};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub trait ProvisioningTransport {
    fn post(&mut self, path: &str, identity: &MachineIdentity, body: &[u8]) -> Result<SecretBytes>;
}

pub fn client_time() -> Result<String> {
    OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|_| Error::Protocol)?
        .format(&Rfc3339)
        .map_err(|_| Error::Protocol)
}

const ROOT_SHA256: [u8; 32] = [
    0xb0, 0xb1, 0x73, 0x0e, 0xcb, 0xc7, 0xff, 0x45, 0x05, 0x14, 0x2c, 0x49, 0xf1, 0x29, 0x5e, 0x6e,
    0xda, 0x6b, 0xca, 0xed, 0x7e, 0x2c, 0x68, 0xc5, 0xbe, 0x91, 0xb5, 0xa1, 0x10, 0x01, 0xf0, 0x24,
];

pub struct AppleTransport {
    client: Client,
}

impl AppleTransport {
    pub fn new(apple_root_der: &[u8]) -> Result<Self> {
        if apple_root_der.len() > 64 * 1024
            || Sha256::digest(apple_root_der).as_slice() != ROOT_SHA256
        {
            return Err(Error::Certificate);
        }
        let cert = Certificate::from_der(apple_root_der).map_err(|_| Error::Certificate)?;
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .add_root_certificate(cert)
            .https_only(true)
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| Error::Transport)?;
        Ok(Self { client })
    }
}

impl ProvisioningTransport for AppleTransport {
    fn post(&mut self, path: &str, identity: &MachineIdentity, body: &[u8]) -> Result<SecretBytes> {
        let response = self
            .client
            .post(format!("https://gsa.apple.com{path}"))
            .header("Content-Type", "text/xml")
            .header("X-Apple-Client-App-Name", "Setup")
            .header("X-Mme-Client-Info", CLIENT_INFO)
            .header("X-Mme-Device-Id", &identity.device_id)
            .header("X-Mme-Legacy-Device-Id", &identity.legacy_device_id)
            .header("X-Apple-I-MD-LU", &identity.local_user)
            .header("X-Apple-I-Client-Time", client_time()?)
            .body(body.to_vec())
            .send()
            .map_err(|_| Error::Transport)?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|n| n > MAX_BLOB as u64)
        {
            return Err(Error::Transport);
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_BLOB as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Transport)?;
        if bytes.len() > MAX_BLOB {
            return Err(Error::Transport);
        }
        let response = SecretBytes::new(bytes);
        if status != 200 {
            return Err(Error::Transport);
        }
        Ok(response)
    }
}
