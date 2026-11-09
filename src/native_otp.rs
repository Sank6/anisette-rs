use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    crypto::{adi_compression, adi_proof, adi_seed},
    engine::{Otp, SecretBytes, format_headers},
    identity::{MachineIdentity, hex},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportedOtpState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<u32>,
    profile_sha256: String,
    identity: MachineIdentity,
    routing_info: u64,
    template: SecretBytes,
    lanes: SecretBytes,
    machine: SecretBytes,
    otp_prefix: SecretBytes,
    otp_suffix: SecretBytes,
}

impl ExportedOtpState {
    pub(crate) fn decoded(identity: MachineIdentity, fingerprint: String, bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), 392);
        let mut template = bytes[..304].to_vec();
        template.resize(336, 0);
        Self {
            version: None,
            profile_sha256: fingerprint,
            identity,
            routing_info: 0,
            template: SecretBytes::new(template),
            lanes: SecretBytes::new(bytes[304..320].to_vec()),
            machine: SecretBytes::new(bytes[320..380].to_vec()),
            otp_prefix: SecretBytes::new(bytes[380..388].to_vec()),
            otp_suffix: SecretBytes::new(bytes[388..392].to_vec()),
        }
    }

    pub(crate) fn identity(&self) -> &MachineIdentity {
        &self.identity
    }
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let state: Self = serde_json::from_slice(bytes)
            .map_err(|_| Error::State("invalid exported OTP state"))?;
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<()> {
        if self.version.is_some_and(|version| version != 1)
            || self.profile_sha256.len() != 64
            || !self
                .profile_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || self.template.as_ref().len() != 336
            || self.lanes.as_ref().len() != 16
            || self.machine.as_ref().len() != 60
            || self.otp_prefix.as_ref().len() != 8
            || self.otp_suffix.as_ref().len() != 4
        {
            return Err(Error::State("invalid exported OTP state"));
        }
        self.identity.validate()
    }
}

#[derive(Default)]
pub struct NativeOtpProgram;

const PROOF_FINGERPRINT: &str = "ef5796b978431a75b4f1b012083b1e2025829b87b3ec81d81811416f8117ddc1";

impl NativeOtpProgram {
    pub(crate) fn fingerprint(&self) -> &str {
        PROOF_FINGERPRINT
    }
    pub fn new() -> Self {
        Self
    }
    /// Validates a proof reference without evaluating it at runtime.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if hex(&Sha256::digest(bytes), false) != PROOF_FINGERPRINT {
            return Err(Error::State("unsupported proof reference"));
        }
        Ok(Self)
    }

    pub fn generate_at(&self, state: &ExportedOtpState, unix_seconds: u64) -> Result<Otp> {
        if state.profile_sha256 != PROOF_FINGERPRINT {
            return Err(Error::State("proof format does not match exported state"));
        }
        let mut lanes = [0; 16];
        lanes.copy_from_slice(state.lanes.as_ref());
        let block = Zeroizing::new(adi_seed::prepare_block(unix_seconds, &lanes));
        let digest = Zeroizing::new(adi_compression::compress_block(&block));
        let mut input = Zeroizing::new([0; 336]);
        input.copy_from_slice(state.template.as_ref());
        for (i, word) in digest.iter().enumerate() {
            input[304 + i * 4..308 + i * 4].copy_from_slice(&(word ^ 0x57072765).to_le_bytes());
        }
        let proof = adi_proof::proof(&input);
        let mut otp = Vec::with_capacity(28);
        otp.extend_from_slice(state.otp_prefix.as_ref());
        otp.extend_from_slice(&proof);
        otp.extend_from_slice(state.otp_suffix.as_ref());
        Ok(Otp {
            machine: SecretBytes::new(state.machine.as_ref().to_vec()),
            otp: SecretBytes::new(otp),
        })
    }

    pub fn headers_at(
        &self,
        state: &ExportedOtpState,
        unix_seconds: u64,
    ) -> Result<BTreeMap<String, String>> {
        let timestamp =
            i64::try_from(unix_seconds).map_err(|_| Error::State("unsupported clock"))?;
        let now = OffsetDateTime::from_unix_timestamp(timestamp)
            .map_err(|_| Error::State("unsupported clock"))?
            .format(&Rfc3339)
            .map_err(|_| Error::State("unsupported clock"))?;
        let otp = self.generate_at(state, unix_seconds)?;
        Ok(format_headers(
            &state.identity,
            state.routing_info,
            &otp,
            now,
        ))
    }
}
