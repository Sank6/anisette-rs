use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    path::{Component, Path},
};
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    crypto::circuit::Circuit,
    engine::{AdiEngine, Otp, SecretBytes, StartedProvisioning},
    identity::{MachineIdentity, hex},
    native_otp::{ExportedOtpState, NativeOtpProgram},
    store::read_private_bytes,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    profile: String,
    manifest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    identity: MachineIdentity,
    start: Artifact,
    finish: Artifact,
    decode: Artifact,
    #[serde(default, rename = "proof")]
    _proof: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Source {
    Spim,
    Session,
    Ptm,
    TrustKey,
    File,
    Filetime,
    Random,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Segment {
    kind: Source,
    offset: usize,
    length: usize,
    indices: Option<Vec<usize>>,
    file_index: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    phase: String,
    profile_sha256: String,
    input_bytes: usize,
    output_bytes: usize,
    inputs: Vec<Segment>,
    outputs: serde_json::Value,
}

struct Stage {
    program: Circuit,
    manifest: Manifest,
}

fn artifact_path(root: &Path, name: &str) -> Result<std::path::PathBuf> {
    let mut parts = Path::new(name).components();
    if !matches!(parts.next(), Some(Component::Normal(_))) || parts.next().is_some() {
        return Err(Error::State("factory artifacts must be sibling files"));
    }
    Ok(root.join(name))
}

fn number(value: &serde_json::Value, key: &str) -> Result<usize> {
    value[key]
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(Error::Circuit)
}

impl Stage {
    fn open(root: &Path, artifact: &Artifact, phase: &str) -> Result<Self> {
        let bytes =
            read_private_bytes(&artifact_path(root, &artifact.profile)?, 256 * 1024 * 1024)?;
        let manifest: Manifest = serde_json::from_slice(&read_private_bytes(
            &artifact_path(root, &artifact.manifest)?,
            1024 * 1024,
        )?)
        .map_err(|_| Error::State("invalid factory manifest"))?;
        if manifest.phase != phase
            || manifest.profile_sha256 != hex(&Sha256::digest(bytes.as_slice()), false)
        {
            return Err(Error::State(
                "factory profile fingerprint or phase mismatch",
            ));
        }
        let program = Circuit::from_json(&bytes)?;
        if program.dimensions() != (manifest.input_bytes, manifest.output_bytes) {
            return Err(Error::Circuit);
        }
        let mut offset = 0_usize;
        for segment in &manifest.inputs {
            if segment.offset != offset || segment.length == 0 {
                return Err(Error::Circuit);
            }
            offset = offset.checked_add(segment.length).ok_or(Error::Circuit)?;
            if offset > manifest.input_bytes {
                return Err(Error::Circuit);
            }
            match (&segment.kind, phase) {
                (Source::Spim, "start")
                | (Source::Session, "finish")
                | (Source::Ptm, "finish")
                | (Source::TrustKey, "finish")
                | (Source::File, "decode") => {}
                (Source::Random, _) => {}
                (Source::Filetime, _) if segment.length == 8 => {}
                _ => return Err(Error::Circuit),
            }
            if matches!(segment.kind, Source::Session)
                && segment
                    .indices
                    .as_ref()
                    .is_none_or(|indices| indices.len() != segment.length)
            {
                return Err(Error::Circuit);
            }
            if matches!(segment.kind, Source::File) && segment.file_index.is_none() {
                return Err(Error::Circuit);
            }
        }
        if offset != manifest.input_bytes {
            return Err(Error::Circuit);
        }
        Ok(Self { program, manifest })
    }

    fn run(&self, arguments: &Arguments<'_>, random: &mut File) -> Result<Zeroizing<Vec<u8>>> {
        let mut input = Zeroizing::new(vec![0; self.manifest.input_bytes]);
        let mut random_segments = Vec::new();
        for segment in &self.manifest.inputs {
            let target = &mut input[segment.offset..segment.offset + segment.length];
            let source = match segment.kind {
                Source::Spim => Some(arguments.spim),
                Source::Ptm => Some(arguments.ptm),
                Source::TrustKey => Some(arguments.trust_key),
                Source::File => Some(
                    *arguments
                        .files
                        .get(segment.file_index.ok_or(Error::Circuit)?)
                        .ok_or(Error::Circuit)?,
                ),
                Source::Session => {
                    for (out, &index) in target
                        .iter_mut()
                        .zip(segment.indices.as_ref().ok_or(Error::Circuit)?)
                    {
                        *out = *arguments.session.get(index).ok_or(Error::Circuit)?;
                    }
                    None
                }
                Source::Filetime => {
                    let value = arguments
                        .unix_seconds
                        .checked_add(11_644_473_600)
                        .and_then(|value| value.checked_mul(10_000_000))
                        .ok_or(Error::Circuit)?;
                    target.copy_from_slice(&value.to_le_bytes());
                    None
                }
                Source::Random => {
                    random_segments.push((segment.offset, segment.length));
                    None
                }
            };
            if let Some(source) = source {
                target.copy_from_slice(source);
            }
        }
        if random_segments.is_empty() {
            return self.program.evaluate(&input);
        }
        let mut selected = vec![false; input.len()];
        for &(offset, length) in &random_segments {
            selected[offset..offset + length].fill(true);
        }
        crate::crypto::sampling::sample(
            &self.program,
            &mut input,
            &selected,
            &mut std::io::BufReader::new(random),
        )
    }
}

#[derive(Default)]
struct Arguments<'a> {
    spim: &'a [u8],
    session: &'a [u8],
    ptm: &'a [u8],
    trust_key: &'a [u8],
    files: Vec<&'a [u8]>,
    unix_seconds: u64,
}

fn now() -> u64 {
    time::OffsetDateTime::now_utc().unix_timestamp() as u64
}

pub struct Factory {
    identity: MachineIdentity,
    start: Stage,
    finish: Stage,
    decode: Stage,
    proof: NativeOtpProgram,
    cpim_length: usize,
    file_lengths: Vec<usize>,
    random: File,
    sessions: BTreeMap<u32, SessionMaterial>,
    next_session: u32,
}

struct SessionMaterial {
    bytes: SecretBytes,
    unix_seconds: u64,
}

impl Factory {
    pub fn open(path: &Path) -> Result<Self> {
        let config: Configuration =
            serde_json::from_slice(&read_private_bytes(path, 64 * 1024)?)
                .map_err(|_| Error::State("invalid native factory configuration"))?;
        config.identity.validate()?;
        let root = path
            .parent()
            .ok_or(Error::State("factory path has no parent"))?;
        let start = Stage::open(root, &config.start, "start")?;
        let finish = Stage::open(root, &config.finish, "finish")?;
        let decode = Stage::open(root, &config.decode, "decode")?;
        let proof = NativeOtpProgram::new();
        let cpim_length = number(&start.manifest.outputs, "cpim_length")?;
        let state_length = start.manifest.outputs["state_addresses"]
            .as_array()
            .ok_or(Error::Circuit)?
            .len();
        if cpim_length == 0
            || cpim_length.checked_add(state_length) != Some(start.manifest.output_bytes)
            || !start
                .manifest
                .inputs
                .iter()
                .any(|segment| matches!(segment.kind, Source::Random) && segment.length >= 16)
        {
            return Err(Error::Circuit);
        }
        let file_lengths = {
            let lengths = finish.manifest.outputs["file_lengths"]
                .as_array()
                .ok_or(Error::Circuit)?
                .iter()
                .map(|value| {
                    value
                        .as_u64()
                        .and_then(|value| usize::try_from(value).ok())
                        .filter(|&value| value > 0 && value <= 4096)
                        .ok_or(Error::Circuit)
                })
                .collect::<Result<Vec<_>>>()?;
            if lengths
                .iter()
                .try_fold(0_usize, |sum, &length| sum.checked_add(length))
                != Some(finish.manifest.output_bytes)
                || number(&decode.manifest.outputs, "otp_state_bytes")? != 392
                || decode.manifest.output_bytes != 392
            {
                return Err(Error::Circuit);
            }
            lengths
        };
        for segment in &finish.manifest.inputs {
            if matches!(segment.kind, Source::Session)
                && segment
                    .indices
                    .as_ref()
                    .is_none_or(|indices| indices.iter().any(|&index| index >= state_length))
            {
                return Err(Error::Circuit);
            }
        }
        for segment in &decode.manifest.inputs {
            if matches!(segment.kind, Source::File)
                && file_lengths
                    .get(segment.file_index.ok_or(Error::Circuit)?)
                    .copied()
                    != Some(segment.length)
            {
                return Err(Error::Circuit);
            }
        }
        Ok(Self {
            identity: config.identity,
            start,
            finish,
            decode,
            proof,
            cpim_length,
            file_lengths,
            random: File::open("/dev/urandom")?,
            sessions: BTreeMap::new(),
            next_session: 1,
        })
    }
    pub fn identity(&self) -> &MachineIdentity {
        &self.identity
    }

    fn install_start(&mut self, output: &[u8], unix_seconds: u64) -> Result<StartedProvisioning> {
        let session = self.next_session;
        self.next_session += 1;
        self.sessions.insert(
            session,
            SessionMaterial {
                bytes: SecretBytes::new(output[self.cpim_length..].to_vec()),
                unix_seconds,
            },
        );
        Ok(StartedProvisioning {
            session,
            cpim: SecretBytes::new(output[..self.cpim_length].to_vec()),
        })
    }
}

impl AdiEngine for Factory {
    fn start(&mut self, identity: &MachineIdentity, spim: &[u8]) -> Result<StartedProvisioning> {
        if identity != &self.identity {
            return Err(Error::Identity);
        }
        let unix_seconds = now();
        let output = self.start.run(
            &Arguments {
                spim,
                unix_seconds,
                ..Arguments::default()
            },
            &mut self.random,
        )?;
        self.install_start(&output, unix_seconds)
    }
    fn finish(&mut self, session: u32, ptm: &[u8], trust_key: &[u8]) -> Result<SecretBytes> {
        let session = self.sessions.get(&session).ok_or(Error::Engine)?;
        let unix_seconds = session.unix_seconds;
        let files = self.finish.run(
            &Arguments {
                session: session.bytes.as_ref(),
                ptm,
                trust_key,
                unix_seconds,
                ..Arguments::default()
            },
            &mut self.random,
        )?;
        let mut offset = 0;
        let mut slices = Vec::new();
        for &length in &self.file_lengths {
            slices.push(&files[offset..offset + length]);
            offset += length;
        }
        let decoded = self.decode.run(
            &Arguments {
                files: slices,
                unix_seconds,
                ..Arguments::default()
            },
            &mut self.random,
        )?;
        let state = ExportedOtpState::decoded(
            self.identity.clone(),
            self.proof.fingerprint().to_owned(),
            &decoded,
        );
        serde_json::to_vec(&state)
            .map(SecretBytes::new)
            .map_err(|_| Error::State("cannot encode native OTP state"))
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
        if identity != &self.identity {
            return Err(Error::Identity);
        }
        let state = ExportedOtpState::from_json(state)?;
        if state.identity() != identity {
            return Err(Error::Identity);
        }
        self.proof.generate_at(&state, unix_seconds)
    }
}
