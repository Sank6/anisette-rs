use crate::{Error, MAX_BLOB, Result, engine::SecretBytes};
use base64::{Engine, engine::general_purpose::STANDARD};
use plist::{Dictionary, Value};
use serde::Deserialize;

pub const START_PATH: &str = "/grandslam/MidService/startMachineProvisioning";
pub const FINISH_PATH: &str = "/grandslam/MidService/finishMachineProvisioning";

pub struct FinishResponse {
    pub ptm: SecretBytes,
    pub trust_key: SecretBytes,
    pub routing_info: u64,
}

#[derive(Deserialize)]
struct Envelope<T> {
    #[serde(rename = "Response")]
    response: T,
}

#[derive(Deserialize)]
struct Status {
    ec: i64,
}

#[derive(Deserialize)]
struct StartResponse {
    #[serde(rename = "Status")]
    status: Option<Status>,
    spim: String,
}

#[derive(Deserialize)]
struct RawFinishResponse {
    #[serde(rename = "Status")]
    status: Option<Status>,
    ptm: String,
    tk: String,
    #[serde(rename = "X-Apple-I-MD-RINFO")]
    routing_info: String,
}

fn request(payload: Dictionary) -> Result<SecretBytes> {
    let mut root = Dictionary::new();
    root.insert("Header".into(), Value::Dictionary(Dictionary::new()));
    root.insert("Request".into(), Value::Dictionary(payload));
    let mut bytes = Vec::new();
    Value::Dictionary(root)
        .to_writer_xml(&mut bytes)
        .map_err(|_| Error::Protocol)?;
    Ok(SecretBytes::new(bytes))
}

pub fn start_request() -> Result<SecretBytes> {
    request(Dictionary::new())
}

pub fn finish_request(cpim: &[u8]) -> Result<SecretBytes> {
    let mut payload = Dictionary::new();
    payload.insert("cpim".into(), Value::String(STANDARD.encode(cpim)));
    request(payload)
}

fn response<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    if bytes.is_empty() || bytes.len() > MAX_BLOB {
        return Err(Error::Protocol);
    }
    plist::from_bytes::<Envelope<T>>(bytes)
        .map(|envelope| envelope.response)
        .map_err(|_| Error::Protocol)
}

fn check(status: Option<Status>) -> Result<()> {
    if status.is_some_and(|status| status.ec != 0) {
        return Err(Error::AppleStatus);
    }
    Ok(())
}

fn blob(value: String) -> Result<SecretBytes> {
    let bytes = STANDARD.decode(value).map_err(|_| Error::Protocol)?;
    if bytes.is_empty() || bytes.len() > MAX_BLOB {
        return Err(Error::Protocol);
    }
    Ok(SecretBytes::new(bytes))
}

pub fn parse_start(bytes: &[u8]) -> Result<SecretBytes> {
    let response: StartResponse = response(bytes)?;
    check(response.status)?;
    blob(response.spim)
}

pub fn parse_finish(bytes: &[u8]) -> Result<FinishResponse> {
    let response: RawFinishResponse = response(bytes)?;
    check(response.status)?;
    Ok(FinishResponse {
        ptm: blob(response.ptm)?,
        trust_key: blob(response.tk)?,
        routing_info: response.routing_info.parse().map_err(|_| Error::Protocol)?,
    })
}
