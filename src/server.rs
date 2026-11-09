use crate::{
    CLIENT_INFO, Error, Result, USER_AGENT,
    engine::{AdiEngine, ProvisionedDevice},
};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    time::Duration,
};

const MAX_REQUEST: usize = 8192;

pub fn require_loopback(host: IpAddr) -> Result<()> {
    if !host.is_loopback() {
        return Err(Error::State("HTTP service must bind a loopback address"));
    }
    Ok(())
}

pub struct NativeService<E> {
    engine: E,
    device: ProvisionedDevice,
}

impl<E: AdiEngine> NativeService<E> {
    pub fn new(mut engine: E, device: ProvisionedDevice) -> Result<Self> {
        device.validate()?;
        engine.otp_at(
            &device.identity,
            device.engine_state.as_ref(),
            time::OffsetDateTime::now_utc().unix_timestamp() as u64,
        )?;
        Ok(Self { engine, device })
    }

    fn dispatch(&mut self, method: &str, path: &str) -> Result<(u16, Value)> {
        if method != "GET" {
            return Ok((405, json!({"error":"method not allowed"})));
        }
        Ok(match path {
            "/" => (200, json!(self.device.headers(&mut self.engine)?)),
            "/healthz" => (200, json!({"status":"ok","provisioned":true})),
            "/v3/client_info" => (
                200,
                json!({"client_info":CLIENT_INFO,"user_agent":USER_AGENT}),
            ),
            _ => (404, json!({"error":"route not found"})),
        })
    }

    fn connection(&mut self, mut stream: TcpStream) -> Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        let (status, body) = match read_request(&mut stream) {
            Ok((method, path)) => self.dispatch(&method, &path)?,
            Err(status) => (status, json!({"error":"invalid HTTP request"})),
        };
        let body = body.to_string();
        let reason = match status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            431 => "Request Header Fields Too Large",
            _ => "Service Unavailable",
        };
        write!(
            stream,
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nPragma: no-cache\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n",
            body.len()
        )?;
        if status == 405 {
            stream.write_all(b"Allow: GET\r\n")?;
        }
        stream.write_all(b"\r\n")?;
        stream.write_all(body.as_bytes())?;
        Ok(())
    }
}

fn read_request(reader: &mut impl Read) -> std::result::Result<(String, String), u16> {
    let mut bytes = Vec::new();
    let end = loop {
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index;
        }
        if bytes.len() == MAX_REQUEST {
            return Err(431);
        }
        let mut buffer = [0_u8; 512];
        let maximum = buffer.len().min(MAX_REQUEST - bytes.len());
        let count = reader.read(&mut buffer[..maximum]).map_err(|error| {
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) {
                408_u16
            } else {
                400_u16
            }
        })?;
        if count == 0 {
            return Err(400);
        }
        bytes.extend_from_slice(&buffer[..count]);
    };
    let header = std::str::from_utf8(&bytes[..end]).map_err(|_| 400_u16)?;
    let mut lines = header.split("\r\n");
    let parts = lines
        .next()
        .ok_or(400_u16)?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    if parts.len() != 3
        || !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1")
        || !parts[1].starts_with('/')
    {
        return Err(400);
    }
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(400_u16)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(400);
        }
        if parts[0] == "GET"
            && (name.eq_ignore_ascii_case("transfer-encoding")
                || name.eq_ignore_ascii_case("content-length") && value.trim() != "0")
        {
            return Err(400);
        }
    }
    Ok((
        parts[0].to_owned(),
        parts[1].split('?').next().ok_or(400_u16)?.to_owned(),
    ))
}

pub fn serve<E: AdiEngine>(address: SocketAddr, mut service: NativeService<E>) -> Result<()> {
    require_loopback(address.ip())?;
    let listener = TcpListener::bind(address)?;
    println!("Serving anisette on http://{}", listener.local_addr()?);
    for stream in listener.incoming() {
        let stream = stream?;
        service.connection(stream)?;
    }
    Ok(())
}
