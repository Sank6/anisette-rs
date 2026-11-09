//! Opt-in checks against a privately provisioned native state and independent
//! reference computations. No captured state is embedded in the test binary.
#![allow(clippy::unwrap_used)]
use anisette_rs::{engine::AdiEngine, native_adi::NativeEngine, store::StateStore};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

#[derive(Deserialize)]
struct Reference {
    timestamps: Vec<u64>,
    machine: String,
    otps: Vec<String>,
}
struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn request(port: u16, path: &str) -> serde_json::Value {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        Duration::from_secs(2),
    )
    .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 200 "),
        "service request failed"
    );
    let offset = response.windows(4).position(|x| x == b"\r\n\r\n").unwrap() + 4;
    serde_json::from_slice(&response[offset..]).unwrap()
}

#[test]
#[ignore = "set ANISETTE_RS_NATIVE_STATE_DIR and ANISETTE_RS_NATIVE_REFERENCE to private verification inputs"]
fn native_restart_headers_and_service_match_independent_reference() {
    let state = std::env::var("ANISETTE_RS_NATIVE_STATE_DIR").expect("native state directory");
    let reference =
        std::env::var("ANISETTE_RS_NATIVE_REFERENCE").expect("independent reference path");
    let reference: Reference = serde_json::from_slice(&std::fs::read(reference).unwrap()).unwrap();
    assert_eq!(reference.timestamps.len(), reference.otps.len());
    let machine = STANDARD.decode(&reference.machine).unwrap();
    let device = {
        let store = StateStore::open(Path::new(&state)).unwrap();
        store.load().unwrap()
    };
    for restart in 0..2 {
        let mut engine = NativeEngine::stored();
        for (index, (&timestamp, expected)) in
            reference.timestamps.iter().zip(&reference.otps).enumerate()
        {
            let otp = engine
                .otp_at(&device.identity, device.engine_state.as_ref(), timestamp)
                .unwrap();
            assert!(
                otp.machine.as_ref() == machine,
                "machine mismatch after restart {restart}"
            );
            let bytes = otp.otp.as_ref();
            assert!(
                bytes[..8] == [0, 0, 0, 5, 0, 0, 0, 16] && bytes[24..] == [0, 0, 0, 2],
                "OTP framing mismatch"
            );
            assert!(
                bytes[8..24] == STANDARD.decode(expected).unwrap(),
                "reference mismatch at timestamp index {index}"
            );
        }
    }
    let binary = env!("CARGO_BIN_EXE_anisette-rs");
    let output = Command::new(binary)
        .env_clear()
        .args(["--state-dir", &state, "headers"])
        .output()
        .unwrap();
    assert!(output.status.success(), "header CLI failed");
    let headers: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        STANDARD
            .decode(headers["X-Apple-I-MD-M"].as_str().unwrap())
            .unwrap()
            == machine,
        "CLI machine mismatch"
    );
    for _ in 0..2 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut server = Server(
            Command::new(binary)
                .env_clear()
                .args(["--state-dir", &state, "serve", "--port", &port.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let mut ready = false;
        for _ in 0..100 {
            assert!(
                server.0.try_wait().unwrap().is_none(),
                "service exited during startup"
            );
            if TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_ok() {
                ready = true;
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(ready, "service startup timeout");
        assert!(request(port, "/healthz")["provisioned"] == true);
        let headers = request(port, "/");
        assert!(
            STANDARD
                .decode(headers["X-Apple-I-MD-M"].as_str().unwrap())
                .unwrap()
                == machine,
            "service machine mismatch"
        );
        assert_eq!(
            STANDARD
                .decode(headers["X-Apple-I-MD"].as_str().unwrap())
                .unwrap()
                .len(),
            28
        );
        assert!(
            request(port, "/v3/client_info")["client_info"]
                .as_str()
                .unwrap()
                .contains("AuthKitWin")
        );
        let locked = Command::new(binary)
            .env_clear()
            .args(["--state-dir", &state, "headers"])
            .output()
            .unwrap();
        assert!(
            !locked.status.success(),
            "state lock was not retained while serving"
        );
        drop(server);
    }
}
