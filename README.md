# anisette-rs

`anisette-rs` implements Apple anisette provisioning and header generation in
Rust. It does not load Apple DLLs, use Wine or Python, or call a third-party
anisette service.

The runtime uses private, build- and identity-specific arithmetic
profiles.

## Requirements

- Linux
- Rust 1.90 or newer
- A private factory configuration for provisioning and state-backed headers
- Apple's root certificate in DER format for provisioning

State directories must be owned by the current user with mode `0700`. Private
input and state files must use mode `0600`.

## Build

```sh
cargo build --release --locked
```

The executable is written to `target/release/anisette-rs`. Check a factory
configuration with:

```sh
target/release/anisette-rs \
  --factory /path/to/factory.json \
  doctor
```

## Provision and generate headers

Provision a device into a state directory:

```sh
target/release/anisette-rs \
  --factory /path/to/factory.json \
  --state-dir /path/to/native-device \
  provision --apple-root /path/to/AppleIncRootCertificate.cer
```

Provisioning contacts Apple's anonymous provisioning endpoints. An existing
provisioned device is reused, and state belonging to a different identity is
never replaced.

Generate fresh anisette headers from the provisioned state:

```sh
target/release/anisette-rs \
  --factory /path/to/factory.json \
  --state-dir /path/to/native-device \
  headers
```

Headers can also be generated directly from an extracted OTP circuit and
exported state:

```sh
target/release/anisette-rs headers \
  --circuit /path/to/proof-circuit.json \
  --exported-state /path/to/native-otp-state.json
```

## Run the HTTP service

Serve headers from an existing provisioned identity:

```sh
target/release/anisette-rs \
  --factory /path/to/factory.json \
  --state-dir /path/to/native-device \
  serve --port 6970
```

The service listens on loopback by default and provides:

- `GET /` for anisette JSON
- `GET /healthz` for readiness
- `GET /v3/client_info` for client metadata

For [iCloud-Keychain-for-Linux](https://github.com/Sank6/iCloud-Keychain-for-Linux):

```sh
export ICP_ANISETTE_URL=http://127.0.0.1:6970
icp login
```

## Other commands

The CLI can also derive Windows identity metadata. See the built-in help for
details:

```sh
target/release/anisette-rs --help
target/release/anisette-rs <command> --help
```
