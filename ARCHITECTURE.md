# Architecture

`anisette-rs` provisions a Windows anisette identity and generates the headers
used by Apple account clients. The runtime is native Rust and evaluates bounded
arithmetic profiles; it does not execute Apple binaries.

## Runtime flow

Provisioning has four steps:

1. Derive a machine identity from explicit Windows hardware values.
2. Fetch SPIM from Apple's machine-provisioning service.
3. Evaluate the start profile to produce CPIM and session state.
4. Send CPIM to Apple, evaluate the finish and decode profiles, and store the
   resulting OTP state.

Header generation evaluates the stored OTP state with the current 30-second
time slot. Provisioning and header generation use the same factory identity.

## Machine identity

The device ID contains seven uppercase, eight-character MD5 prefixes separated
by periods. Its inputs are:

1. MAC address bytes
2. Little-endian volume serial
3. Windows ProductId bytes
4. Processor name bytes
5. BIOS version bytes
6. UTF-16LE computer name
7. UTF-16LE hardware profile GUID

The legacy device ID concatenates lowercase MD5 prefixes for the MAC address,
volume serial, byte-widened BIOS version, byte-widened processor name, and
ProductId. The local user ID is the uppercase first eight bytes of the MD5 of
the device ID.

Hardware values are always supplied explicitly. Linux hardware values are not
substituted for Windows values.

## Factory

A factory binds one machine identity to four artifacts:

- start profile
- finish profile
- state-decoding profile
- OTP proof profile

Each stage manifest defines its input segments, output size, and profile
fingerprint. Artifact paths are sibling files of the factory configuration.
Profiles and state are rejected when their fingerprints or identities differ.

Profiles are typed bit-vector graphs containing scalar operations, lookup
tables, bounded arrays, and path guards. They contain no instruction decoder,
program counter, system calls, or host pointers.

Random input segments use kernel entropy. When a path guard rejects a random
choice, the sampler changes dependent random bytes and reevaluates the full
profile. Fixed inputs are never modified.

## Provisioning transport

The client posts plist requests to:

- `/grandslam/MidService/startMachineProvisioning`
- `/grandslam/MidService/finishMachineProvisioning`

Requests carry AuthKitWin client metadata and the configured machine identity.
TLS uses hostname and chain validation plus the expected Apple root certificate
fingerprint. Redirects are disabled, requests have deadlines, and responses are
limited to 1 MiB.

Provisioning is anonymous and does not accept Apple account credentials.

## OTP generation

OTP generation builds a padded 55-byte message from the decoded state and the
current 30-second time slot. A CoreADI-specific, SHA-256-shaped compression
function produces eight context words for the OTP proof profile.

The final OTP contains an eight-byte prefix, a 16-byte proof, and a four-byte
suffix. Machine data is 60 bytes.

## State

The default state directory is selected in this order:

1. `$ANISETTE_RS_HOME`
2. `$XDG_DATA_HOME/anisette-rs`
3. `~/.local/share/anisette-rs`

Directories must be owned by the current user with mode `0700`. Private files
must be regular files owned by the current user with mode `0600`. Writes use a
private temporary file, `fsync`, and atomic rename. An advisory lock covers the
lifetime of each state-store handle.

## HTTP service

The service binds to a loopback address and exposes:

| Route | Response |
| --- | --- |
| `GET /` | Fresh anisette headers |
| `GET /healthz` | Provisioning readiness |
| `GET /v3/client_info` | AuthKit client metadata |

Requests are handled serially. The service reads an existing provisioned state
and never contacts Apple's provisioning endpoints.
