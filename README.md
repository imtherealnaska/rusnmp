# rusnmp - A Custom SNMP Manager Built from Scratch

This is a SNMP v2c manager. It was a deep dive into network protocols, binary encoding, and async Rust.

## What Is This?

This project is an SNMP (Simple Network Management Protocol) manager that lets you query and monitor network devices.

- **Custom ASN.1 BER Parser**: encoder/decoder for the binary format that SNMP uses
- **SNMP Protocol Implementation**: Message construction and parsing following RFC specifications
- **Async Network Engine**: Concurrent device polling using Tokio with timeout handling
- **Multiple SNMP Operations**: GET, WALK, GET-BULK, and BULK-WALK operations
- **Real-world Testing**: Validated against actual SNMP agents (net-snmp)

## How to Use It

The CLI supports multiple commands for different SNMP operations:

### GET - Retrieve a single OID from one or more devices

```bash
cargo run -- get --community public --oid .1.3.6.1.2.1.1.1.0 192.168.1.1
```

### WALK - Traverse a subtree on multiple devices

```bash
cargo run -- walk --community public --oid .1.3.6.1.2.1.1 192.168.1.1 192.168.1.2
```

### BULK - Efficiently request multiple OIDs at once

```bash
cargo run -- bulk --community public --target 192.168.1.1 --non-repeaters 0 --max-repititions 10 .1.3.6.1.2.1.1 .1.3.6.1.2.1.2
```

### BULK-WALK - Fast traversal of large MIB trees

```bash
cargo run -- bulk-walk --community public --target 192.168.1.1 --oid .1.3.6.1.2.1 --max-repetitions 20
```

Note: GET and WALK support multiple targets for concurrent polling, while BULK and BULK-WALK work with a single target.

## The Architecture

Here's how everything fits together:

1. **BER Layer** ([src/ber/](src/ber/)) - The foundation. Handles encoding/decoding of ASN.1 Basic Encoding Rules
2. **SNMP Protocol** ([src/snmp/](src/snmp/)) - Builds SNMP messages on top of BER (PDUs, message structures, etc.)
3. **Manager** ([src/manager/](src/manager/)) - The high-level API that orchestrates everything
4. **Network Layer** ([src/manager/network.rs](src/manager/network.rs)) - UDP socket handling with async I/O
5. **CLI** ([src/main.rs](src/main.rs)) - Command-line interface with progress bars for user interaction

## Tech Stack

- **Rust** - For memory safety and performance
- **Tokio** - Async runtime for concurrent network operations
- **Clap** - Command-line argument parsing
- **Indicatif** - Progress bars and status indicators
- **Custom BER encoding/decoding** - No external SNMP dependencies

## What I Learned Building This

This project was a fantastic learning experience:

- How to implement network protocols from RFC specifications
- Binary encoding schemes (ASN.1 BER) and parsing binary data
- Async I/O patterns in Rust with Tokio
- Network protocol debugging and packet analysis
- The intricacies of SNMP (community strings, PDU types, OID traversal)
- How to structure concurrent network applications

## Current Status

The implementation covers SNMP v2c basics:

- ✅ GET requests (single and multi-target)
- ✅ WALK operations (GETNEXT-based subtree traversal)
- ✅ GET-BULK requests (efficient multi-variable queries)
- ✅ BULK-WALK (optimized tree traversal)
- ✅ Concurrent multi-device polling with progress indicators
- ✅ Tested against real SNMP agents

## What's Next (Maybe)

If I continue working on this, here are some ideas:

- **SNMP v3**: Add authentication and encryption support
- **Trap Receiver**: Listen for SNMP traps/notifications from devices
- **Better Error Handling**: More detailed error messages and recovery

## Running Tests

```bash
cargo test
```

The tests include parsing validation, encoding round-trips, and real packet captures from snmpd.
