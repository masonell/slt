# Installation

This guide covers building and installing SLT from source.

## Build Requirements

### Rust Toolchain

SLT requires Rust 1.85 or later with the 2024 edition. Install Rust using [rustup](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

After installation, ensure you have the latest stable toolchain:

```bash
rustup update stable
```

### System Dependencies

SLT uses BoringSSL (via the `boring-sys` crate) for TLS and cryptographic operations. Building BoringSSL requires:

- **CMake** (3.12 or later) - Build system for BoringSSL
- **C Compiler** - GCC or Clang
- **Go** (1.18 or later) - Required by BoringSSL for code generation utilities
- **Perl** - Used by BoringSSL build process
- **Make** or **Ninja** - Build tools

#### Debian/Ubuntu

```bash
sudo apt update
sudo apt install build-essential cmake golang-go perl ninja-build pkg-config
```

#### Fedora/RHEL/CentOS

```bash
sudo dnf install gcc cmake golang perl ninja-build pkg-config
```

#### macOS

```bash
brew install cmake go perl ninja pkg-config
```

#### Arch Linux

```bash
sudo pacman -S base-devel cmake go perl ninja pkg-config
```

### Additional Runtime Dependencies

SLT creates TUN interfaces for VPN traffic, which requires elevated privileges:

- **Linux**: `CAP_NET_ADMIN` capability or root access
- **macOS**: Root access or appropriate entitlements

## Building from Source

Clone the repository and build with Cargo:

```bash
git clone https://github.com/your-org/slt.git
cd slt
cargo build --release
```

The initial build will compile BoringSSL from source, which may take several minutes. Subsequent builds will be faster due to caching.

## Binaries

After a successful build, the following binaries are available in `target/release/`:

| Binary | Description |
|--------|-------------|
| `client` | VPN client - establishes connections to the server and routes traffic through the TUN interface |
| `server` | VPN server - handles client authentication, session management, and traffic routing |
| `slt` | CLI utility - generates keys, certificates, and manages configuration |

### Additional Tools

The `slt-tools` crate provides debugging utilities (also in `target/release/`):

| Binary | Description |
|--------|-------------|
| `tcp_client_hello` | Generates TLS ClientHello packets for testing |
| `quic_client_hello` | Generates QUIC ClientHello packets for testing |

## Installing Binaries

To install the binaries to `~/.cargo/bin/` (which should be in your PATH):

```bash
cargo install --path slt-client --locked
cargo install --path slt-server --locked
cargo install --path slt-cli --locked
```

Or copy them manually:

```bash
sudo cp target/release/client /usr/local/bin/slt-client
sudo cp target/release/server /usr/local/bin/slt-server
sudo cp target/release/slt /usr/local/bin/slt
```

## Verifying the Installation

Check that the binaries work:

```bash
./target/release/client --help
./target/release/server --help
./target/release/slt --help
```

## Troubleshooting

### BoringSSL Build Fails

If the BoringSSL build fails:

1. Ensure all system dependencies are installed
2. Check that Go is in your PATH: `go version`
3. Try cleaning and rebuilding:
   ```bash
   cargo clean
   cargo build --release
   ```

### Permission Denied on TUN Interface

On Linux, you may need to grant capabilities to the binaries:

```bash
sudo setcap cap_net_admin+ep target/release/client
sudo setcap cap_net_admin+ep target/release/server
```

Alternatively, run the binaries with `sudo`.

### Linker Errors

If you encounter linker errors, ensure you have the standard C library development headers installed:

- Debian/Ubuntu: `sudo apt install libc6-dev`
- Fedora/RHEL: `sudo dnf install glibc-devel`
- Arch Linux: included in `base-devel`

## Next Steps

- [Quick Start](quick-start.md) - Get up and running quickly
- [Configuration](configuration.md) - Configuration options for client and server
