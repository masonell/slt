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

SLT attaches to a preconfigured TUN device for VPN traffic. Creating and addressing the interface requires `CAP_NET_ADMIN` (or root) once; the running client/server then needs only access to the device. On the server, binding public port 443 additionally requires `CAP_NET_BIND_SERVICE` (or root).

- **Linux**: `CAP_NET_ADMIN` once for TUN preconfiguration; `CAP_NET_BIND_SERVICE` for the server's port 443
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
| `slt-client` | VPN client - establishes connections to the server and routes traffic through the TUN interface |
| `slt-server` | VPN server - handles client authentication, session management, and traffic routing |
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
sudo cp target/release/slt-client /usr/local/bin/slt-client
sudo cp target/release/slt-server /usr/local/bin/slt-server
sudo cp target/release/slt /usr/local/bin/slt
```

## Verifying the Installation

Check that the binaries work:

```bash
# If running from build directory
./target/release/slt-client --help
./target/release/slt-server --help
./target/release/slt --help

# Or if installed to ~/.cargo/bin or /usr/local/bin
slt-client --help
slt-server --help
slt --help
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

SLT attaches to a preconfigured TUN interface and needs no `CAP_NET_ADMIN` at runtime. Permission errors at startup usually mean the interface has not been preconfigured, or your user cannot open it:

```bash
# Preconfigure the interface once (root), reading [tun] from the config; owner = your user
sudo slt net up --config /etc/slt/client.toml --user "$USER"
```

For the server only, grant privileged-port binding without root:

```bash
sudo setcap cap_net_bind_service+ep target/release/slt-server
```

The client needs no capabilities once the interface is owned by its user.

### Linker Errors

If you encounter linker errors, ensure you have the standard C library development headers installed:

- Debian/Ubuntu: `sudo apt install libc6-dev`
- Fedora/RHEL: `sudo dnf install glibc-devel`
- Arch Linux: included in `base-devel`

## Next Steps

- [Quick Start](quick-start.md) - Get up and running quickly
- [Configuration](configuration.md) - Configuration options for client and server
