# Installation

RustySocks can be installed and deployed in multiple ways depending on your needs.

## Prerequisites

- **Rust** 1.75 or higher (for building from source)
- **OpenSSL** or **LibreSSL** (for TLS support)
- **Docker** (optional, for containerized deployment)

## Installation Methods

### Using Cargo (Recommended)

The simplest way to install RustySocks is through Cargo:

```bash
cargo install rusty-socks
```

### Building from Source

For the latest features or custom modifications:

```bash
git clone https://github.com/yourusername/rusty-socks.git
cd rusty-socks
cargo build --release
```

The binary will be available at `target/release/rusty-socks`.

### Using Docker

Pull the official Docker image:

```bash
docker pull rustysocks/server:latest
```

Or use Docker Compose:

```yaml
version: '3.8'
services:
  rustysocks:
    image: rustysocks/server:latest
    ports:
      - "8080:8080"
      - "8443:8443"
    environment:
      - RUST_LOG=info
      - JWT_SECRET=${JWT_SECRET}
    volumes:
      - ./config:/etc/rustysocks
      - ./certs:/certs
```

### Package Managers

#### Homebrew (macOS/Linux)

```bash
brew tap rustysocks/tap
brew install rustysocks
```

#### APT (Debian/Ubuntu)

```bash
curl -fsSL https://rustysocks.io/install/apt-key.gpg | sudo apt-key add -
echo "deb https://rustysocks.io/apt stable main" | sudo tee /etc/apt/sources.list.d/rustysocks.list
sudo apt update
sudo apt install rustysocks
```

## Verifying Installation

After installation, verify RustySocks is working:

```bash
rustysocks --version
```

You should see output like:
```
rustysocks 0.1.0
```

## System Requirements

### Minimum Requirements

- **CPU**: 1 core
- **RAM**: 512MB
- **Disk**: 50MB
- **Network**: 1Gbps recommended

### Production Requirements

For production deployments handling 10k+ concurrent connections:

- **CPU**: 4+ cores
- **RAM**: 8GB+
- **Disk**: SSD with 100GB+
- **Network**: 10Gbps+

### Operating System Support

RustySocks is tested on:

- **Linux**: Ubuntu 20.04+, Debian 11+, RHEL 8+, Alpine 3.15+
- **macOS**: 11.0+ (Big Sur and later)
- **Windows**: Windows Server 2019+, Windows 10+
- **BSD**: FreeBSD 13+, OpenBSD 7.0+

## TLS Certificate Setup

For production use, you'll need TLS certificates:

### Using Let's Encrypt

```bash
certbot certonly --standalone -d yourdomain.com
```

### Self-signed (Development Only)

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

## Next Steps

- Configure your server: [Configuration Guide](./configuration.md)
- Run your first server: [Quick Start Tutorial](./quickstart.md)
- Deploy to production: [Production Checklist](../deployment/checklist.md)