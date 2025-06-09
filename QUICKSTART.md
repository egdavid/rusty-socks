# 🚀 Quick Start Guide

Get Rusty Socks up and running in minutes!

## Prerequisites

- Rust 1.70+ ([Install Rust](https://rustup.rs/))
- OpenSSL development headers
  - Ubuntu/Debian: `sudo apt install libssl-dev`
  - CentOS/RHEL: `sudo yum install openssl-devel`
  - macOS: `brew install openssl`

## 1. Clone and Build

```bash
git clone https://github.com/egdavid/rusty-socks.git
cd rusty-socks
cargo build --release
```

## 2. Configure Environment

```bash
# Copy the example configuration
cp .env.example .env

# Generate secure secrets
export JWT_SECRET=$(openssl rand -base64 32)
export CSRF_SECRET=$(openssl rand -base64 32)

# Update .env file with your secrets
sed -i "s/generate_secure_jwt_secret_min_32_characters/$JWT_SECRET/" .env
sed -i "s/generate_different_csrf_secret_min_32_characters/$CSRF_SECRET/" .env
```

## 3. Run the Server

```bash
# Development mode
cargo run

# Or use the release binary
./target/release/rusty-socks
```

The server starts on `http://localhost:3030` by default.

## 4. Test with WebSocket Client

### Using JavaScript (Browser Console)

```javascript
const ws = new WebSocket('ws://localhost:3030/ws');

ws.onopen = () => {
    console.log('Connected to Rusty Socks!');
    
    // Join a room
    ws.send(JSON.stringify({
        type: 'join_room',
        room_id: 'general'
    }));
};

ws.onmessage = (event) => {
    console.log('Received:', JSON.parse(event.data));
};

// Send a message
ws.send(JSON.stringify({
    type: 'send_message',
    room_id: 'general',
    content: 'Hello, Rusty Socks!'
}));
```

### Using curl

```bash
# Test the health endpoint
curl http://localhost:3030/health

# WebSocket connection requires a WebSocket client
# Try wscat: npm install -g wscat
wscat -c ws://localhost:3030/ws
```

## 5. Production Deployment

### Enable TLS

```bash
# Generate self-signed certificate (for testing)
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365

# Update .env
echo "RUSTY_SOCKS_ENABLE_TLS=true" >> .env
echo "RUSTY_SOCKS_TLS_CERT_PATH=./cert.pem" >> .env
echo "RUSTY_SOCKS_TLS_KEY_PATH=./key.pem" >> .env
echo "RUST_ENV=production" >> .env
```

### Docker Deployment

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/rusty-socks /usr/local/bin/
EXPOSE 3030
CMD ["rusty-socks"]
```

```bash
# Build and run
docker build -t rusty-socks .
docker run -p 3030:3030 --env-file .env rusty-socks
```

## Configuration Options

Key environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `RUSTY_SOCKS_HOST` | Bind address | `127.0.0.1` |
| `RUSTY_SOCKS_PORT` | Port number | `3030` |
| `RUSTY_SOCKS_JWT_SECRET` | JWT signing secret | **Required** |
| `RUSTY_SOCKS_CSRF_SECRET` | CSRF token secret | **Required** |
| `RUSTY_SOCKS_ENABLE_TLS` | Enable HTTPS/WSS | `false` |
| `RUST_ENV` | Environment mode | `development` |

See [.env.example](.env.example) for all options.

## API Examples

### Authentication

```javascript
// Get JWT token (implement your auth endpoint)
const token = 'your-jwt-token';

const ws = new WebSocket('ws://localhost:3030/ws', [], {
    headers: {
        'Authorization': `Bearer ${token}`
    }
});
```

### Room Operations

```javascript
// Create a room
ws.send(JSON.stringify({
    type: 'create_room',
    room_id: 'my-room',
    room_name: 'My Awesome Room'
}));

// Join a room
ws.send(JSON.stringify({
    type: 'join_room',
    room_id: 'my-room'
}));

// Send message
ws.send(JSON.stringify({
    type: 'send_message',
    room_id: 'my-room',
    content: 'Hello everyone!'
}));

// Leave room
ws.send(JSON.stringify({
    type: 'leave_room',
    room_id: 'my-room'
}));
```

## Troubleshooting

### Common Issues

1. **"JWT_SECRET environment variable is required"**
   - Make sure your `.env` file has valid secrets
   - Secrets must be at least 32 characters

2. **"Certificate file not found"**
   - Check TLS certificate paths in `.env`
   - Ensure files exist and are readable

3. **Connection refused**
   - Check if server is running: `curl http://localhost:3030/health`
   - Verify firewall settings
   - Check logs for error messages

### Enable Debug Logging

```bash
RUST_LOG=debug cargo run
```

### Performance Testing

```bash
# Install wrk for load testing
sudo apt install wrk

# Basic HTTP test
wrk -t12 -c400 -d30s http://localhost:3030/health

# WebSocket testing requires specialized tools
# Try artillery.io or websocket-king
```

## Next Steps

- Read the [Security Guide](SECURITY.md)
- Check the [Roadmap](ROADMAP.md)
- Explore [Examples](examples/)
- Join the community discussions

## Need Help?

- 📖 [Full Documentation](https://docs.rs/rusty-socks)
- 🐛 [Report Issues](https://github.com/egdavid/rusty-socks/issues)
- 💬 [Discussions](https://github.com/egdavid/rusty-socks/discussions)
- 🔒 [Security Issues](SECURITY.md)

Happy coding! 🦀🧦