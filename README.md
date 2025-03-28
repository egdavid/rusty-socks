# Rusty Socks

A lightweight WebSocket server implemented in Rust!

## Overview

Rusty Socks is a 'high-performance' WebSocket server built with Rust, designed for real-time communication applications. It provides a viable foundation for building WebSocket-based services with features like:

- Session management
- Message broadcasting
- In-memory message storage
- Health monitoring
- More to come...

## Architecture

The server is built on the following components:

- **Core**: Session management, connection handling, and message processing
- **Handlers**: WebSocket and HTTP request processing
- **Storage**: Simple in-memory message persistence
- **Configuration**: Dynamic server settings through environment variables

## Prerequisites

- Rust (1.63.0 or newer)
- Cargo package manager

## Installation

Clone the repository and build the project:

```bash
git clone https://github.com/egdavid/rusty-socks.git
cd rusty-socks
cargo build --release
```

## Configuration

Rusty Socks can be configured using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| RUSTY_SOCKS_HOST | Server host address | 127.0.0.1 |
| RUSTY_SOCKS_PORT | Server port | 3030 |
| RUSTY_SOCKS_MAX_CONN | Maximum connections | 100 |
| RUSTY_SOCKS_BUFFER | Message buffer size | 1024 |

## Usage

### Running the server

```bash
cargo run --bin rusty_socks
```

Or with custom configuration:

```bash
RUSTY_SOCKS_PORT=8080 cargo run --bin rusty_socks
```

### Connecting to the server

WebSocket endpoint is available at:

```
ws://[host]:[port]/ws
```

Health check endpoint:

```
http://[host]:[port]/health
```

### Client example (JavaScript)

```javascript
const socket = new WebSocket('ws://localhost:3030/ws');

socket.onopen = function() {
  console.log('Connected to Rusty Socks server');
  
  // Send a message
  const message = {
    sender: 'client',
    content: 'Hello from JS client',
    timestamp: new Date().toISOString()
  };
  
  socket.send(JSON.stringify(message));
};

socket.onmessage = function(event) {
  const message = JSON.parse(event.data);
  console.log('Received:', message);
};

socket.onclose = function() {
  console.log('Connection closed');
};
```

## Testing

### Automated Tests

Run the integration tests:

```bash
cargo test
```

Run specific tests:

```bash
cargo test --test websocket_test
```

### Manual WebSocket testing using wscat

You can use `wscat` to manually test the WebSocket server functionality. This is particularly useful for debugging and verifying real-time message exchange.

#### Installation

Install wscat using npm:

```bash
npm install -g wscat
```

#### Basic Connection Testing

Connect to the WebSocket server:

```bash
wscat -c ws://localhost:3030/ws
```

#### Testing Message Exchange

1. Start the server:
   ```bash
   cargo run --bin rusty_socks
   ```

2. Connect with a client:
   ```bash
   wscat -c ws://localhost:3030/ws
   ```

3. After connecting, you should receive a welcome message with your client ID.

4. Send a test message (should be properly formatted JSON):
   ```json
   {"id":"00000000-0000-0000-0000-000000000000","sender":"test_user","content":"Hello from wscat!","timestamp":"2025-03-15T12:00:00Z"}
   ```

5. Any response from the server will be displayed in the terminal.

#### Testing Multiple Clients

For testing broadcast functionality, open multiple terminal sessions with wscat connections and observe how messages are distributed among clients.

#### Connection Options

Connect with verbose output for debugging:
```bash
wscat -c ws://localhost:3030/ws --verbose
```

Connect to a custom port:
```bash
wscat -c ws://localhost:8080/ws
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request 🙃

## License

This project is licensed under the MIT License - see the LICENSE file for details.