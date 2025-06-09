# Rusty Socks

A high-performance, production-ready WebSocket server written in Rust, designed for real-time applications across gaming, finance, chat, and other domains requiring fast, secure communication.

## Features

### Core Capabilities
- **High-Performance WebSocket Server** - Built with Tokio and Warp for maximum throughput
- **Room-Based Communication** - Organize users into channels/rooms with fine-grained permissions
- **JWT Authentication** - Secure token-based authentication with role-based access control (RBAC)
- **Rate Limiting** - Prevent abuse with configurable per-user and global rate limits
- **Message Validation** - XSS protection, spam detection, and content filtering
- **Thread-Safe Architecture** - Concurrent message handling with race condition protection

### Security Features
- **Production-Ready Security** - Comprehensive vulnerability protection
- **Role-Based Permissions** - Owner, Admin, Moderator, Member, and Guest roles
- **Ban/Kick/Mute System** - Complete moderation toolkit
- **Connection Limiting** - Prevent DoS attacks with IP-based connection limits
- **Input Validation** - Protect against injection and malformed data

### Scalability
- **Configurable Thread Pool** - Optimize performance for your hardware
- **Memory Protection** - Built-in safeguards against memory exhaustion
- **Async Broadcasting** - Efficient message distribution to large user groups
- **Resource Cleanup** - Automatic cleanup of idle connections and expired data

## Architecture

The server is built on the following components:

- **Authentication**: JWT token management with role-based access control
- **Core**: Room management, session handling, connection processing, and thread pooling
- **Handlers**: WebSocket and HTTP request processing with authentication
- **Storage**: Simple in-memory message persistence with room isolation
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
| RUSTY_SOCKS_HOST | Server host address | 0.0.0.0 |
| RUSTY_SOCKS_PORT | Server port | 3030 |
| RUSTY_SOCKS_MAX_CONN | Maximum connections | 100 |
| RUSTY_SOCKS_BUFFER | Message buffer size | 1024 |
| RUSTY_SOCKS_TIMEOUT | Connection timeout in seconds | 60 |
| RUSTY_SOCKS_PING | Ping interval in seconds | 30 |
| RUSTY_SOCKS_THREAD_POOL_SIZE | Number of worker threads in the pool | 4 |
| RUSTY_SOCKS_MAX_QUEUED_TASKS | Maximum number of tasks that can be queued | 1000 |
| RUSTY_SOCKS_JWT_SECRET | Secret key for JWT token signing | "your-secret-key" |

## Usage

### Running the server

```bash
cargo run --bin rusty_socks
```

Or with custom configuration:

```bash
RUSTY_SOCKS_PORT=8080 RUSTY_SOCKS_THREAD_POOL_SIZE=8 cargo run --bin rusty_socks
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

Thread pool statistics endpoint:

```
http://[host]:[port]/stats
```

### Connection Handling and Rejection

Rusty Socks uses a thread pool to efficiently manage multiple concurrent WebSocket connections. When the server is under heavy load:

1. New WebSocket connections are queued if all worker threads are busy
2. If the connection queue reaches its maximum capacity (`RUSTY_SOCKS_MAX_QUEUED_TASKS`), **new connection attempts will be rejected**
3. Rejected clients will experience a connection failure
4. Existing connections remain unaffected and continue to function normally

**Important for client implementations:**
- Implement connection retry logic with exponential backoff
- Add appropriate error handling for connection failures
- Consider monitoring connection rejection rates in production environments

This connection rejection mechanism is a deliberate design choice to maintain server stability and responsiveness for existing connections during peak loads, rather than risking degraded performance for all users.

### Authentication

Rusty Socks uses JWT tokens for authentication. To connect to the WebSocket server:

1. **Obtain a JWT token** (implement your own authentication endpoint)
2. **Include the token** in the WebSocket connection URL as a query parameter:
   ```
   ws://localhost:3030/ws?token=your_jwt_token_here
   ```

### Client example (JavaScript)

```javascript
// Assuming you have a JWT token from your auth system
const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';
const socket = new WebSocket(`ws://localhost:3030/ws?token=${token}`);

socket.onopen = function() {
  console.log('Connected to Rusty Socks server');
  
  // Join a room
  const joinMessage = {
    type: 'join_room',
    room_id: 'general',
    password: null // optional for password-protected rooms
  };
  socket.send(JSON.stringify(joinMessage));
  
  // Send a message to the room
  const message = {
    type: 'room_message',
    room_id: 'general',
    content: 'Hello from JS client',
    timestamp: new Date().toISOString()
  };
  socket.send(JSON.stringify(message));
};

socket.onmessage = function(event) {
  const message = JSON.parse(event.data);
  console.log('Received:', message);
  
  // Handle different message types
  switch(message.type) {
    case 'room_message':
      console.log(`[${message.room_id}] ${message.sender}: ${message.content}`);
      break;
    case 'user_joined':
      console.log(`${message.username} joined ${message.room_id}`);
      break;
    case 'error':
      console.error('Server error:', message.message);
      break;
  }
};

socket.onclose = function() {
  console.log('Connection closed');
};

socket.onerror = function(error) {
  console.error('WebSocket error:', error);
  // Implement exponential backoff retry here
};
```

### Room Management

Users with appropriate permissions can manage rooms:

```javascript
// Create a new room (requires ManageRoom permission)
const createRoom = {
  type: 'create_room',
  name: 'My Private Room',
  is_private: true,
  max_members: 50
};
socket.send(JSON.stringify(createRoom));

// Set user role (requires ManageRoles permission)
const setRole = {
  type: 'set_user_role',
  room_id: 'general',
  user_id: 'target_user_id',
  role: 'Moderator'
};
socket.send(JSON.stringify(setRole));

// Ban user (requires BanUsers permission)
const banUser = {
  type: 'ban_user',
  room_id: 'general',
  user_id: 'target_user_id',
  duration_hours: 24 // optional, null for permanent
};
socket.send(JSON.stringify(banUser));
```

## Performance

Rusty Socks is designed for high performance with a configurable thread pool that:

- Distributes connection handling across multiple worker threads
- Controls maximum task queue size to prevent server overload
- Provides monitoring through the `/stats` endpoint
- Efficiently utilizes multi-core processors

To optimize performance, adjust the thread pool settings based on your hardware:

```bash
# For a machine with 8 cores
RUSTY_SOCKS_THREAD_POOL_SIZE=8 RUSTY_SOCKS_MAX_QUEUED_TASKS=2000 cargo run --bin rusty_socks
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

## Load Testing

The server's thread pool allows it to handle multiple concurrent connections efficiently. To test the server under load:

1. Install a load testing tool like `artillery` or `vegeta`
2. Run the load test against the WebSocket endpoint
3. Monitor the server's thread pool stats during the test:
   ```bash
   curl http://localhost:3030/stats
   ```

4. To simulate connection rejection scenarios:
   ```bash
   # Run with a small thread pool and queue size
   RUSTY_SOCKS_THREAD_POOL_SIZE=2 RUSTY_SOCKS_MAX_QUEUED_TASKS=10 cargo run --bin rusty_socks
   
   # Then send many simultaneous connection requests
   # Observe which ones are accepted and which are rejected
   ```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request 🙃

## License

This project is licensed under the MIT License - see the LICENSE file for details.