# Quick Start

Get a RustySocks server running in under 5 minutes!

## Step 1: Install RustySocks

```bash
cargo install rusty-socks
```

## Step 2: Create Configuration

Create a `.env` file with minimal configuration:

```bash
# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080

# Security (Generate secure values for production!)
JWT_SECRET=your-secret-key-change-this
ENCRYPTION_KEY=your-32-byte-encryption-key-here

# Optional: Enable TLS
# TLS_CERT_PATH=/path/to/cert.pem
# TLS_KEY_PATH=/path/to/key.pem
```

## Step 3: Run the Server

```bash
rustysocks serve
```

You should see:
```
[INFO] RustySocks v0.1.0 starting...
[INFO] Server listening on ws://0.0.0.0:8080
[INFO] Security checks passed
[INFO] Ready to accept connections
```

## Step 4: Connect a Client

### Using JavaScript/TypeScript

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onopen = () => {
    console.log('Connected to RustySocks!');
    
    // Send authentication
    ws.send(JSON.stringify({
        type: 'AUTH',
        payload: {
            token: 'your-jwt-token'
        }
    }));
};

ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    console.log('Received:', message);
};

// Join a room
ws.send(JSON.stringify({
    type: 'JOIN_ROOM',
    payload: {
        room_id: 'general'
    }
}));

// Broadcast a message
ws.send(JSON.stringify({
    type: 'BROADCAST',
    payload: {
        room_id: 'general',
        message: 'Hello, RustySocks!'
    }
}));
```

### Using the RustySocks Client Library

```javascript
import { RustySocksClient } from 'rustysocks-client';

const client = new RustySocksClient('ws://localhost:8080');

await client.connect();
await client.authenticate('your-jwt-token');
await client.joinRoom('general');

client.on('message', (msg) => {
    console.log('Received:', msg);
});

await client.broadcast('general', 'Hello, RustySocks!');
```

## Step 5: Monitor Your Server

Check server health:

```bash
curl http://localhost:8080/health
```

View metrics:

```bash
curl http://localhost:8080/metrics
```

## Example: Simple Chat Server

Here's a complete example of a chat server:

### Server Configuration

```rust
use rusty_socks::{Server, ServerConfig, MessageHandler, Message};
use std::sync::Arc;

#[derive(Clone)]
struct ChatHandler;

#[async_trait::async_trait]
impl MessageHandler for ChatHandler {
    async fn handle_message(
        &self,
        message: Message,
        context: Arc<rusty_socks::Context>
    ) -> rusty_socks::Result<()> {
        match message.message_type.as_str() {
            "CHAT" => {
                // Broadcast to all users in the room
                context.broadcast_to_room(
                    &message.room_id.unwrap_or_default(),
                    message
                ).await?;
            }
            _ => {}
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ServerConfig::from_env()?;
    let server = Server::builder()
        .config(config)
        .handler(ChatHandler)
        .build()
        .await?;
    
    server.run().await?;
    Ok(())
}
```

### HTML Client

```html
<!DOCTYPE html>
<html>
<head>
    <title>RustySocks Chat</title>
</head>
<body>
    <div id="messages"></div>
    <input type="text" id="input" placeholder="Type a message...">
    <button onclick="sendMessage()">Send</button>

    <script>
        const ws = new WebSocket('ws://localhost:8080/ws');
        const messages = document.getElementById('messages');
        
        ws.onmessage = (event) => {
            const msg = JSON.parse(event.data);
            if (msg.type === 'CHAT') {
                const div = document.createElement('div');
                div.textContent = msg.payload.message;
                messages.appendChild(div);
            }
        };
        
        function sendMessage() {
            const input = document.getElementById('input');
            ws.send(JSON.stringify({
                type: 'CHAT',
                room_id: 'general',
                payload: {
                    message: input.value
                }
            }));
            input.value = '';
        }
    </script>
</body>
</html>
```

## What's Next?

Now that you have a basic server running:

1. **Secure your server**: Follow the [TLS Configuration Guide](./tls.md)
2. **Add authentication**: Implement [JWT Authentication](../guide/authentication.md)
3. **Scale up**: Learn about [Clustering](../advanced/clustering.md)
4. **Monitor performance**: Set up [Metrics & Monitoring](../advanced/monitoring.md)

## Troubleshooting

### Connection Refused

Ensure the server is running and the port is not blocked:
```bash
netstat -an | grep 8080
```

### Authentication Failed

Check your JWT secret matches between server and client:
```bash
echo $JWT_SECRET
```

### Performance Issues

Enable debug logging:
```bash
RUST_LOG=debug rustysocks serve
```

For more help, see our [Troubleshooting Guide](../troubleshooting.md).