use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: Uuid,
    pub sender: String,
    pub content: String,
    pub timestamp: DateTime<Utc>,
}

impl Message {
    pub fn new(sender: String, content: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            sender,
            content,
            timestamp: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SocketMessage {
    Connect { client_id: String },
    Disconnect { client_id: String },
    Chat(Message),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_creation() {
        let msg = Message::new("user1".to_string(), "Hello".to_string());
        assert_eq!(msg.sender, "user1");
        assert_eq!(msg.content, "Hello");
    }
}
