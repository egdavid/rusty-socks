//! Extensible plugin system for custom message handlers
//! 
//! This module provides a trait-based system for creating custom message
//! handlers that can be dynamically loaded and registered with the server.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use crate::auth::AuthenticatedUser;
use crate::core::server::SharedServerManager;
use crate::error::{Result, RustySocksError};

/// Context passed to message handlers
#[derive(Clone)]
pub struct HandlerContext {
    pub user: AuthenticatedUser,
    pub server: SharedServerManager,
    pub request_id: Option<String>,
    pub client_ip: Option<std::net::IpAddr>,
    pub metadata: HashMap<String, String>,
}

impl HandlerContext {
    pub fn new(user: AuthenticatedUser, server: SharedServerManager) -> Self {
        Self {
            user,
            server,
            request_id: None,
            client_ip: None,
            metadata: HashMap::new(),
        }
    }
    
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }
    
    pub fn with_client_ip(mut self, ip: std::net::IpAddr) -> Self {
        self.client_ip = Some(ip);
        self
    }
    
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

/// Response from a message handler
#[derive(Debug, Clone)]
pub enum HandlerResponse {
    /// Send a message back to the requesting client
    Reply(Value),
    /// Send a message to specific users
    SendToUsers {
        user_ids: Vec<String>,
        message: Value,
    },
    /// Broadcast to a room
    BroadcastToRoom {
        room_id: String,
        message: Value,
        exclude_sender: bool,
    },
    /// Broadcast to all connected clients
    BroadcastGlobal {
        message: Value,
        exclude_sender: bool,
    },
    /// No response needed
    None,
    /// Forward to another handler
    Forward {
        handler_name: String,
        message: Value,
    },
}

/// Trait for custom message handlers
#[async_trait]
pub trait MessageHandler: Send + Sync {
    /// Get the name of this handler (used for registration)
    fn name(&self) -> &'static str;
    
    /// Get the message types this handler can process
    fn message_types(&self) -> Vec<&'static str>;
    
    /// Process a message and return a response
    async fn handle_message(
        &self,
        message_type: &str,
        payload: Value,
        context: HandlerContext,
    ) -> Result<HandlerResponse>;
    
    /// Called when the handler is registered (for initialization)
    async fn on_register(&self) -> Result<()> {
        Ok(())
    }
    
    /// Called when the handler is unregistered (for cleanup)
    async fn on_unregister(&self) -> Result<()> {
        Ok(())
    }
    
    /// Get handler metadata/description
    fn description(&self) -> &'static str {
        "Custom message handler"
    }
    
    /// Get handler version
    fn version(&self) -> &'static str {
        "1.0.0"
    }
}

/// Registry for managing message handlers
pub struct HandlerRegistry {
    handlers: HashMap<String, Box<dyn MessageHandler>>,
    type_mappings: HashMap<String, String>, // message_type -> handler_name
}

impl HandlerRegistry {
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            type_mappings: HashMap::new(),
        }
    }
    
    /// Register a new message handler
    pub async fn register_handler(
        &mut self,
        handler: Box<dyn MessageHandler>,
    ) -> Result<()> {
        let name = handler.name().to_string();
        let message_types = handler.message_types();
        
        // Check for conflicts
        for msg_type in &message_types {
            if let Some(existing_handler) = self.type_mappings.get(*msg_type) {
                return Err(RustySocksError::RegistrationError(
                    format!(
                        "Message type '{}' is already handled by '{}'",
                        msg_type, existing_handler
                    )
                ));
            }
        }
        
        // Call handler's initialization
        handler.on_register().await?;
        
        // Register message type mappings
        for msg_type in message_types {
            self.type_mappings.insert(msg_type.to_string(), name.clone());
        }
        
        // Store the handler
        self.handlers.insert(name.clone(), handler);
        
        log::info!("Registered message handler: {}", name);
        Ok(())
    }
    
    /// Unregister a message handler
    pub async fn unregister_handler(&mut self, name: &str) -> Result<()> {
        if let Some(handler) = self.handlers.remove(name) {
            // Remove type mappings
            let message_types = handler.message_types();
            for msg_type in message_types {
                self.type_mappings.remove(msg_type);
            }
            
            // Call handler's cleanup
            handler.on_unregister().await?;
            
            log::info!("Unregistered message handler: {}", name);
            Ok(())
        } else {
            Err(RustySocksError::NotFound(format!("Handler '{}' not found", name)))
        }
    }
    
    /// Get a handler by name
    pub fn get_handler(&self, name: &str) -> Option<&dyn MessageHandler> {
        self.handlers.get(name).map(|h| h.as_ref())
    }
    
    /// Get a handler for a message type
    pub fn get_handler_for_type(&self, message_type: &str) -> Option<&dyn MessageHandler> {
        self.type_mappings
            .get(message_type)
            .and_then(|name| self.handlers.get(name))
            .map(|h| h.as_ref())
    }
    
    /// Handle a message with the appropriate handler
    pub async fn handle_message(
        &self,
        message_type: &str,
        payload: Value,
        context: HandlerContext,
    ) -> Result<HandlerResponse> {
        if let Some(handler) = self.get_handler_for_type(message_type) {
            handler.handle_message(message_type, payload, context).await
        } else {
            Err(RustySocksError::NotFound(
                format!("No handler registered for message type: {}", message_type)
            ))
        }
    }
    
    /// List all registered handlers
    pub fn list_handlers(&self) -> Vec<&str> {
        self.handlers.keys().map(|s| s.as_str()).collect()
    }
    
    /// Get handler info
    pub fn get_handler_info(&self, name: &str) -> Option<HandlerInfo> {
        self.handlers.get(name).map(|h| HandlerInfo {
            name: h.name(),
            description: h.description(),
            version: h.version(),
            message_types: h.message_types(),
        })
    }
    
    /// Get all handler info
    pub fn get_all_handler_info(&self) -> Vec<HandlerInfo> {
        self.handlers
            .values()
            .map(|h| HandlerInfo {
                name: h.name(),
                description: h.description(),
                version: h.version(),
                message_types: h.message_types(),
            })
            .collect()
    }
}

/// Information about a registered handler
#[derive(Debug, Clone)]
pub struct HandlerInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub version: &'static str,
    pub message_types: Vec<&'static str>,
}

/// Example gaming handler for game-specific messages
pub struct GamingHandler;

#[async_trait]
impl MessageHandler for GamingHandler {
    fn name(&self) -> &'static str {
        "gaming"
    }
    
    fn message_types(&self) -> Vec<&'static str> {
        vec![
            "game_invite",
            "game_accept",
            "game_reject",
            "game_start",
            "game_move",
            "game_end",
            "lobby_create",
            "lobby_join",
            "lobby_leave",
        ]
    }
    
    async fn handle_message(
        &self,
        message_type: &str,
        payload: Value,
        context: HandlerContext,
    ) -> Result<HandlerResponse> {
        match message_type {
            "game_invite" => {
                // Handle game invitation
                if let Some(target_user) = payload.get("target_user").and_then(|v| v.as_str()) {
                    let invite_message = serde_json::json!({
                        "type": "game_invitation",
                        "from_user": context.user.user_id,
                        "from_username": context.user.username,
                        "game_type": payload.get("game_type").unwrap_or(&Value::String("unknown".to_string())),
                        "message": format!("{} invites you to play a game!", context.user.username)
                    });
                    
                    Ok(HandlerResponse::SendToUsers {
                        user_ids: vec![target_user.to_string()],
                        message: invite_message,
                    })
                } else {
                    Err(RustySocksError::ValidationError("Missing target_user in game invite".to_string()))
                }
            }
            
            "lobby_create" => {
                // Handle lobby creation
                let lobby_name = payload.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Game Lobby");
                
                let max_players = payload.get("max_players")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(4) as usize;
                
                // Create a room for the lobby
                match context.server.create_room(lobby_name.to_string(), Some(max_players)).await {
                    Ok(room_id) => {
                        let response = serde_json::json!({
                            "type": "lobby_created",
                            "lobby_id": room_id,
                            "name": lobby_name,
                            "max_players": max_players,
                            "creator": context.user.username
                        });
                        
                        Ok(HandlerResponse::Reply(response))
                    }
                    Err(e) => Err(e),
                }
            }
            
            _ => {
                log::debug!("Unhandled gaming message type: {}", message_type);
                Ok(HandlerResponse::None)
            }
        }
    }
    
    fn description(&self) -> &'static str {
        "Handler for gaming-related messages like invites, lobbies, and game sessions"
    }
}

/// Example finance handler for trading/market messages
pub struct FinanceHandler;

#[async_trait]
impl MessageHandler for FinanceHandler {
    fn name(&self) -> &'static str {
        "finance"
    }
    
    fn message_types(&self) -> Vec<&'static str> {
        vec![
            "subscribe_ticker",
            "unsubscribe_ticker",
            "place_order",
            "cancel_order",
            "get_portfolio",
            "market_data_request",
        ]
    }
    
    async fn handle_message(
        &self,
        message_type: &str,
        payload: Value,
        context: HandlerContext,
    ) -> Result<HandlerResponse> {
        match message_type {
            "subscribe_ticker" => {
                if let Some(symbol) = payload.get("symbol").and_then(|v| v.as_str()) {
                    // Join a room for this ticker symbol
                    let room_id = format!("ticker_{}", symbol.to_uppercase());
                    
                    match context.server.join_room(context.user.user_id.clone(), room_id.clone()).await {
                        Ok(_) => {
                            let response = serde_json::json!({
                                "type": "subscription_confirmed",
                                "symbol": symbol.to_uppercase(),
                                "room_id": room_id
                            });
                            Ok(HandlerResponse::Reply(response))
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    Err(RustySocksError::ValidationError("Missing symbol in ticker subscription".to_string()))
                }
            }
            
            "place_order" => {
                // Simulate order placement
                let order_id = uuid::Uuid::new_v4().to_string();
                let _response = serde_json::json!({
                    "type": "order_placed",
                    "order_id": order_id,
                    "status": "pending",
                    "symbol": payload.get("symbol"),
                    "quantity": payload.get("quantity"),
                    "price": payload.get("price"),
                    "order_type": payload.get("order_type")
                });
                
                // Notify trading room
                let trading_notification = serde_json::json!({
                    "type": "new_order",
                    "user": context.user.username,
                    "order_id": order_id,
                    "symbol": payload.get("symbol"),
                    "quantity": payload.get("quantity")
                });
                
                Ok(HandlerResponse::BroadcastToRoom {
                    room_id: "trading_floor".to_string(),
                    message: trading_notification,
                    exclude_sender: true,
                })
            }
            
            _ => {
                log::debug!("Unhandled finance message type: {}", message_type);
                Ok(HandlerResponse::None)
            }
        }
    }
    
    fn description(&self) -> &'static str {
        "Handler for finance and trading messages including orders, subscriptions, and market data"
    }
}

/// Utility function to create a registry with common handlers
pub async fn create_default_registry() -> Result<HandlerRegistry> {
    let mut registry = HandlerRegistry::new();
    
    // Register gaming handler
    registry.register_handler(Box::new(GamingHandler)).await?;
    
    // Register finance handler  
    registry.register_handler(Box::new(FinanceHandler)).await?;
    
    Ok(registry)
}

/// Middleware trait for processing messages before/after handlers
#[async_trait]
pub trait HandlerMiddleware: Send + Sync {
    /// Called before the handler processes the message
    async fn pre_handle(
        &self,
        message_type: &str,
        payload: &Value,
        context: &HandlerContext,
    ) -> Result<bool>; // Return false to skip handler
    
    /// Called after the handler processes the message
    async fn post_handle(
        &self,
        message_type: &str,
        payload: &Value,
        context: &HandlerContext,
        response: &HandlerResponse,
    ) -> Result<()>;
}

/// Example logging middleware
pub struct LoggingMiddleware;

#[async_trait]
impl HandlerMiddleware for LoggingMiddleware {
    async fn pre_handle(
        &self,
        message_type: &str,
        _payload: &Value,
        context: &HandlerContext,
    ) -> Result<bool> {
        log::info!("Processing message type '{}' for user '{}'", message_type, context.user.user_id);
        Ok(true)
    }
    
    async fn post_handle(
        &self,
        message_type: &str,
        _payload: &Value,
        context: &HandlerContext,
        response: &HandlerResponse,
    ) -> Result<()> {
        log::debug!("Completed handling '{}' for user '{}', response: {:?}", 
                   message_type, context.user.user_id, response);
        Ok(())
    }
}