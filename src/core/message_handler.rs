//! Message handler with room-based routing and permission checking

use log::debug;
use serde_json;

use crate::core::message_types::{ClientMessage, RoomInfo, ServerMessage, UserInfo};
use crate::core::server::SharedServerManager;
use crate::core::OperationType;
use crate::security::{
    protect_user_content, clean_user_input, contains_xss_patterns,
    UnicodeSecurityValidator, UnicodeSecurityConfig, UnicodeSecurityError
};
use crate::error::{Result, RustySocksError};

/// Handles incoming client messages and routes them appropriately
pub struct MessageHandler {
    server: SharedServerManager,
    unicode_validator: UnicodeSecurityValidator,
}

impl MessageHandler {
    /// Create a new message handler
    pub fn new(server: SharedServerManager) -> Self {
        // Configure Unicode validator for chat messages
        let mut config = UnicodeSecurityConfig::default();
        config.max_normalized_length = 2000; // Match MAX_MESSAGE_LENGTH
        config.allow_mixed_scripts = false; // Prevent homograph attacks
        config.allow_bidirectional = false; // Prevent BiDi spoofing
        config.allow_private_use = false; // Block private use characters
        
        Self { 
            server,
            unicode_validator: UnicodeSecurityValidator::with_config(config),
        }
    }
    
    /// Create a Unicode validator specifically configured for room names
    fn create_room_name_validator(&self) -> UnicodeSecurityValidator {
        let mut config = UnicodeSecurityConfig::default();
        config.max_normalized_length = 50; // Shorter limit for room names
        config.allow_mixed_scripts = false; // Strict: prevent homograph attacks
        config.allow_bidirectional = false; // Prevent BiDi spoofing in room names
        config.allow_private_use = false; // Block private use characters
        
        UnicodeSecurityValidator::with_config(config)
    }
    
    /// Helper to send message to user with proper error logging
    async fn send_to_user_safe(&self, user_id: &str, message: &str, context: &str) {
        if let Err(e) = self.server.send_to_user(user_id, message).await {
            log::warn!("Failed to send {} to user {}: {}", context, user_id, e);
        }
    }
    
    /// Helper to broadcast to room with proper error logging
    async fn broadcast_to_room_safe(&self, room_id: &str, message: &str, exclude_user: Option<&str>, context: &str) {
        match self.server.broadcast_to_room(room_id, message, exclude_user).await {
            Ok(count) => {
                log::debug!("Broadcast {} to {} users in room {}", context, count, room_id);
            }
            Err(e) => {
                log::warn!("Failed to broadcast {} to room {}: {}", context, room_id, e);
            }
        }
    }
    
    /// Validate message content for security and quality with comprehensive Unicode protection
    fn validate_message_content(&self, content: &str) -> std::result::Result<String, String> {
        // Check if message is empty or only whitespace
        if content.trim().is_empty() {
            return Err("Message cannot be empty".to_string());
        }
        
        // SECURITY: Comprehensive Unicode validation to prevent Unicode-based attacks
        let validated_content = match self.unicode_validator.validate(content) {
            Ok(safe_content) => safe_content,
            Err(unicode_error) => {
                let error_msg = match unicode_error {
                    UnicodeSecurityError::ControlCharacters(details) => {
                        log::warn!("Message blocked: Control characters detected - {}", details);
                        "Message contains dangerous control characters".to_string()
                    },
                    UnicodeSecurityError::BidirectionalOverride(details) => {
                        log::warn!("Message blocked: BiDi attack detected - {}", details);
                        "Message contains bidirectional text formatting that could be malicious".to_string()
                    },
                    UnicodeSecurityError::HomographAttack(details) => {
                        log::warn!("Message blocked: Homograph attack detected - {}", details);
                        "Message contains lookalike characters that could be deceptive".to_string()
                    },
                    UnicodeSecurityError::MixedScriptAttack(details) => {
                        log::warn!("Message blocked: Mixed script attack detected - {}", details);
                        "Message mixes different writing systems in a suspicious way".to_string()
                    },
                    UnicodeSecurityError::InvalidUnicode(details) => {
                        log::warn!("Message blocked: Invalid Unicode - {}", details);
                        "Message contains invalid Unicode sequences".to_string()
                    },
                    UnicodeSecurityError::NormalizationAttack(details) => {
                        log::warn!("Message blocked: Normalization attack - {}", details);
                        "Message contains Unicode normalization attack".to_string()
                    },
                    UnicodeSecurityError::NormalizationExpansion(details) => {
                        log::warn!("Message blocked: Normalization expansion - {}", details);
                        "Message too long after Unicode normalization".to_string()
                    },
                    UnicodeSecurityError::InvisibleCharacters(details) => {
                        log::warn!("Message blocked: Invisible characters - {}", details);
                        "Message contains invisible characters".to_string()
                    },
                    UnicodeSecurityError::PrivateUseCharacters(details) => {
                        log::warn!("Message blocked: Private use characters - {}", details);
                        "Message contains private use Unicode characters".to_string()
                    },
                };
                return Err(error_msg);
            }
        };
        
        // Additional legacy validations (still useful as secondary checks)
        
        // Check message length (prevent DoS with huge messages)
        const MAX_MESSAGE_LENGTH: usize = 2000;
        if validated_content.len() > MAX_MESSAGE_LENGTH {
            return Err(format!("Message too long. Maximum {} characters allowed", MAX_MESSAGE_LENGTH));
        }
        
        // Check for excessive repeated characters (spam detection)
        if self.has_excessive_repetition(&validated_content) {
            return Err("Message contains excessive repeated characters".to_string());
        }
        
        // Check for suspicious patterns that might be injection attempts
        if self.contains_suspicious_patterns(&validated_content) {
            return Err("Message contains suspicious content".to_string());
        }
        
        // Check for null bytes (should be caught by Unicode validation but double-check)
        if validated_content.contains('\0') {
            return Err("Message contains null bytes".to_string());
        }
        
        // Return the validated and normalized content
        Ok(validated_content)
    }
    
    /// Check for excessive character repetition (simple spam detection)
    fn has_excessive_repetition(&self, content: &str) -> bool {
        const MAX_CONSECUTIVE_CHARS: usize = 10;
        
        let chars: Vec<char> = content.chars().collect();
        if chars.len() < MAX_CONSECUTIVE_CHARS {
            return false;
        }
        
        let mut consecutive_count = 1;
        for i in 1..chars.len() {
            if chars[i] == chars[i-1] {
                consecutive_count += 1;
                if consecutive_count >= MAX_CONSECUTIVE_CHARS {
                    return true;
                }
            } else {
                consecutive_count = 1;
            }
        }
        
        false
    }
    
    /// Check for suspicious patterns that might indicate injection attempts
    fn contains_suspicious_patterns(&self, content: &str) -> bool {
        // Use the comprehensive XSS protection
        contains_xss_patterns(content)
    }

    /// Process a client message
    pub async fn handle_client_message(&self, sender_id: &str, message_text: &str) -> Result<()> {
        // SECURITY: Reduced message size limit to prevent DoS attacks
        const MAX_JSON_MESSAGE_SIZE: usize = 2048; // 2KB max (was 8KB, reduced for security)
        
        if message_text.len() > MAX_JSON_MESSAGE_SIZE {
            log::warn!("Large message rejected from {}: {} bytes", sender_id, message_text.len());
            return Err(RustySocksError::MessageTooLarge(message_text.len()));
        }
        
        // Track message processing stats for monitoring
        let processing_start = std::time::Instant::now();
        
        // Validate JSON structure (basic security check)
        if message_text.matches('{').count() != message_text.matches('}').count() ||
           message_text.matches('[').count() != message_text.matches(']').count() {
            return Err(RustySocksError::MessageParseError("Malformed JSON structure".to_string()));
        }
        
        // Parse the client message
        let client_message: ClientMessage = serde_json::from_str(message_text)
            .map_err(|e| RustySocksError::MessageParseError(format!("Invalid JSON: {}", e)))?;

        match client_message {
            ClientMessage::JoinRoom {
                room_id,
                password: _,
            } => self.handle_join_room(sender_id, room_id).await,

            ClientMessage::LeaveRoom { room_id } => {
                self.handle_leave_room(sender_id, &room_id).await
            }

            ClientMessage::RoomMessage { room_id, content } => {
                self.handle_room_message(sender_id, &room_id, &content)
                    .await
            }

            ClientMessage::PrivateMessage {
                target_user_id,
                content,
            } => {
                self.handle_private_message(sender_id, &target_user_id, &content)
                    .await
            }

            ClientMessage::CreateRoom {
                name,
                is_private: _,
                max_members,
                password: _,
            } => self.handle_create_room(sender_id, name, max_members).await,

            ClientMessage::ListRooms => self.handle_list_rooms(sender_id).await,

            ClientMessage::GetRoomMembers { room_id } => {
                self.handle_get_room_members(sender_id, &room_id).await
            }

            ClientMessage::SetUserRole {
                room_id,
                user_id,
                role,
            } => {
                self.handle_set_user_role(sender_id, &room_id, &user_id, &role)
                    .await
            }

            ClientMessage::BanUser {
                room_id,
                user_id,
                duration_hours,
            } => {
                self.handle_ban_user(sender_id, &room_id, &user_id, duration_hours)
                    .await
            }

            ClientMessage::KickUser { room_id, user_id } => {
                self.handle_kick_user(sender_id, &room_id, &user_id).await
            }
        }?;
        
        // SECURITY: Track message processing time and size for monitoring
        let processing_time = processing_start.elapsed();
        if processing_time.as_millis() > 100 {
            log::warn!("Slow message processing: {}ms for user {} (size: {} bytes)", 
                       processing_time.as_millis(), sender_id, message_text.len());
        }
        
        log::trace!("Message processed: user={}, size={} bytes, time={}ms", 
                   sender_id, message_text.len(), processing_time.as_millis());
        
        Ok(())
    }

    /// Handle join room request
    async fn handle_join_room(&self, sender_id: &str, room_id: String) -> Result<()> {
        // SECURITY: Validate and clean room ID to prevent XSS
        let cleaned_room_id = match clean_user_input(&room_id) {
            Some(cleaned) => cleaned,
            None => {
                let error_msg = ServerMessage::Error {
                    code: "INVALID_ROOM_ID".to_string(),
                    message: "Invalid room ID. Room names can only contain letters, numbers, hyphens, and underscores.".to_string(),
                };
                let error_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &error_str, "error message").await;
                return Err(RustySocksError::ValidationError("Invalid room ID".to_string()));
            }
        };

        // Check multi-tier rate limiting for room management
        let user_tier = self.server.determine_user_tier(sender_id).await;
        let user_ip = self.server.get_user_ip(sender_id).await.unwrap_or_else(|| {
            log::warn!("Could not get IP for user {}, using localhost fallback", sender_id);
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        });
        
        if !self.server.can_user_perform_operation(sender_id, user_ip, user_tier, OperationType::RoomManagement).await {
            let error_msg = ServerMessage::Error {
                code: "RATE_LIMITED".to_string(),
                message: "Room management rate limit exceeded. Please wait before joining/leaving rooms.".to_string(),
            };
            let msg_str = serde_json::to_string(&error_msg).unwrap();
            self.send_to_user_safe(sender_id, &msg_str, "rate limit error").await;
            return Err(RustySocksError::Forbidden);
        }
        match self
            .server
            .join_room(sender_id.to_string(), cleaned_room_id.clone())
            .await
        {
            Ok(_) => {
                // Send success message
                let success_msg = ServerMessage::Success {
                    message: format!("Joined room: {}", cleaned_room_id),
                    data: None,
                };
                let msg_str = serde_json::to_string(&success_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;

                // Notify room members
                let join_notification = ServerMessage::UserJoined {
                    room_id: cleaned_room_id.clone(),
                    user_id: sender_id.to_string(),
                    username: protect_user_content(&self.server.get_user_info(sender_id).await.unwrap_or_else(|| "Unknown".to_string())),
                };
                let notification_str = serde_json::to_string(&join_notification).unwrap();
                self.broadcast_to_room_safe(&cleaned_room_id, &notification_str, Some(sender_id), "join notification").await;

                Ok(())
            }
            Err(e) => {
                let error_msg = ServerMessage::Error {
                    code: "JOIN_FAILED".to_string(),
                    message: format!("Failed to join room: {}", e),
                };
                let msg_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                Err(e)
            }
        }
    }

    /// Handle leave room request
    async fn handle_leave_room(&self, sender_id: &str, room_id: &str) -> Result<()> {
        // Check multi-tier rate limiting for room management
        let user_tier = self.server.determine_user_tier(sender_id).await;
        let user_ip = self.server.get_user_ip(sender_id).await.unwrap_or_else(|| {
            log::warn!("Could not get IP for user {}, using localhost fallback", sender_id);
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        });
        
        if !self.server.can_user_perform_operation(sender_id, user_ip, user_tier, OperationType::RoomManagement).await {
            let error_msg = ServerMessage::Error {
                code: "RATE_LIMITED".to_string(),
                message: "Room management rate limit exceeded. Please wait before joining/leaving rooms.".to_string(),
            };
            let msg_str = serde_json::to_string(&error_msg).unwrap();
            self.send_to_user_safe(sender_id, &msg_str, "rate limit error").await;
            return Err(RustySocksError::Forbidden);
        }
        match self.server.leave_room(sender_id, room_id).await {
            Ok(_) => {
                // Notify room members
                let leave_notification = ServerMessage::UserLeft {
                    room_id: room_id.to_string(),
                    user_id: sender_id.to_string(),
                    username: self.server.get_user_info(sender_id).await.unwrap_or_else(|| "Unknown".to_string()),
                };
                let notification_str = serde_json::to_string(&leave_notification).unwrap();
                self.broadcast_to_room_safe(room_id, &notification_str, Some(sender_id), "leave notification").await;

                Ok(())
            }
            Err(e) => {
                let error_msg = ServerMessage::Error {
                    code: "LEAVE_FAILED".to_string(),
                    message: format!("Failed to leave room: {}", e),
                };
                let msg_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                Err(e)
            }
        }
    }

    /// Handle room message with comprehensive input validation
    async fn handle_room_message(
        &self,
        sender_id: &str,
        room_id: &str,
        content: &str,
    ) -> Result<()> {
        // Validate message content first and get the validated (normalized) content
        let validated_content = match self.validate_message_content(content) {
            Ok(safe_content) => safe_content,
            Err(validation_error) => {
                let error_msg = ServerMessage::Error {
                    code: "INVALID_MESSAGE".to_string(),
                    message: validation_error.clone(),
                };
                let error_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &error_str, "validation error").await;
                return Err(RustySocksError::ValidationError(validation_error));
            }
        };
        
        // Check multi-tier rate limiting
        let user_tier = self.server.determine_user_tier(sender_id).await;
        let user_ip = self.server.get_user_ip(sender_id).await.unwrap_or_else(|| {
            log::warn!("Could not get IP for user {}, using localhost fallback", sender_id);
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        });
        
        if !self.server.can_user_perform_operation(sender_id, user_ip, user_tier.clone(), OperationType::Message).await {
            // Get rate limit status for more detailed error message
            let status_msg = if let Some(status) = self.server.get_user_rate_status(sender_id).await {
                if status.penalty_level > 1.0 {
                    format!("Rate limit exceeded. Penalty level: {:.1}x (violations: {}). Please slow down.", 
                           status.penalty_level, status.violation_count)
                } else {
                    format!("Rate limit exceeded. You have sent {} messages recently. Please slow down.", 
                           status.recent_requests)
                }
            } else {
                "Rate limit exceeded. Please slow down.".to_string()
            };
            
            let error_msg = ServerMessage::Error {
                code: "RATE_LIMITED".to_string(),
                message: status_msg,
            };
            let error_str = serde_json::to_string(&error_msg).unwrap();
            self.send_to_user_safe(sender_id, &error_str, "rate limit error").await;
            
            log::info!("Rate limit exceeded for user {} (tier: {:?})", sender_id, user_tier);
            return Err(RustySocksError::Forbidden);
        }
        
        // Check if user has permission to send messages in this room
        match self.server.can_user_send_message(sender_id, room_id).await {
            Ok(true) => {
                // User has permission, proceed
            }
            Ok(false) => {
                // User doesn't have permission
                let error_msg = ServerMessage::Error {
                    code: "FORBIDDEN".to_string(),
                    message: "You don't have permission to send messages in this room. You may be banned, muted, or not a member.".to_string(),
                };
                let error_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &error_str, "error message").await;
                return Err(RustySocksError::Forbidden);
            }
            Err(e) => {
                // Error checking permissions
                let error_msg = ServerMessage::Error {
                    code: "PERMISSION_CHECK_FAILED".to_string(),
                    message: format!("Failed to check permissions: {}", e),
                };
                let error_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &error_str, "error message").await;
                return Err(e);
            }
        }

        // Get user information for display
        let sender_username = self.server.get_user_info(sender_id).await
            .unwrap_or_else(|| "Unknown".to_string());

        // SECURITY: Apply additional XSS protection to the already Unicode-validated content
        let protected_content = protect_user_content(&validated_content);

        let room_message = ServerMessage::RoomMessage {
            room_id: room_id.to_string(),
            sender_id: sender_id.to_string(),
            sender_username: protect_user_content(&sender_username),
            content: protected_content,
            timestamp: chrono::Utc::now(),
        };

        let msg_str = serde_json::to_string(&room_message).unwrap();

        match self
            .server
            .broadcast_to_room(room_id, &msg_str, Some(sender_id))
            .await
        {
            Ok(sent_count) => {
                debug!(
                    "Room message sent to {} users in room {}",
                    sent_count, room_id
                );
                Ok(())
            }
            Err(e) => {
                let error_msg = ServerMessage::Error {
                    code: "SEND_FAILED".to_string(),
                    message: format!("Failed to send message: {}", e),
                };
                let error_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &error_str, "error message").await;
                Err(e)
            }
        }
    }

    /// Handle private message
    async fn handle_private_message(
        &self,
        sender_id: &str,
        target_user_id: &str,
        content: &str,
    ) -> Result<()> {
        // Validate message content first and get the validated (normalized) content
        let validated_content = match self.validate_message_content(content) {
            Ok(safe_content) => safe_content,
            Err(validation_error) => {
                let error_msg = ServerMessage::Error {
                    code: "INVALID_MESSAGE".to_string(),
                    message: validation_error.clone(),
                };
                let error_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &error_str, "validation error").await;
                return Err(RustySocksError::ValidationError(validation_error));
            }
        };
        
        // Check multi-tier rate limiting for private messages
        let user_tier = self.server.determine_user_tier(sender_id).await;
        let user_ip = self.server.get_user_ip(sender_id).await.unwrap_or_else(|| {
            log::warn!("Could not get IP for user {}, using localhost fallback", sender_id);
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        });
        
        if !self.server.can_user_perform_operation(sender_id, user_ip, user_tier, OperationType::PrivateMessage).await {
            let error_msg = ServerMessage::Error {
                code: "RATE_LIMITED".to_string(),
                message: "Private message rate limit exceeded. Please slow down.".to_string(),
            };
            let error_str = serde_json::to_string(&error_msg).unwrap();
            self.send_to_user_safe(sender_id, &error_str, "rate limit error").await;
            return Err(RustySocksError::Forbidden);
        }
        let private_message = ServerMessage::PrivateMessage {
            sender_id: sender_id.to_string(),
            sender_username: self.server.get_user_info(sender_id).await.unwrap_or_else(|| "Unknown".to_string()),
            content: protect_user_content(&validated_content), // Apply XSS protection to validated content
            timestamp: chrono::Utc::now(),
        };

        let msg_str = serde_json::to_string(&private_message).unwrap();

        match self.server.send_to_user(target_user_id, &msg_str).await {
            Ok(_) => Ok(()),
            Err(e) => {
                let error_msg = ServerMessage::Error {
                    code: "SEND_FAILED".to_string(),
                    message: format!("Failed to send private message: {}", e),
                };
                let error_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &error_str, "error message").await;
                Err(e)
            }
        }
    }

    /// Handle create room request
    async fn handle_create_room(
        &self,
        sender_id: &str,
        name: String,
        max_members: Option<usize>,
    ) -> Result<()> {
        // Check multi-tier rate limiting for room creation (very restrictive)
        let user_tier = self.server.determine_user_tier(sender_id).await;
        let user_ip = self.server.get_user_ip(sender_id).await.unwrap_or_else(|| {
            log::warn!("Could not get IP for user {}, using localhost fallback", sender_id);
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        });
        
        if !self.server.can_user_perform_operation(sender_id, user_ip, user_tier.clone(), OperationType::RoomCreation).await {
            let error_msg = ServerMessage::Error {
                code: "RATE_LIMITED".to_string(),
                message: "Room creation rate limit exceeded. Please wait before creating another room.".to_string(),
            };
            let msg_str = serde_json::to_string(&error_msg).unwrap();
            self.send_to_user_safe(sender_id, &msg_str, "rate limit error").await;
            return Err(RustySocksError::Forbidden);
        }
        // Check if user has permission to create rooms
        let user_info = self.server.get_user_info(sender_id).await;
        let has_permission = if let Some(info) = user_info {
            // Check if user has global CreateRooms permission
            // For now, check if user has Admin/Owner role in any room or global role
            // Check against user database in production
            info.contains("Admin") || info.contains("Owner")
        } else {
            // Anonymous users cannot create rooms
            false
        };

        if !has_permission {
            let error_msg = ServerMessage::Error {
                code: "PERMISSION_DENIED".to_string(),
                message: "You don't have permission to create rooms".to_string(),
            };
            let msg_str = serde_json::to_string(&error_msg).unwrap();
            self.send_to_user_safe(sender_id, &msg_str, "permission denied").await;
            return Err(RustySocksError::PermissionDenied(
                "User lacks CreateRooms permission".to_string()
            ));
        }

        // SECURITY: Comprehensive Unicode validation for room names
        let room_name_validator = self.create_room_name_validator();
        let validated_room_name = match room_name_validator.validate(&name) {
            Ok(safe_name) => safe_name,
            Err(unicode_error) => {
                let (error_code, error_msg) = match unicode_error {
                    UnicodeSecurityError::ControlCharacters(_) => {
                        ("INVALID_CHARACTERS", "Room name contains dangerous control characters")
                    },
                    UnicodeSecurityError::BidirectionalOverride(_) => {
                        ("INVALID_CHARACTERS", "Room name contains bidirectional formatting")
                    },
                    UnicodeSecurityError::HomographAttack(_) => {
                        ("HOMOGRAPH_ATTACK", "Room name contains lookalike characters that could be deceptive")
                    },
                    UnicodeSecurityError::MixedScriptAttack(_) => {
                        ("MIXED_SCRIPTS", "Room name mixes different writing systems")
                    },
                    UnicodeSecurityError::InvalidUnicode(_) => {
                        ("INVALID_UNICODE", "Room name contains invalid Unicode")
                    },
                    UnicodeSecurityError::NormalizationAttack(_) => {
                        ("NORMALIZATION_ATTACK", "Room name contains Unicode normalization attack")
                    },
                    UnicodeSecurityError::NormalizationExpansion(_) => {
                        ("NAME_TOO_LONG", "Room name too long after normalization")
                    },
                    UnicodeSecurityError::InvisibleCharacters(_) => {
                        ("INVALID_CHARACTERS", "Room name contains invisible characters")
                    },
                    UnicodeSecurityError::PrivateUseCharacters(_) => {
                        ("INVALID_CHARACTERS", "Room name contains private Unicode characters")
                    },
                };
                
                log::warn!("Room creation blocked: {} - {:?}", error_msg, unicode_error);
                
                let error_response = ServerMessage::Error {
                    code: error_code.to_string(),
                    message: error_msg.to_string(),
                };
                let msg_str = serde_json::to_string(&error_response).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "validation error").await;
                return Err(RustySocksError::ValidationError(error_msg.to_string()));
            }
        };

        // Basic length check (after Unicode normalization)
        if validated_room_name.trim().is_empty() {
            let error_msg = ServerMessage::Error {
                code: "INVALID_NAME".to_string(),
                message: "Room name cannot be empty".to_string(),
            };
            let msg_str = serde_json::to_string(&error_msg).unwrap();
            self.send_to_user_safe(sender_id, &msg_str, "validation error").await;
            return Err(RustySocksError::ValidationError(
                "Empty room name".to_string()
            ));
        }

        // Additional basic checks (most security checks are now handled by Unicode validation)
        
        // Check for path traversal patterns (extra security layer)
        if validated_room_name.contains("..") || validated_room_name.contains("./") || validated_room_name.contains(".\\") {
            let error_msg = ServerMessage::Error {
                code: "INVALID_PATTERN".to_string(),
                message: "Room name contains invalid patterns".to_string(),
            };
            let msg_str = serde_json::to_string(&error_msg).unwrap();
            self.send_to_user_safe(sender_id, &msg_str, "validation error").await;
            return Err(RustySocksError::ValidationError(
                "Path traversal attempt in room name".to_string()
            ));
        }

        // Ensure minimum length (after Unicode normalization and trimming)
        if validated_room_name.trim().len() < 2 {
            let error_msg = ServerMessage::Error {
                code: "NAME_TOO_SHORT".to_string(),
                message: "Room name must be at least 2 characters long".to_string(),
            };
            let msg_str = serde_json::to_string(&error_msg).unwrap();
            self.send_to_user_safe(sender_id, &msg_str, "validation error").await;
            return Err(RustySocksError::ValidationError(
                "Room name too short".to_string()
            ));
        }

        // Validate max_members
        if let Some(max) = max_members {
            if max == 0 || max > 1000 {
                let error_msg = ServerMessage::Error {
                    code: "INVALID_MAX_MEMBERS".to_string(),
                    message: "Max members must be between 1 and 1000".to_string(),
                };
                let msg_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "validation error").await;
                return Err(RustySocksError::ValidationError(
                    "Invalid max members value".to_string()
                ));
            }
        }

        match self.server.create_room(validated_room_name.clone(), max_members).await {
            Ok(room_id) => {
                let success_msg = ServerMessage::Success {
                    message: format!("Room '{}' created", validated_room_name),
                    data: Some(serde_json::json!({ "room_id": room_id })),
                };
                let msg_str = serde_json::to_string(&success_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                log::info!("User {} created room '{}' ({})", sender_id, validated_room_name, room_id);
                Ok(())
            }
            Err(e) => {
                let error_msg = ServerMessage::Error {
                    code: "CREATE_FAILED".to_string(),
                    message: "Failed to create room due to server error".to_string(),
                };
                let msg_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "error message").await;
                log::warn!("Failed to create room for user {}: {}", sender_id, e);
                Err(e)
            }
        }
    }

    /// Handle list rooms request
    async fn handle_list_rooms(&self, sender_id: &str) -> Result<()> {
        let rooms_data = self.server.list_rooms().await;
        let rooms: Vec<RoomInfo> = rooms_data
            .into_iter()
            .map(|(id, name, member_count)| RoomInfo {
                id,
                name,
                member_count,
                max_members: None,        // Retrieve from room data in production
                is_private: false,        // Retrieve from room data in production
                requires_password: false, // Retrieve from room data in production
            })
            .collect();

        let response = ServerMessage::RoomList { rooms };
        let msg_str = serde_json::to_string(&response).unwrap();
        self.send_to_user_safe(sender_id, &msg_str, "room list response").await;
        Ok(())
    }

    /// Handle get room members request
    async fn handle_get_room_members(&self, sender_id: &str, room_id: &str) -> Result<()> {
        match self.server.get_room_members(room_id).await {
            Ok(member_ids) => {
                let mut members: Vec<UserInfo> = Vec::new();
                for member_id in member_ids {
                    let username = self.server.get_user_info(&member_id).await.unwrap_or_else(|| "Unknown".to_string());
                    // NOTE: Role system implemented - use server.get_user_role() method
                    let role = None; // Integrate get_user_role() call in production
                    // Check if user is actually online in production
                    let is_online = true;
                    
                    members.push(UserInfo {
                        id: member_id,
                        username,
                        role,
                        is_online,
                    });
                }

                let response = ServerMessage::RoomMembers {
                    room_id: room_id.to_string(),
                    members,
                };
                let msg_str = serde_json::to_string(&response).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                Ok(())
            }
            Err(e) => {
                let error_msg = ServerMessage::Error {
                    code: "GET_MEMBERS_FAILED".to_string(),
                    message: format!("Failed to get room members: {}", e),
                };
                let msg_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                Err(e)
            }
        }
    }

    /// Handle set user role request
    async fn handle_set_user_role(
        &self,
        sender_id: &str,
        room_id: &str,
        user_id: &str,
        role: &str,
    ) -> Result<()> {
        // Check if sender has permission to manage roles
        match self.server.can_user_moderate(sender_id, room_id, crate::auth::user::Permission::ManageRoles).await {
            Ok(true) => {
                // Has permission, proceed
            }
            Ok(false) => {
                let error_msg = ServerMessage::Error {
                    code: "FORBIDDEN".to_string(),
                    message: "You don't have permission to manage roles in this room".to_string(),
                };
                let msg_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                return Err(RustySocksError::Forbidden);
            }
            Err(e) => {
                let error_msg = ServerMessage::Error {
                    code: "PERMISSION_CHECK_FAILED".to_string(),
                    message: format!("Failed to check permissions: {}", e),
                };
                let msg_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                return Err(e);
            }
        }
        
        // Parse role string to UserRole enum
        let user_role = match role.to_lowercase().as_str() {
            "owner" => crate::auth::user::UserRole::Owner,
            "admin" => crate::auth::user::UserRole::Admin,
            "moderator" => crate::auth::user::UserRole::Moderator,
            "member" => crate::auth::user::UserRole::Member,
            "guest" => crate::auth::user::UserRole::Guest,
            _ => {
                let error_msg = ServerMessage::Error {
                    code: "INVALID_ROLE".to_string(),
                    message: format!("Invalid role: {}. Valid roles: owner, admin, moderator, member, guest", role),
                };
                let msg_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                return Err(RustySocksError::MessageParseError("Invalid role".to_string()));
            }
        };
        
        // Set the role
        match self.server.set_user_role(sender_id, room_id, user_id, user_role).await {
            Ok(_) => {
                let success_msg = ServerMessage::Success {
                    message: format!("Role set successfully for user {} in room {}", user_id, room_id),
                    data: Some(serde_json::json!({
                        "user_id": user_id,
                        "room_id": room_id,
                        "new_role": role
                    })),
                };
                let msg_str = serde_json::to_string(&success_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                Ok(())
            }
            Err(e) => {
                let error_msg = ServerMessage::Error {
                    code: "SET_ROLE_FAILED".to_string(),
                    message: format!("Failed to set role: {}", e),
                };
                let msg_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                Err(e)
            }
        }
    }

    /// Handle ban user request
    async fn handle_ban_user(
        &self,
        sender_id: &str,
        room_id: &str,
        user_id: &str,
        duration_hours: Option<u64>,
    ) -> Result<()> {
        // Check multi-tier rate limiting for moderation actions
        let user_tier = self.server.determine_user_tier(sender_id).await;
        let user_ip = self.server.get_user_ip(sender_id).await.unwrap_or_else(|| {
            log::warn!("Could not get IP for user {}, using localhost fallback", sender_id);
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        });
        
        if !self.server.can_user_perform_operation(sender_id, user_ip, user_tier, OperationType::Moderation).await {
            let error_msg = ServerMessage::Error {
                code: "RATE_LIMITED".to_string(),
                message: "Moderation action rate limit exceeded. Please wait before performing another action.".to_string(),
            };
            let msg_str = serde_json::to_string(&error_msg).unwrap();
            self.send_to_user_safe(sender_id, &msg_str, "rate limit error").await;
            return Err(RustySocksError::Forbidden);
        }
        // Check if sender has permission to ban users
        match self.server.can_user_moderate(sender_id, room_id, crate::auth::user::Permission::BanUsers).await {
            Ok(true) => {
                // Has permission, proceed
            }
            Ok(false) => {
                let error_msg = ServerMessage::Error {
                    code: "FORBIDDEN".to_string(),
                    message: "You don't have permission to ban users in this room".to_string(),
                };
                let msg_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                return Err(RustySocksError::Forbidden);
            }
            Err(e) => {
                let error_msg = ServerMessage::Error {
                    code: "PERMISSION_CHECK_FAILED".to_string(),
                    message: format!("Failed to check permissions: {}", e),
                };
                let msg_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                return Err(e);
            }
        }
        
        // Ban the user
        match self.server.ban_user(sender_id, room_id, user_id, duration_hours).await {
            Ok(_) => {
                let ban_type = if duration_hours.is_some() {
                    format!("for {} hours", duration_hours.unwrap())
                } else {
                    "permanently".to_string()
                };
                
                let success_msg = ServerMessage::Success {
                    message: format!("User {} banned {} from room {}", user_id, ban_type, room_id),
                    data: Some(serde_json::json!({
                        "user_id": user_id,
                        "room_id": room_id,
                        "duration_hours": duration_hours
                    })),
                };
                let msg_str = serde_json::to_string(&success_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                
                // Notify the banned user if they're online
                let ban_notification = ServerMessage::Error {
                    code: "BANNED".to_string(),
                    message: format!("You have been banned from room {} {}", room_id, ban_type),
                };
                let notification_str = serde_json::to_string(&ban_notification).unwrap();
                self.send_to_user_safe(user_id, &notification_str, "notification").await;
                
                Ok(())
            }
            Err(e) => {
                let error_msg = ServerMessage::Error {
                    code: "BAN_FAILED".to_string(),
                    message: format!("Failed to ban user: {}", e),
                };
                let msg_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                Err(e)
            }
        }
    }

    /// Handle kick user request
    async fn handle_kick_user(&self, sender_id: &str, room_id: &str, user_id: &str) -> Result<()> {
        // Check multi-tier rate limiting for moderation actions
        let user_tier = self.server.determine_user_tier(sender_id).await;
        let user_ip = self.server.get_user_ip(sender_id).await.unwrap_or_else(|| {
            log::warn!("Could not get IP for user {}, using localhost fallback", sender_id);
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        });
        
        if !self.server.can_user_perform_operation(sender_id, user_ip, user_tier, OperationType::Moderation).await {
            let error_msg = ServerMessage::Error {
                code: "RATE_LIMITED".to_string(),
                message: "Moderation action rate limit exceeded. Please wait before performing another action.".to_string(),
            };
            let msg_str = serde_json::to_string(&error_msg).unwrap();
            self.send_to_user_safe(sender_id, &msg_str, "rate limit error").await;
            return Err(RustySocksError::Forbidden);
        }
        // Check if sender has permission to kick users
        match self.server.can_user_moderate(sender_id, room_id, crate::auth::user::Permission::KickUsers).await {
            Ok(true) => {
                // Has permission, proceed
            }
            Ok(false) => {
                let error_msg = ServerMessage::Error {
                    code: "FORBIDDEN".to_string(),
                    message: "You don't have permission to kick users from this room".to_string(),
                };
                let msg_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                return Err(RustySocksError::Forbidden);
            }
            Err(e) => {
                let error_msg = ServerMessage::Error {
                    code: "PERMISSION_CHECK_FAILED".to_string(),
                    message: format!("Failed to check permissions: {}", e),
                };
                let msg_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                return Err(e);
            }
        }
        
        // Kick the user
        match self.server.kick_user(sender_id, room_id, user_id).await {
            Ok(_) => {
                let success_msg = ServerMessage::Success {
                    message: format!("User {} kicked from room {}", user_id, room_id),
                    data: Some(serde_json::json!({
                        "user_id": user_id,
                        "room_id": room_id
                    })),
                };
                let msg_str = serde_json::to_string(&success_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                
                // Notify the kicked user if they're online
                let kick_notification = ServerMessage::Error {
                    code: "KICKED".to_string(),
                    message: format!("You have been kicked from room {}", room_id),
                };
                let notification_str = serde_json::to_string(&kick_notification).unwrap();
                self.send_to_user_safe(user_id, &notification_str, "notification").await;
                
                Ok(())
            }
            Err(e) => {
                let error_msg = ServerMessage::Error {
                    code: "KICK_FAILED".to_string(),
                    message: format!("Failed to kick user: {}", e),
                };
                let msg_str = serde_json::to_string(&error_msg).unwrap();
                self.send_to_user_safe(sender_id, &msg_str, "success message").await;
                Err(e)
            }
        }
    }
}
