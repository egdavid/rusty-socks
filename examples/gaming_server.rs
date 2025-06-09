//! Gaming server example
//! 
//! This example demonstrates how to use rusty-socks for gaming applications
//! with lobbies, matchmaking, and real-time game state synchronization.

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use tokio::time::{Duration, interval};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use uuid::Uuid;

#[derive(Debug, Clone)]
struct GameLobby {
    id: String,
    name: String,
    host: String,
    players: Vec<String>,
    max_players: usize,
    game_type: String,
    status: LobbyStatus,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, PartialEq)]
enum LobbyStatus {
    Waiting,
    Starting,
    InProgress,
    Finished,
}

#[derive(Debug, Clone)]
struct Player {
    id: String,
    username: String,
    current_lobby: Option<String>,
    ready: bool,
}

type SharedGameState = Arc<RwLock<GameState>>;

#[derive(Debug)]
struct GameState {
    lobbies: HashMap<String, GameLobby>,
    players: HashMap<String, Player>,
    active_games: HashMap<String, GameSession>,
}

#[derive(Debug, Clone)]
struct GameSession {
    id: String,
    lobby_id: String,
    players: Vec<String>,
    game_data: HashMap<String, Value>,
    started_at: chrono::DateTime<chrono::Utc>,
}

async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    println!("🎮 Rusty Socks Gaming Server Example");
    println!("This example shows how to build a gaming platform with lobbies and matchmaking");
    
    let game_state = Arc::new(RwLock::new(GameState {
        lobbies: HashMap::new(),
        players: HashMap::new(),
        active_games: HashMap::new(),
    }));
    
    // Start the matchmaking service
    let matchmaking_state = game_state.clone();
    tokio::spawn(async move {
        matchmaking_service(matchmaking_state).await;
    });
    
    // Start the game state update service
    let update_state = game_state.clone();
    tokio::spawn(async move {
        game_update_service(update_state).await;
    });
    
    // Simulate some game clients
    let mut handles = Vec::new();
    
    for i in 1..=5 {
        let state = game_state.clone();
        let handle = tokio::spawn(async move {
            simulate_player(format!("Player{}", i), state).await;
        });
        handles.push(handle);
    }
    
    // Let the simulation run for a while
    tokio::time::sleep(Duration::from_secs(30)).await;
    
    println!("🎮 Gaming simulation completed!");
    
    // Wait for all players to finish
    for handle in handles {
        let _ = handle.await;
    }
    
    Ok(())
}

async fn simulate_player(username: String, game_state: SharedGameState) {
    println!("🎮 {} joining the gaming server", username);
    
    // Connect to WebSocket server (you'd replace this with actual connection)
    if let Ok((ws_stream, _)) = connect_async("ws://127.0.0.1:8080/ws").await {
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();
        
        // Register as a player
        let player_id = Uuid::new_v4().to_string();
        {
            let mut state = game_state.write().await;
            state.players.insert(player_id.clone(), Player {
                id: player_id.clone(),
                username: username.clone(),
                current_lobby: None,
                ready: false,
            });
        }
        
        // Send initial gaming messages
        let gaming_messages = vec![
            json!({
                "type": "lobby_create",
                "name": format!("{}'s Lobby", username),
                "max_players": 4,
                "game_type": "FPS"
            }),
            json!({
                "type": "game_invite",
                "target_user": "Player2",
                "game_type": "Strategy"
            }),
        ];
        
        for msg in gaming_messages {
            if let Err(e) = ws_sender.send(Message::Text(msg.to_string())).await {
                println!("❌ {} failed to send message: {}", username, e);
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        
        // Listen for responses
        let mut message_count = 0;
        while let Some(ws_message) = ws_receiver.next().await {
            message_count += 1;
            if message_count > 10 { // Limit messages per player
                break;
            }
            
            match ws_message {
                Ok(Message::Text(text)) => {
                    if let Ok(msg) = serde_json::from_str::<Value>(&text) {
                        handle_gaming_message(&username, &msg).await;
                    }
                }
                Ok(Message::Close(_)) => break,
                Err(e) => {
                    println!("❌ {} WebSocket error: {}", username, e);
                    break;
                }
                _ => {}
            }
        }
        
        println!("🎮 {} finished gaming session", username);
    } else {
        // Simulate without actual WebSocket connection
        println!("🎮 {} simulating gaming actions (no server connection)", username);
        
        let player_id = Uuid::new_v4().to_string();
        {
            let mut state = game_state.write().await;
            state.players.insert(player_id.clone(), Player {
                id: player_id.clone(),
                username: username.clone(),
                current_lobby: None,
                ready: false,
            });
        }
        
        // Simulate creating a lobby
        let lobby_id = Uuid::new_v4().to_string();
        {
            let mut state = game_state.write().await;
            let lobby = GameLobby {
                id: lobby_id.clone(),
                name: format!("{}'s Lobby", username),
                host: player_id.clone(),
                players: vec![player_id.clone()],
                max_players: 4,
                game_type: "FPS".to_string(),
                status: LobbyStatus::Waiting,
                created_at: chrono::Utc::now(),
            };
            state.lobbies.insert(lobby_id.clone(), lobby);
            
            if let Some(player) = state.players.get_mut(&player_id) {
                player.current_lobby = Some(lobby_id.clone());
            }
        }
        
        println!("🎮 {} created lobby: {}", username, lobby_id);
        
        // Wait a bit then mark as ready
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        {
            let mut state = game_state.write().await;
            if let Some(player) = state.players.get_mut(&player_id) {
                player.ready = true;
                println!("🎮 {} is ready to play!", username);
            }
        }
    }
}

async fn handle_gaming_message(username: &str, msg: &Value) {
    match msg.get("type").and_then(|t| t.as_str()) {
        Some("lobby_created") => {
            let lobby_id = msg.get("lobby_id").and_then(|id| id.as_str()).unwrap_or("unknown");
            let name = msg.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
            println!("🏠 {}: Created lobby '{}' ({})", username, name, lobby_id);
        }
        
        Some("game_invitation") => {
            let from_user = msg.get("from_username").and_then(|u| u.as_str()).unwrap_or("unknown");
            let game_type = msg.get("game_type").and_then(|t| t.as_str()).unwrap_or("unknown");
            println!("📧 {}: Received game invitation from {} for {}", username, from_user, game_type);
        }
        
        Some("game_started") => {
            let game_id = msg.get("game_id").and_then(|id| id.as_str()).unwrap_or("unknown");
            println!("🎯 {}: Game started! ({})", username, game_id);
        }
        
        Some("error") => {
            let message = msg.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error");
            println!("❌ {}: Error - {}", username, message);
        }
        
        _ => {
            println!("📨 {}: {}", username, msg);
        }
    }
}

async fn matchmaking_service(game_state: SharedGameState) {
    println!("🔍 Starting matchmaking service");
    let mut interval = interval(Duration::from_secs(5));
    
    loop {
        interval.tick().await;
        
        let mut state = game_state.write().await;
        let mut lobbies_to_start = Vec::new();
        
        // Check lobbies that are ready to start
        for (lobby_id, lobby) in state.lobbies.iter_mut() {
            if lobby.status == LobbyStatus::Waiting && lobby.players.len() >= 2 {
                // Check if all players are ready
                let all_ready = lobby.players.iter().all(|player_id| {
                    state.players.get(player_id)
                        .map_or(false, |p| p.ready)
                });
                
                if all_ready {
                    lobby.status = LobbyStatus::Starting;
                    lobbies_to_start.push(lobby_id.clone());
                }
            }
        }
        
        // Start games for ready lobbies
        for lobby_id in lobbies_to_start {
            if let Some(lobby) = state.lobbies.get(&lobby_id) {
                let game_id = Uuid::new_v4().to_string();
                let game_session = GameSession {
                    id: game_id.clone(),
                    lobby_id: lobby_id.clone(),
                    players: lobby.players.clone(),
                    game_data: HashMap::new(),
                    started_at: chrono::Utc::now(),
                };
                
                state.active_games.insert(game_id.clone(), game_session);
                
                if let Some(lobby) = state.lobbies.get_mut(&lobby_id) {
                    lobby.status = LobbyStatus::InProgress;
                }
                
                println!("🎯 Matchmaking: Started game {} for lobby {}", game_id, lobby_id);
            }
        }
        
        // Clean up old lobbies and games
        let now = chrono::Utc::now();
        state.lobbies.retain(|_, lobby| {
            let age = now.signed_duration_since(lobby.created_at);
            age.num_minutes() < 30 // Remove lobbies older than 30 minutes
        });
        
        // Print current state
        println!("🔍 Matchmaking: {} lobbies, {} active games, {} players", 
               state.lobbies.len(), 
               state.active_games.len(), 
               state.players.len());
    }
}

async fn game_update_service(game_state: SharedGameState) {
    println!("🎮 Starting game update service");
    let mut interval = interval(Duration::from_secs(1));
    
    loop {
        interval.tick().await;
        
        let mut state = game_state.write().await;
        let mut games_to_finish = Vec::new();
        
        // Update active games
        for (game_id, game) in state.active_games.iter_mut() {
            let age = chrono::Utc::now().signed_duration_since(game.started_at);
            
            // Simulate game progression
            if age.num_seconds() % 5 == 0 {
                let score = rand::random::<u32>() % 100;
                game.game_data.insert("latest_score".to_string(), json!(score));
                
                // Broadcast game update to players (in real implementation)
                println!("🎮 Game {}: Score update - {}", game_id, score);
            }
            
            // End games after 20 seconds
            if age.num_seconds() > 20 {
                games_to_finish.push(game_id.clone());
            }
        }
        
        // Finish completed games
        for game_id in games_to_finish {
            if let Some(game) = state.active_games.remove(&game_id) {
                // Update lobby status
                if let Some(lobby) = state.lobbies.get_mut(&game.lobby_id) {
                    lobby.status = LobbyStatus::Finished;
                }
                
                // Reset player states
                for player_id in &game.players {
                    if let Some(player) = state.players.get_mut(player_id) {
                        player.current_lobby = None;
                        player.ready = false;
                    }
                }
                
                println!("🏁 Game {} finished! Players returned to matchmaking pool", game_id);
            }
        }
    }
}