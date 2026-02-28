//! Trading client example
//! 
//! This example demonstrates how to use rusty-socks for financial applications
//! including real-time market data, order management, and portfolio tracking.

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[derive(Debug, Clone)]
struct Portfolio {
    cash: f64,
    positions: HashMap<String, Position>,
    pending_orders: HashMap<String, Order>,
}

#[derive(Debug, Clone)]
struct Position {
    symbol: String,
    quantity: i64,
    average_price: f64,
    market_value: f64,
}

#[derive(Debug, Clone)]
struct Order {
    id: String,
    symbol: String,
    side: OrderSide,
    quantity: i64,
    price: f64,
    order_type: OrderType,
    status: OrderStatus,
}

#[derive(Debug, Clone)]
enum OrderSide {
    Buy,
    Sell,
}

#[derive(Debug, Clone)]
enum OrderType {
    Market,
    Limit,
    Stop,
}

#[derive(Debug, Clone)]
enum OrderStatus {
    Pending,
    Filled,
    Cancelled,
    PartiallyFilled,
}

#[derive(Debug, Clone)]
struct MarketData {
    symbol: String,
    price: f64,
    bid: f64,
    ask: f64,
    volume: u64,
    timestamp: chrono::DateTime<chrono::Utc>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    println!("📈 Rusty Socks Trading Client Example");
    println!("This example shows how to build a trading platform with real-time market data");
    
    // Initialize portfolio
    let mut portfolio = Portfolio {
        cash: 100000.0, // Start with $100k
        positions: HashMap::new(),
        pending_orders: HashMap::new(),
    };
    
    // Track market data
    let mut market_data: HashMap<String, MarketData> = HashMap::new();
    
    // Symbols we're interested in
    let symbols = vec!["AAPL", "GOOGL", "MSFT", "TSLA", "BTC-USD"];
    
    // Try to connect to WebSocket server
    if let Ok((ws_stream, _)) = connect_async("ws://127.0.0.1:8080/ws").await {
        println!("✅ Connected to trading server");
        
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        
        // Spawn task to forward channel messages to the WebSocket
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if ws_sender.send(msg).await.is_err() {
                    break;
                }
            }
        });
        
        // Join trading floor room
        let join_msg = json!({
            "type": "join_room",
            "room_id": "trading_floor"
        });
        let _ = tx.send(Message::Text(join_msg.to_string()));
        
        // Subscribe to market data for all symbols
        for symbol in &symbols {
            let subscribe_msg = json!({
                "type": "subscribe_ticker",
                "symbol": symbol
            });
            let _ = tx.send(Message::Text(subscribe_msg.to_string()));
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        // Start market data simulation
        let tx_market = tx.clone();
        tokio::spawn(async move {
            simulate_market_data(tx_market, symbols).await;
        });
        
        // Start trading strategy
        let tx_strategy = tx.clone();
        tokio::spawn(async move {
            simple_trading_strategy(tx_strategy).await;
        });
        
        // Handle incoming messages
        while let Some(ws_message) = ws_receiver.next().await {
            match ws_message {
                Ok(Message::Text(text)) => {
                    if let Ok(msg) = serde_json::from_str::<Value>(&text) {
                        handle_trading_message(&msg, &mut portfolio, &mut market_data).await;
                    }
                }
                Ok(Message::Close(_)) => {
                    println!("🔌 Trading connection closed");
                    break;
                }
                Err(e) => {
                    println!("❌ WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    } else {
        println!("❌ Could not connect to server, running in simulation mode");
        
        // Run simulation without server
        simulate_trading_session(&mut portfolio, &mut market_data).await;
    }
    
    // Print final portfolio state
    print_portfolio_summary(&portfolio);
    
    Ok(())
}

async fn simulate_market_data(
    tx: mpsc::UnboundedSender<Message>,
    symbols: Vec<&str>,
) {
    let mut interval = interval(Duration::from_secs(2));
    let mut prices: HashMap<String, f64> = HashMap::new();
    
    // Initialize prices
    for symbol in &symbols {
        let initial_price = match *symbol {
            "AAPL" => 150.0,
            "GOOGL" => 2500.0,
            "MSFT" => 300.0,
            "TSLA" => 800.0,
            "BTC-USD" => 45000.0,
            _ => 100.0,
        };
        prices.insert(symbol.to_string(), initial_price);
    }
    
    for _ in 0..30 { // Run for 30 cycles
        interval.tick().await;
        
        for symbol in &symbols {
            if let Some(current_price) = prices.get_mut(*symbol) {
                // Simulate price movement (±2% random walk)
                let change_percent = (rand::random::<f64>() - 0.5) * 0.04;
                *current_price *= 1.0 + change_percent;
                
                let market_update = json!({
                    "type": "market_data",
                    "symbol": symbol,
                    "price": *current_price,
                    "bid": *current_price * 0.999,
                    "ask": *current_price * 1.001,
                    "volume": rand::random::<u32>() % 1000000,
                    "timestamp": chrono::Utc::now().to_rfc3339()
                });
                
                let _ = tx.send(Message::Text(market_update.to_string()));
            }
        }
    }
}

async fn simple_trading_strategy(tx: mpsc::UnboundedSender<Message>) {
    let mut interval = interval(Duration::from_secs(10));
    
    let strategies = vec![
        ("AAPL", 145.0, 155.0), // Buy below 145, sell above 155
        ("GOOGL", 2400.0, 2600.0),
        ("MSFT", 290.0, 310.0),
    ];
    
    for _ in 0..6 { // Execute 6 trading decisions
        interval.tick().await;
        
        for (symbol, buy_threshold, sell_threshold) in &strategies {
            // Simulate strategy decision
            let action = if rand::random::<f64>() > 0.5 { "buy" } else { "sell" };
            let price = if action == "buy" { *buy_threshold } else { *sell_threshold };
            
            let order_msg = json!({
                "type": "place_order",
                "symbol": symbol,
                "side": action,
                "quantity": 100,
                "price": price,
                "order_type": "limit"
            });
            
            let _ = tx.send(Message::Text(order_msg.to_string()));
            println!("📊 Strategy: Placed {} order for {} @ ${:.2}", action, symbol, price);
        }
    }
}

async fn handle_trading_message(
    msg: &Value,
    portfolio: &mut Portfolio,
    market_data: &mut HashMap<String, MarketData>
) {
    match msg.get("type").and_then(|t| t.as_str()) {
        Some("market_data") => {
            if let (Some(symbol), Some(price)) = (
                msg.get("symbol").and_then(|s| s.as_str()),
                msg.get("price").and_then(|p| p.as_f64())
            ) {
                let data = MarketData {
                    symbol: symbol.to_string(),
                    price,
                    bid: msg.get("bid").and_then(|b| b.as_f64()).unwrap_or(price * 0.999),
                    ask: msg.get("ask").and_then(|a| a.as_f64()).unwrap_or(price * 1.001),
                    volume: msg.get("volume").and_then(|v| v.as_u64()).unwrap_or(0),
                    timestamp: chrono::Utc::now(),
                };
                
                market_data.insert(symbol.to_string(), data.clone());
                println!("📈 {}: ${:.2} (Vol: {})", symbol, price, data.volume);
                
                // Update portfolio market values
                if let Some(position) = portfolio.positions.get_mut(symbol) {
                    position.market_value = position.quantity as f64 * price;
                }
            }
        }
        
        Some("order_placed") => {
            if let Some(order_id) = msg.get("order_id").and_then(|id| id.as_str()) {
                let symbol = msg.get("symbol").and_then(|s| s.as_str()).unwrap_or("UNKNOWN");
                let status = msg.get("status").and_then(|s| s.as_str()).unwrap_or("unknown");
                println!("📋 Order {} placed for {} - Status: {}", order_id, symbol, status);
            }
        }
        
        Some("order_filled") => {
            if let (Some(symbol), Some(quantity), Some(price)) = (
                msg.get("symbol").and_then(|s| s.as_str()),
                msg.get("quantity").and_then(|q| q.as_i64()),
                msg.get("price").and_then(|p| p.as_f64())
            ) {
                let side = msg.get("side").and_then(|s| s.as_str()).unwrap_or("unknown");
                
                // Update portfolio
                if side == "buy" {
                    portfolio.cash -= quantity as f64 * price;
                    let position = portfolio.positions.entry(symbol.to_string()).or_insert(Position {
                        symbol: symbol.to_string(),
                        quantity: 0,
                        average_price: 0.0,
                        market_value: 0.0,
                    });
                    
                    let total_cost = position.quantity as f64 * position.average_price + quantity as f64 * price;
                    position.quantity += quantity;
                    position.average_price = total_cost / position.quantity as f64;
                    position.market_value = position.quantity as f64 * price;
                } else if side == "sell" {
                    portfolio.cash += quantity as f64 * price;
                    if let Some(position) = portfolio.positions.get_mut(symbol) {
                        position.quantity -= quantity;
                        position.market_value = position.quantity as f64 * price;
                        
                        if position.quantity <= 0 {
                            portfolio.positions.remove(symbol);
                        }
                    }
                }
                
                println!("✅ {} {} shares of {} @ ${:.2}", side.to_uppercase(), quantity, symbol, price);
            }
        }
        
        Some("subscription_confirmed") => {
            let symbol = msg.get("symbol").and_then(|s| s.as_str()).unwrap_or("UNKNOWN");
            println!("📡 Subscribed to market data for {}", symbol);
        }
        
        Some("new_order") => {
            let user = msg.get("user").and_then(|u| u.as_str()).unwrap_or("unknown");
            let symbol = msg.get("symbol").and_then(|s| s.as_str()).unwrap_or("UNKNOWN");
            let quantity = msg.get("quantity").and_then(|q| q.as_i64()).unwrap_or(0);
            println!("📢 Trading Floor: {} placed order for {} shares of {}", user, quantity, symbol);
        }
        
        Some("error") => {
            let message = msg.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error");
            println!("❌ Error: {}", message);
        }
        
        _ => {
            println!("📨 Trading message: {}", msg);
        }
    }
}

async fn simulate_trading_session(
    portfolio: &mut Portfolio,
    market_data: &mut HashMap<String, MarketData>
) {
    println!("🎯 Running trading simulation...");
    
    // Simulate some market data and trades
    let symbols = vec!["AAPL", "GOOGL", "MSFT"];
    
    for symbol in symbols {
        let price = 150.0 + rand::random::<f64>() * 100.0;
        
        market_data.insert(symbol.to_string(), MarketData {
            symbol: symbol.to_string(),
            price,
            bid: price * 0.999,
            ask: price * 1.001,
            volume: 1000000,
            timestamp: chrono::Utc::now(),
        });
        
        // Simulate buying some shares
        let quantity = 100;
        portfolio.cash -= quantity as f64 * price;
        portfolio.positions.insert(symbol.to_string(), Position {
            symbol: symbol.to_string(),
            quantity,
            average_price: price,
            market_value: quantity as f64 * price,
        });
        
        println!("📈 Simulated: Bought {} shares of {} @ ${:.2}", quantity, symbol, price);
        
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn print_portfolio_summary(portfolio: &Portfolio) {
    println!("\n💼 Portfolio Summary");
    println!("==================");
    println!("Cash: ${:.2}", portfolio.cash);
    
    let mut total_value = portfolio.cash;
    
    if !portfolio.positions.is_empty() {
        println!("\nPositions:");
        for (symbol, position) in &portfolio.positions {
            let unrealized_pnl = position.market_value - (position.quantity as f64 * position.average_price);
            total_value += position.market_value;
            
            println!("  {} - {} shares @ ${:.2} avg | Market Value: ${:.2} | P&L: ${:.2}",
                    symbol,
                    position.quantity,
                    position.average_price,
                    position.market_value,
                    unrealized_pnl);
        }
    }
    
    println!("\nTotal Portfolio Value: ${:.2}", total_value);
    println!("Initial Value: $100,000.00");
    println!("Total Return: ${:.2} ({:.2}%)", total_value - 100000.0, (total_value - 100000.0) / 1000.0);
}