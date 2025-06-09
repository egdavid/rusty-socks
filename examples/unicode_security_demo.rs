//! Demonstration of Unicode security validation
//! 
//! This example shows how the Unicode security validator protects against
//! various Unicode-based attacks that could be used in chat messages.

use rusty_socks::security::{UnicodeSecurityValidator, UnicodeSecurityConfig};

fn main() {
    println!("🔒 Unicode Security Validation Demo");
    println!("===================================\n");

    let validator = UnicodeSecurityValidator::new();

    // Test cases with different types of attacks
    let test_cases = vec![
        ("Valid ASCII", "Hello, world!"),
        ("Valid Unicode", "Bonjour le monde! 🌍"),
        ("Bidirectional Attack", "admin\u{202E}nima"), // Contains RLO (Right-to-Left Override)
        ("Invisible Characters", "Hello\u{200B}world"), // Contains Zero-Width Space
        ("Homograph Attack", "pаypal.com"), // Contains Cyrillic 'а' that looks like Latin 'a'
        ("Control Characters", "Hello\u{202A}world"), // Contains LRE (Left-to-Right Embedding)
        ("Mixed Scripts", "googleа.com"), // Latin + Cyrillic mixing
        ("Private Use", "Hello\u{E000}world"), // Private Use Area character
    ];

    for (test_name, test_input) in test_cases {
        println!("🧪 Testing: {}", test_name);
        println!("   Input: {:?}", test_input);
        
        match validator.validate(test_input) {
            Ok(safe_content) => {
                println!("   ✅ SAFE: {:?}", safe_content);
                if safe_content != test_input {
                    println!("   📝 Note: Content was normalized during validation");
                }
            }
            Err(error) => {
                println!("   ❌ BLOCKED: {:?}", error);
            }
        }
        println!();
    }

    // Demo with custom configuration
    println!("🔧 Custom Configuration Demo");
    println!("=============================\n");

    let mut custom_config = UnicodeSecurityConfig::default();
    custom_config.allow_bidirectional = true; // Allow BiDi text
    custom_config.max_normalized_length = 100; // Shorter limit
    
    let custom_validator = UnicodeSecurityValidator::with_config(custom_config);
    
    let bidi_text = "admin\u{202E}nima";
    println!("🧪 Testing BiDi text with permissive config:");
    println!("   Input: {:?}", bidi_text);
    
    match custom_validator.validate(bidi_text) {
        Ok(safe_content) => {
            println!("   ✅ ALLOWED: {:?}", safe_content);
        }
        Err(error) => {
            println!("   ❌ BLOCKED: {:?}", error);
        }
    }

    println!("\n🛡️  Unicode security validation helps protect against:");
    println!("   • Homograph attacks (lookalike characters)");
    println!("   • Bidirectional text spoofing");
    println!("   • Invisible character injection");
    println!("   • Control character abuse");
    println!("   • Mixed script confusion");
    println!("   • Unicode normalization attacks");
    println!("   • Private use area exploitation");
}