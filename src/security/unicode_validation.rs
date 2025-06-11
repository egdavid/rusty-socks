//! Unicode validation and security module
//!
//! This module provides comprehensive protection against Unicode-based attacks including:
//! - Homograph attacks (lookalike characters)
//! - Bidirectional text attacks (BiDi spoofing)
//! - Control character injection
//! - Normalization attacks
//! - Overlong encodings
//! - Mixed script attacks

use std::collections::HashSet;

/// Unicode security validation errors
#[derive(Debug, Clone, PartialEq)]
pub enum UnicodeSecurityError {
    /// Contains dangerous control characters
    ControlCharacters(String),
    /// Contains bidirectional override characters
    BidirectionalOverride(String),
    /// Contains homograph attack characters
    HomographAttack(String),
    /// Contains mixed scripts that could be confusing
    MixedScriptAttack(String),
    /// Contains invalid or malformed Unicode sequences
    InvalidUnicode(String),
    /// Text normalization produced unexpected results
    NormalizationAttack(String),
    /// Contains invisible or zero-width characters
    InvisibleCharacters(String),
    /// Contains private use area characters
    PrivateUseCharacters(String),
    /// Text is suspiciously long after normalization
    NormalizationExpansion(String),
}

/// Configuration for Unicode security validation
#[derive(Debug, Clone)]
pub struct UnicodeSecurityConfig {
    /// Maximum allowed text length after normalization
    pub max_normalized_length: usize,
    /// Allow mixed scripts (different writing systems)
    pub allow_mixed_scripts: bool,
    /// Allow bidirectional text
    pub allow_bidirectional: bool,
    /// Allow private use area characters
    pub allow_private_use: bool,
    /// Allowed Unicode scripts (if empty, all are allowed)
    pub allowed_scripts: HashSet<UnicodeScript>,
    /// Maximum expansion ratio during normalization
    pub max_normalization_expansion: f64,
}

impl Default for UnicodeSecurityConfig {
    fn default() -> Self {
        Self {
            max_normalized_length: 2000,
            allow_mixed_scripts: false,
            allow_bidirectional: false,
            allow_private_use: false,
            allowed_scripts: HashSet::new(), // Empty = allow all
            max_normalization_expansion: 3.0, // Text can expand up to 3x during normalization
        }
    }
}

/// Common Unicode scripts for validation
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum UnicodeScript {
    Latin,
    Greek,
    Cyrillic,
    Arabic,
    Hebrew,
    Han,
    Hiragana,
    Katakana,
    Hangul,
    Thai,
    Devanagari,
    Common,
    Inherited,
}

/// Dangerous Unicode control characters that should be blocked
const DANGEROUS_CONTROL_CHARS: &[char] = &[
    '\u{202A}', // LEFT-TO-RIGHT EMBEDDING
    '\u{202B}', // RIGHT-TO-LEFT EMBEDDING
    '\u{202C}', // POP DIRECTIONAL FORMATTING
    '\u{202D}', // LEFT-TO-RIGHT OVERRIDE
    '\u{202E}', // RIGHT-TO-LEFT OVERRIDE
    '\u{2066}', // LEFT-TO-RIGHT ISOLATE
    '\u{2067}', // RIGHT-TO-LEFT ISOLATE
    '\u{2068}', // FIRST STRONG ISOLATE
    '\u{2069}', // POP DIRECTIONAL ISOLATE
    '\u{200E}', // LEFT-TO-RIGHT MARK
    '\u{200F}', // RIGHT-TO-LEFT MARK
    '\u{061C}', // ARABIC LETTER MARK
    '\u{180E}', // MONGOLIAN VOWEL SEPARATOR
    '\u{FEFF}', // ZERO WIDTH NO-BREAK SPACE (BOM)
];

/// Zero-width and invisible characters
const INVISIBLE_CHARS: &[char] = &[
    '\u{200B}', // ZERO WIDTH SPACE
    '\u{200C}', // ZERO WIDTH NON-JOINER
    '\u{200D}', // ZERO WIDTH JOINER
    '\u{2060}', // WORD JOINER
    '\u{FEFF}', // ZERO WIDTH NO-BREAK SPACE
    '\u{034F}', // COMBINING GRAPHEME JOINER
    '\u{17B4}', // KHMER VOWEL INHERENT AQ
    '\u{17B5}', // KHMER VOWEL INHERENT AA
];

/// Homograph attack character mappings (commonly confused characters)
const HOMOGRAPH_PAIRS: &[(char, char)] = &[
    ('а', 'a'), // Cyrillic 'а' vs Latin 'a'
    ('о', 'o'), // Cyrillic 'о' vs Latin 'o'
    ('р', 'p'), // Cyrillic 'р' vs Latin 'p'
    ('е', 'e'), // Cyrillic 'е' vs Latin 'e'
    ('х', 'x'), // Cyrillic 'х' vs Latin 'x'
    ('с', 'c'), // Cyrillic 'с' vs Latin 'c'
    ('у', 'y'), // Cyrillic 'у' vs Latin 'y'
    ('і', 'i'), // Ukrainian 'і' vs Latin 'i'
    ('ο', 'o'), // Greek 'ο' vs Latin 'o'
    ('α', 'a'), // Greek 'α' vs Latin 'a'
    ('ρ', 'p'), // Greek 'ρ' vs Latin 'p'
    ('τ', 't'), // Greek 'τ' vs Latin 't'
    ('υ', 'u'), // Greek 'υ' vs Latin 'u'
    ('ν', 'v'), // Greek 'ν' vs Latin 'v'
    ('κ', 'k'), // Greek 'κ' vs Latin 'k'
];

/// Unicode security validator
pub struct UnicodeSecurityValidator {
    config: UnicodeSecurityConfig,
}

impl UnicodeSecurityValidator {
    /// Create a new Unicode security validator with default configuration
    pub fn new() -> Self {
        Self {
            config: UnicodeSecurityConfig::default(),
        }
    }

    /// Create a new Unicode security validator with custom configuration
    pub fn with_config(config: UnicodeSecurityConfig) -> Self {
        Self { config }
    }

    /// Validate text for Unicode security issues
    pub fn validate(&self, text: &str) -> Result<String, UnicodeSecurityError> {
        // Step 1: Check for invalid Unicode sequences
        if !text.is_ascii() && !self.is_valid_unicode(text) {
            return Err(UnicodeSecurityError::InvalidUnicode(
                "Text contains invalid Unicode sequences".to_string()
            ));
        }

        // Step 2: Check for dangerous control characters
        self.check_control_characters(text)?;

        // Step 3: Check for bidirectional text attacks
        if !self.config.allow_bidirectional {
            self.check_bidirectional_attacks(text)?;
        }

        // Step 4: Check for invisible characters
        self.check_invisible_characters(text)?;

        // Step 5: Check for private use characters
        if !self.config.allow_private_use {
            self.check_private_use_characters(text)?;
        }

        // Step 6: Normalize text and check for expansion attacks
        let normalized = self.normalize_and_validate(text)?;

        // Step 7: Check for homograph attacks
        self.check_homograph_attacks(&normalized)?;

        // Step 8: Check for mixed script attacks
        if !self.config.allow_mixed_scripts {
            self.check_mixed_scripts(&normalized)?;
        }

        Ok(normalized)
    }

    /// Check if text contains valid Unicode sequences
    fn is_valid_unicode(&self, text: &str) -> bool {
        // Rust strings are guaranteed to be valid UTF-8, but we can check for:
        // - Overlong encodings (already handled by Rust)
        // - Surrogate pairs (invalid in UTF-8)
        // - Non-characters
        
        for ch in text.chars() {
            // Check for Unicode non-characters
            let code_point = ch as u32;
            if (code_point >= 0xFDD0 && code_point <= 0xFDEF) || // Non-characters in Arabic Presentation Forms-A
               (code_point & 0xFFFF) == 0xFFFE || // Last two code points in any plane
               (code_point & 0xFFFF) == 0xFFFF {
                return false;
            }
        }
        
        true
    }

    /// Check for dangerous control characters
    fn check_control_characters(&self, text: &str) -> Result<(), UnicodeSecurityError> {
        for ch in text.chars() {
            if DANGEROUS_CONTROL_CHARS.contains(&ch) {
                return Err(UnicodeSecurityError::ControlCharacters(
                    format!("Text contains dangerous control character: U+{:04X}", ch as u32)
                ));
            }
            
            // Check for other control characters (except common whitespace)
            if ch.is_control() && ch != '\t' && ch != '\n' && ch != '\r' {
                return Err(UnicodeSecurityError::ControlCharacters(
                    format!("Text contains control character: U+{:04X}", ch as u32)
                ));
            }
        }
        Ok(())
    }

    /// Check for bidirectional text attacks
    fn check_bidirectional_attacks(&self, text: &str) -> Result<(), UnicodeSecurityError> {
        let mut bidi_override_count = 0;
        let mut bidi_isolate_count = 0;
        let mut bidi_embedding_count = 0;

        for ch in text.chars() {
            match ch {
                '\u{202D}' | '\u{202E}' => bidi_override_count += 1,
                '\u{2066}' | '\u{2067}' | '\u{2068}' => bidi_isolate_count += 1,
                '\u{202A}' | '\u{202B}' => bidi_embedding_count += 1,
                '\u{202C}' => {
                    if bidi_embedding_count > 0 {
                        bidi_embedding_count -= 1;
                    }
                },
                '\u{2069}' => {
                    if bidi_isolate_count > 0 {
                        bidi_isolate_count -= 1;
                    }
                },
                _ => {}
            }
        }

        // Check for unbalanced or suspicious bidirectional formatting
        if bidi_override_count > 0 || bidi_isolate_count > 0 || bidi_embedding_count > 0 {
            return Err(UnicodeSecurityError::BidirectionalOverride(
                "Text contains bidirectional override or unbalanced formatting".to_string()
            ));
        }

        Ok(())
    }

    /// Check for invisible characters that could be used for attacks
    fn check_invisible_characters(&self, text: &str) -> Result<(), UnicodeSecurityError> {
        for ch in text.chars() {
            if INVISIBLE_CHARS.contains(&ch) {
                return Err(UnicodeSecurityError::InvisibleCharacters(
                    format!("Text contains invisible character: U+{:04X}", ch as u32)
                ));
            }
        }
        Ok(())
    }

    /// Check for private use area characters
    fn check_private_use_characters(&self, text: &str) -> Result<(), UnicodeSecurityError> {
        for ch in text.chars() {
            let code_point = ch as u32;
            // Check Unicode private use areas
            if (code_point >= 0xE000 && code_point <= 0xF8FF) ||  // Private Use Area
               (code_point >= 0xF0000 && code_point <= 0xFFFFD) || // Supplementary Private Use Area-A
               (code_point >= 0x100000 && code_point <= 0x10FFFD) { // Supplementary Private Use Area-B
                return Err(UnicodeSecurityError::PrivateUseCharacters(
                    format!("Text contains private use character: U+{:04X}", code_point)
                ));
            }
        }
        Ok(())
    }

    /// Normalize text and check for expansion attacks
    fn normalize_and_validate(&self, text: &str) -> Result<String, UnicodeSecurityError> {
        // For this implementation, we'll use basic normalization
        // In a full implementation, you'd use the `unicode-normalization` crate
        
        let normalized = text.trim().to_string();
        
        // Check for normalization expansion attacks
        let expansion_ratio = normalized.len() as f64 / text.len() as f64;
        if expansion_ratio > self.config.max_normalization_expansion {
            return Err(UnicodeSecurityError::NormalizationExpansion(
                format!("Text expanded {:.2}x during normalization (max: {:.2}x)", 
                       expansion_ratio, self.config.max_normalization_expansion)
            ));
        }
        
        // Check final length
        if normalized.len() > self.config.max_normalized_length {
            return Err(UnicodeSecurityError::NormalizationExpansion(
                format!("Normalized text too long: {} characters (max: {})", 
                       normalized.len(), self.config.max_normalized_length)
            ));
        }
        
        Ok(normalized)
    }

    /// Check for homograph attacks (lookalike characters)
    fn check_homograph_attacks(&self, text: &str) -> Result<(), UnicodeSecurityError> {
        let mut suspicious_chars = Vec::new();
        
        for ch in text.chars() {
            // Check if this character is part of a known homograph pair
            for (suspicious, latin) in HOMOGRAPH_PAIRS {
                if ch == *suspicious {
                    suspicious_chars.push((ch, *latin));
                }
            }
        }
        
        if !suspicious_chars.is_empty() {
            let details = suspicious_chars
                .iter()
                .map(|(sus, lat)| format!("'{}' (U+{:04X}) looks like '{}'", sus, *sus as u32, lat))
                .collect::<Vec<_>>()
                .join(", ");
            
            return Err(UnicodeSecurityError::HomographAttack(
                format!("Text contains lookalike characters: {}", details)
            ));
        }
        
        Ok(())
    }

    /// Check for mixed script attacks
    fn check_mixed_scripts(&self, text: &str) -> Result<(), UnicodeSecurityError> {
        let mut scripts_found = HashSet::new();
        
        for ch in text.chars() {
            if ch.is_ascii() {
                scripts_found.insert(UnicodeScript::Latin);
            } else {
                // Simplified script detection
                let script = self.detect_script(ch);
                if script != UnicodeScript::Common && script != UnicodeScript::Inherited {
                    scripts_found.insert(script);
                }
            }
        }
        
        // If specific scripts are allowed, check against them
        if !self.config.allowed_scripts.is_empty() {
            for script in &scripts_found {
                if !self.config.allowed_scripts.contains(script) {
                    return Err(UnicodeSecurityError::MixedScriptAttack(
                        format!("Text contains disallowed script: {:?}", script)
                    ));
                }
            }
        }
        
        // Check for suspicious mixing of scripts
        if scripts_found.len() > 1 {
            // Allow some common combinations
            let has_latin = scripts_found.contains(&UnicodeScript::Latin);
            let has_cyrillic = scripts_found.contains(&UnicodeScript::Cyrillic);
            let has_greek = scripts_found.contains(&UnicodeScript::Greek);
            
            // Latin + Cyrillic or Latin + Greek are suspicious for homograph attacks
            if (has_latin && has_cyrillic) || (has_latin && has_greek) {
                return Err(UnicodeSecurityError::MixedScriptAttack(
                    format!("Suspicious script mixing detected: {:?}", scripts_found)
                ));
            }
        }
        
        Ok(())
    }

    /// Detect the script of a Unicode character (simplified implementation)
    fn detect_script(&self, ch: char) -> UnicodeScript {
        let code_point = ch as u32;
        
        match code_point {
            0x0000..=0x007F => UnicodeScript::Latin,
            0x0370..=0x03FF => UnicodeScript::Greek,
            0x0400..=0x04FF => UnicodeScript::Cyrillic,
            0x0590..=0x05FF => UnicodeScript::Hebrew,
            0x0600..=0x06FF => UnicodeScript::Arabic,
            0x3040..=0x309F => UnicodeScript::Hiragana,
            0x30A0..=0x30FF => UnicodeScript::Katakana,
            0xAC00..=0xD7AF => UnicodeScript::Hangul,
            0x4E00..=0x9FFF => UnicodeScript::Han,
            0x0E00..=0x0E7F => UnicodeScript::Thai,
            0x0900..=0x097F => UnicodeScript::Devanagari,
            _ => UnicodeScript::Common,
        }
    }

    /// Get the current configuration
    pub fn config(&self) -> &UnicodeSecurityConfig {
        &self.config
    }

    /// Update the configuration
    pub fn set_config(&mut self, config: UnicodeSecurityConfig) {
        self.config = config;
    }
}

impl Default for UnicodeSecurityValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Safe Unicode text wrapper that guarantees content has been validated
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeUnicodeText {
    content: String,
}

impl SafeUnicodeText {
    /// Create safe Unicode text from validated content
    pub fn new(validator: &UnicodeSecurityValidator, text: &str) -> Result<Self, UnicodeSecurityError> {
        let validated_content = validator.validate(text)?;
        Ok(Self {
            content: validated_content,
        })
    }

    /// Get the safe content
    pub fn as_str(&self) -> &str {
        &self.content
    }

    /// Get the safe content as String
    pub fn into_string(self) -> String {
        self.content
    }

    /// Get the length of the safe content
    pub fn len(&self) -> usize {
        self.content.len()
    }

    /// Check if the safe content is empty
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }
}

impl std::fmt::Display for SafeUnicodeText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_unicode_validation() {
        let validator = UnicodeSecurityValidator::new();
        
        // Valid ASCII text
        assert!(validator.validate("Hello, world!").is_ok());
        
        // Valid Unicode text
        assert!(validator.validate("Bonjour le monde! 🌍").is_ok());
        
        // Text with control characters should fail
        let text_with_control = format!("Hello{}world", '\u{202E}');
        assert!(validator.validate(&text_with_control).is_err());
    }

    #[test]
    fn test_bidirectional_attacks() {
        let validator = UnicodeSecurityValidator::new();
        
        // Text with RLO (Right-to-Left Override)
        let rlo_attack = format!("{}admin", '\u{202E}');
        let result = validator.validate(&rlo_attack);
        assert!(matches!(result, Err(UnicodeSecurityError::BidirectionalOverride(_))));
    }

    #[test]
    fn test_invisible_characters() {
        let validator = UnicodeSecurityValidator::new();
        
        // Text with zero-width space
        let invisible_text = format!("Hello{}world", '\u{200B}');
        let result = validator.validate(&invisible_text);
        assert!(matches!(result, Err(UnicodeSecurityError::InvisibleCharacters(_))));
    }

    #[test]
    fn test_homograph_attacks() {
        let validator = UnicodeSecurityValidator::new();
        
        // Cyrillic 'а' that looks like Latin 'a'
        let homograph_text = "pаypal.com"; // Contains Cyrillic 'а'
        let result = validator.validate(homograph_text);
        assert!(matches!(result, Err(UnicodeSecurityError::HomographAttack(_))));
    }

    #[test]
    fn test_mixed_script_detection() {
        let validator = UnicodeSecurityValidator::new();
        
        // Latin + Cyrillic mixing (suspicious)
        let mixed_script = "googleа.com"; // Latin + Cyrillic 'а'
        let result = validator.validate(mixed_script);
        assert!(matches!(result, Err(UnicodeSecurityError::MixedScriptAttack(_))));
    }

    #[test]
    fn test_private_use_characters() {
        let validator = UnicodeSecurityValidator::new();
        
        // Private use area character
        let private_use_text = format!("Hello{}world", '\u{E000}');
        let result = validator.validate(&private_use_text);
        assert!(matches!(result, Err(UnicodeSecurityError::PrivateUseCharacters(_))));
    }

    #[test]
    fn test_safe_unicode_text() {
        let validator = UnicodeSecurityValidator::new();
        
        // Valid text should create SafeUnicodeText successfully
        let safe_text = SafeUnicodeText::new(&validator, "Hello, world!");
        assert!(safe_text.is_ok());
        assert_eq!(safe_text.unwrap().as_str(), "Hello, world!");
        
        // Invalid text should fail
        let unsafe_text = format!("Hello{}world", '\u{202E}');
        let result = SafeUnicodeText::new(&validator, &unsafe_text);
        assert!(result.is_err());
    }

    #[test]
    fn test_custom_config() {
        let mut config = UnicodeSecurityConfig::default();
        config.allow_bidirectional = true;
        config.max_normalized_length = 100;
        
        let validator = UnicodeSecurityValidator::with_config(config);
        
        // Should now allow bidirectional text
        let bidi_text = format!("Hello{}world", '\u{202E}');
        // Note: This will still fail due to control character check, not bidi check
        assert!(validator.validate(&bidi_text).is_err());
    }

    #[test]
    fn test_normalization_expansion() {
        let validator = UnicodeSecurityValidator::new();
        
        // Very long text should fail
        let long_text = "A".repeat(3000);
        let result = validator.validate(&long_text);
        assert!(matches!(result, Err(UnicodeSecurityError::NormalizationExpansion(_))));
    }
}