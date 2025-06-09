# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Production-ready security implementation
- Comprehensive audit fixes and improvements

## [0.1.0] - 2025-01-XX

### Added
- WebSocket server with room-based messaging
- JWT authentication with token revocation
- CSRF protection for WebSocket connections
- Multi-tier rate limiting system
- Unicode security validation (homograph, BiDi, control chars)
- XSS protection with comprehensive sanitization
- TLS support with certificate validation
- Security event logging and monitoring
- Production mode warnings and configuration validation
- Timing attack protection for authentication
- Message store with automatic cleanup
- IP-based connection limiting
- Configurable thread pool for performance
- Comprehensive test suite

### Security
- JWT and CSRF secret separation
- Constant-time comparisons for sensitive operations
- Certificate expiration monitoring
- Secure random token generation
- Protection against TOCTOU race conditions
- Input validation for all user content
- Security headers for HTTP responses
- Audit logging for all security events

### Changed
- Removed insecure default secrets (now requires environment configuration)
- Improved error handling with detailed logging
- Enhanced documentation with security guidelines

### Fixed
- Race conditions in room operations
- Memory leaks in message storage
- Timing attacks in token validation
- Unicode normalization attacks

[Unreleased]: https://github.com/egdavid/rusty-socks/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/egdavid/rusty-socks/releases/tag/v0.1.0