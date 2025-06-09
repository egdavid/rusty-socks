# 🔒 Security Policy

## Reporting Security Vulnerabilities

We take security seriously. If you discover a security vulnerability, please report it responsibly:

1. **DO NOT** open a public issue
2. Email: security@rustysocks.io
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We'll respond within 48 hours and work with you to resolve the issue.

## Security Features

### Authentication & Authorization
- **JWT Tokens** with configurable expiration
- **CSRF Protection** for WebSocket connections
- **Token Revocation** with server-side blacklist
- **Role-Based Access Control** for rooms and operations

### Input Validation
- **Unicode Security** - Protection against homograph attacks, BiDi spoofing
- **XSS Prevention** - Comprehensive HTML/JS escaping
- **Message Size Limits** - Configurable per user tier
- **Rate Limiting** - Multi-tier with automatic penalties

### Network Security
- **TLS 1.2+** with secure cipher suites
- **Certificate Validation** with expiration monitoring
- **IP-Based Connection Limits**
- **Origin Validation** for CSRF protection

### Cryptographic Security
- **Timing Attack Protection** - Constant-time comparisons
- **Secure Random Generation** - Using OS entropy
- **Argon2 Password Hashing** - Memory-hard algorithm
- **Secret Separation** - Different keys for JWT/CSRF

### Operational Security
- **Security Event Logging** - Comprehensive audit trail
- **Production Warnings** - Detects insecure configurations
- **No Default Secrets** - Fails safe without configuration
- **Memory Cleanup** - Automatic purging of old data

## Security Configuration

### Required Environment Variables
```bash
# Generate secure secrets (minimum 32 characters)
export RUSTY_SOCKS_JWT_SECRET=$(openssl rand -base64 32)
export RUSTY_SOCKS_CSRF_SECRET=$(openssl rand -base64 32)

# Enable TLS (required for production)
export RUSTY_SOCKS_ENABLE_TLS=true
export RUSTY_SOCKS_TLS_CERT_PATH=/path/to/cert.pem
export RUSTY_SOCKS_TLS_KEY_PATH=/path/to/key.pem

# Set production mode
export RUST_ENV=production
```

### Security Best Practices

1. **Always use TLS in production**
   - Obtain certificates from trusted CA
   - Enable HSTS headers
   - Monitor certificate expiration

2. **Rotate secrets regularly**
   - JWT secrets every 90 days
   - Implement graceful rotation

3. **Monitor security events**
   - Set up alerts for authentication failures
   - Track rate limit violations
   - Monitor for Unicode attacks

4. **Keep dependencies updated**
   ```bash
   ./scripts/update-dependencies.sh
   cargo audit
   ```

5. **Configure rate limits appropriately**
   - Adjust based on your use case
   - Monitor for false positives

## Security Headers

The server automatically sets these security headers:
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Content-Security-Policy: default-src 'self'`

## Threat Model

### Protected Against
- ✅ Cross-Site Scripting (XSS)
- ✅ Cross-Site Request Forgery (CSRF)
- ✅ SQL Injection (no SQL used)
- ✅ Token Replay Attacks
- ✅ Timing Attacks
- ✅ Unicode/Homograph Attacks
- ✅ Resource Exhaustion (DoS)
- ✅ Man-in-the-Middle (with TLS)

### Assumptions
- TLS termination is properly configured
- Environment variables are securely managed
- Host system is hardened and updated
- Monitoring and alerting are in place

## Compliance

The security implementation helps meet requirements for:
- **OWASP Top 10** mitigation
- **GDPR** - User data protection
- **PCI DSS** - If handling payment data
- **SOC 2** - With proper audit logging

## Security Checklist for Deployment

- [ ] TLS certificate from trusted CA
- [ ] Unique, strong JWT and CSRF secrets
- [ ] Production mode enabled
- [ ] Rate limiting configured
- [ ] Security logging enabled
- [ ] Monitoring alerts configured
- [ ] Dependency audit completed
- [ ] Firewall rules configured
- [ ] Regular backup strategy
- [ ] Incident response plan

## Version Support

| Version | Supported | Security Updates |
|---------|-----------|------------------|
| 0.1.x   | ✅        | Until 0.2.0      |
| 0.0.x   | ❌        | No longer supported |

## References

- [OWASP WebSocket Security](https://owasp.org/www-project-web-security-testing-guide/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [Unicode Security Guide](https://unicode.org/reports/tr39/)

---

*Last updated: June 2025*