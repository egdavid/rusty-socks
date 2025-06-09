# Contributing to Rusty Socks

Thank you for your interest in contributing to Rusty Socks! We welcome contributions from everyone.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

Before submitting a bug report:
- Check existing issues to avoid duplicates
- Use the latest version to reproduce the issue

When submitting a bug report:
- Use a clear, descriptive title
- Describe the exact steps to reproduce
- Include system information (OS, Rust version)
- Provide error messages and logs

### Suggesting Features

Feature requests are welcome! Please:
- Check the [Roadmap](ROADMAP.md) first
- Open an issue with the "enhancement" label
- Describe the use case and proposed solution
- Consider backward compatibility

### Security Issues

**DO NOT** report security vulnerabilities in public issues. See our [Security Policy](SECURITY.md) for responsible disclosure.

## Development Process

### Prerequisites

- Rust 1.70+ with cargo
- Git
- OpenSSL development headers

### Setup

```bash
git clone https://github.com/egdavid/rusty-socks.git
cd rusty-socks
cargo build
cargo test
```

### Making Changes

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-feature`
3. **Make** your changes
4. **Add** tests for new functionality
5. **Run** the test suite: `cargo test`
6. **Check** code formatting: `cargo fmt --check`
7. **Run** linting: `cargo clippy`
8. **Commit** with clear messages
9. **Push** to your fork
10. **Create** a Pull Request

### Code Style

- Follow Rust standard formatting (`cargo fmt`)
- Use meaningful variable and function names
- Add documentation for public APIs
- Write tests for new features
- Keep functions focused and small

### Commit Messages

Use conventional commits format:
```
type(scope): description

body (optional)

footer (optional)
```

Examples:
- `feat(auth): add JWT token refresh`
- `fix(rate-limit): correct memory leak in cleanup`
- `docs(security): update TLS configuration guide`

### Pull Request Guidelines

- Fill out the PR template completely
- Link related issues
- Include tests for new functionality
- Update documentation if needed
- Ensure CI passes
- Request review from maintainers

## Testing

### Running Tests

```bash
# All tests
cargo test

# Specific module
cargo test auth::tests

# Integration tests
cargo test --test websocket_test

# With environment setup
RUST_LOG=debug cargo test
```

### Test Categories

- **Unit tests**: Test individual functions
- **Integration tests**: Test component interaction
- **Security tests**: Validate security features
- **Performance tests**: Benchmark critical paths

### Writing Tests

- Use descriptive test names
- Test both success and error cases
- Mock external dependencies
- Use `#[tokio::test]` for async tests

## Documentation

### Code Documentation

- Document all public APIs with `///`
- Include examples in doc comments
- Explain complex algorithms
- Document safety requirements

### User Documentation

- Update README.md for user-facing changes
- Add examples to the `examples/` directory
- Update security documentation
- Keep the roadmap current

## Release Process

Maintainers handle releases following semantic versioning:
- **Patch** (0.1.1): Bug fixes
- **Minor** (0.2.0): New features, backward compatible
- **Major** (1.0.0): Breaking changes

## Performance Guidelines

- Avoid unnecessary allocations in hot paths
- Use async/await for I/O operations
- Profile before optimizing
- Consider memory usage in long-running processes

## Security Guidelines

- Never commit secrets or credentials
- Validate all user inputs
- Use constant-time comparisons for secrets
- Follow the principle of least privilege
- Document security assumptions

## Getting Help

- Check existing [issues](https://github.com/egdavid/rusty-socks/issues)
- Review the [documentation](https://docs.rs/rusty-socks)
- Ask questions in [discussions](https://github.com/egdavid/rusty-socks/discussions)

## Recognition

All contributors will be acknowledged in:
- CONTRIBUTORS.md file
- Release notes
- Documentation credits

Thank you for helping make Rusty Socks better! 🦀🧦