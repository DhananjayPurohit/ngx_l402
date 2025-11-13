# Contributing to ngx_l402

Thank you for your interest in contributing to ngx_l402! This guide will help you understand how to contribute effectively to this high-performance Nginx module for L402 authentication.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Quick Start for Contributors](#quick-start-for-contributors)
- [How to Contribute](#how-to-contribute)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Performance Testing](#performance-testing)
- [Pull Request Process](#pull-request-process)
- [Architecture Guidelines](#architecture-guidelines)

## Code of Conduct

**Inclusivity Policy**: This project maintains a written policy requiring the equal treatment of all people, regardless of race, ethnicity, gender, sexual orientation, disability, age, religion, political opinion, or any other status. All contributors and participants must adhere to this standard.

- Be welcoming, respectful, and inclusive
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards other contributors

## Quick Start for Contributors

1. **Fork and clone** the repository
2. **Review the [README.md](README.md)** for installation and configuration
3. **Create a feature branch**: `git checkout -b feature/your-feature-name`
4. **Make your changes** following our coding standards
5. **Test thoroughly** before submitting

---

## How to Contribute

We welcome various types of contributions:

| Type | Examples |
|------|----------|
| 🐛 **Bug Fixes** | Memory leaks, crashes, incorrect behavior |
| ✨ **Features** | New payment methods, protocol extensions |
| 📚 **Documentation** | Code comments, usage examples, guides |
| 🧪 **Testing** | Unit tests, integration tests, benchmarks |
| ⚡ **Performance** | Profiling, optimization, bottleneck fixes |
| 🔧 **Tooling** | CI/CD improvements, development scripts |

### Finding Issues to Work On

- Browse [open issues](https://github.com/DhananjayPurohit/ngx_l402/issues)
- Look for `good-first-issue` or `help-wanted` labels if you are new.
- Check performance optimization issues (especially post-stress testing)
- Improve areas where documentation is unclear

### Reporting Bugs

**Before submitting**, search existing issues to avoid duplicates.

Include in your bug report:
- **Steps to reproduce** the issue
- **Expected vs actual behavior**
- **Environment**: Nginx version, OS, module version
- **Logs**: Relevant error messages (sanitize secrets!)
- **Configuration**: Nginx config (remove sensitive data)

Use the GitHub issue template when creating a new bug report.

### Suggesting Features

When proposing new features:
- **Check existing feature requests** first
- **Describe the use case** and problem it solves
- **Consider performance impact** (this is a high-performance module)
- **Discuss alternatives** and trade-offs

---

## Development Workflow

### Branching Strategy

```bash
# Create a feature branch
git checkout -b feature/add-new-payment-method

# Create a bugfix branch
git checkout -b fix/memory-leak-in-cashu

# Create a performance branch
git checkout -b perf/optimize-token-verification
```

### Development Cycle

1. **Make changes** in your feature branch
2. **Test locally**
3. **Commit with clear messages** (see [Commit Guidelines](#commit-guidelines))
4. **Push to your fork**
5. **Open a Pull Request**

### Keeping Your Fork Updated

```bash
# Fetch upstream changes
git fetch upstream

# Merge upstream main into your branch
git checkout main
git merge upstream/main

# Rebase your feature branch
git checkout feature/your-feature
git rebase main
```

---

## Coding Standards

### Rust Best Practices

**Required before submitting**:
```bash
cargo fmt              # Format code
```

**Code style**:
- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Write idiomatic Rust (iterators over loops, avoid unnecessary cloning)
- Use meaningful variable names
- Add doc comments (`///`) for public functions

**Code quality principles**:
- **Safety First**: Minimize `unsafe` code; document all safety invariants
- **No Panics**: Use `Result<T, E>` instead of `.unwrap()` or `.expect()`
- **Smart Logging**: Use appropriate log levels (`debug!`, `info!`, `warn!`, `error!`)
- **Self-Documenting**: Code should be clear; comments explain *why*, not *what*
- **Performance Aware**: Avoid allocations and blocking in hot paths

### Commit Guidelines

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`

**Examples**:
```
feat: add P2PK mode for optimized verification

fix: correctly validate expired macaroons

perf: use connection pooling to reduce latency

docs: clarify unsafe code guidelines
```

### Unsafe Code Guidelines

This module uses FFI with Nginx C API. When writing `unsafe` code:

```rust
// ✅ GOOD: Document safety invariants
// SAFETY: `request` pointer is non-null and valid for this handler's lifetime,
// as guaranteed by Nginx before invoking the handler.
pub unsafe extern "C" fn handler(request: *mut ngx_http_request_t) -> isize {
    if request.is_null() {
        return NGX_ERROR as isize;
    }
    // ...
}

// ❌ BAD: No safety documentation
pub unsafe extern "C" fn handler(request: *mut ngx_http_request_t) -> isize {
    let r = &mut *request;  // Could segfault if null!
    // ...
}
```

**Rules**:
- Always check pointers for null before dereferencing
- Document why the unsafe operation is safe
- Prefer safe abstractions when possible
- Test with Valgrind or AddressSanitizer

---

## Testing Guidelines

### Integration Testing

Test the full module with Nginx:

1. Build and install the module
2. Configure a test endpoint
3. Send test requests (valid auth, missing auth, expired tokens)
4. Verify responses and logs

---

## Performance Testing

> 📊 This module has been [stress tested](https://primal.net/e/nevent1qqs0x4x4g4jhugs44mdqwwe7c52lj0m63qsus7f68kvvhx4fs4jf8cqdvadjl) under high load. Performance-critical changes must be benchmarked.

### Performance-Critical Areas

| Component | Target | Notes |
|-----------|--------|-------|
| Request handler | < 1ms | Processes every request |
| L402 verification | < 5ms | Valid token path |
| Cashu P2PK mode | < 10ms | With local verification |
| Redis lookup | < 1ms | Dynamic pricing |

### Optimization Guidelines

**Hot Path Rules**:
- Avoid allocations (use static buffers, lazy initialization)
- No blocking I/O (use async or caching)
- Prefer stack over heap
- Use connection pooling for Redis/database

Example PR description:
```markdown
## Performance Improvement

**Before**: 5,420 req/s (p95: 25ms)
**After**: 8,730 req/s (p95: 12ms)
**Improvement**: +61% throughput, -52% latency
```

---

## Pull Request Process

### Pre-Submission Checklist

Before opening a PR:

- [ ] Code formatted: `cargo fmt`
- [ ] Tests pass: `cargo test`
- [ ] Module builds: `cargo build --release --features export-modules`
- [ ] Manual testing with Nginx performed
- [ ] Commit messages follow conventions
- [ ] No merge conflicts with `main`
- [ ] Documentation updated (if needed)

### PR Template

Use this structure for your PR description:

```markdown
## What
Brief description of changes (1-2 sentences).

## Why
Motivation / problem being solved.

## How
Implementation approach and key changes.

## Testing
- [ ] Unit tests added/updated
- [ ] Manually tested with Nginx
- [ ] Load tested (if performance-related)

## Checklist
- [ ] Code formatted and linted
- [ ] No breaking changes (or documented)
- [ ] Benchmark results included (if perf change)

Closes #issue_number
```

### Review Process

1. **CI checks run**: Automated formatting, linting, tests
2. **Maintainer review**: Code quality, design, safety
3. **Discussion**: Address feedback and questions
4. **Approval**: One maintainer approval required
5. **Merge**: Squash and merge to `main`

### After Your PR is Merged

- You'll be credited in release notes
- Changes included in next release
- Consider helping with documentation or examples

---

## Architecture Guidelines

### Module Structure

```
Request → Access Handler → L402 Check → Verification → Response
                               ↓
                          Redis Pricing (dynamic)
                               ↓
                      Lightning/Cashu Payment
```

### Key Design Principles

1. **Minimal Request Latency**: Every request passes through this module
2. **Zero-Copy Where Possible**: Avoid unnecessary allocations
3. **Fail Securely**: Errors should deny access, not grant it
4. **Async-Aware**: Use non-blocking operations for I/O
5. **Memory Safety**: FFI boundary must be bulletproof

### Adding New Features

When adding features, consider:

- **Backward compatibility**: Will this break existing users?
- **Configuration**: Should this be optional/configurable?
- **Performance impact**: Benchmark critical paths
- **Error handling**: What happens when it fails?
- **Testing**: Can this be unit tested? Integration tested?

### Common Pitfalls

❌ **Don't**:
- Block in the request handler
- Panic in FFI code (Nginx will crash)
- Allocate on every request
- Use `.unwrap()` or `.expect()`
- Skip null checks on C pointers

✅ **Do**:
- Use lazy static for expensive initialization
- Return errors via `Result`
- Profile hot paths
- Add comprehensive safety comments
- Test edge cases

---

## Getting Help

- 📖 **Documentation**: See [README.md](README.md)
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/DhananjayPurohit/ngx_l402/issues)
- 📚 **Learning Resources**:
  - [Rust Book](https://doc.rust-lang.org/book/)
  - [L402 Protocol](https://docs.lightning.engineering/the-lightning-network/l402)
  - [Nginx Dev Guide](http://nginx.org/en/docs/dev/development_guide.html)
  - [Cashu Protocol (NUT)](https://github.com/cashubtc/nuts)

---

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENCE).

---

## Quick Commands Reference

```bash
# Development
cargo fmt                                    # Format
cargo build --release --features export-modules  # Build

# Installation
sudo cp target/release/libngx_l402_lib.so /etc/nginx/modules/
sudo systemctl restart nginx && sudo systemctl reload nginx

# Debugging
sudo journalctl -u nginx -f                  # View logs
sudo tail -f /var/log/nginx/error.log        # Error logs
```

---

**Thank you for contributing to ngx_l402!** 🚀⚡

Your contributions help make Lightning Network payments more accessible and performant for everyone.
