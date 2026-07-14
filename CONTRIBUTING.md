# Contributing to SentinelX

Thank you for your interest in contributing to SentinelX! This guide will help you get started.

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/<your-username>/sentinelx.git
   cd sentinelx
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/sentinelx/sentinelx.git
   ```
4. Create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```

## Development Setup

### Prerequisites

- **Rust** 1.75 or later (install via [rustup](https://rustup.rs/))
- **SQLite** development libraries
- **Linux** (required — SentinelX is Linux-only)
- **Cargo** (included with Rust)

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Build all workspace crates
cargo build --workspace
```

### Running Tests

```bash
# Run all tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p sentinelx-core

# Run benchmarks
cargo bench --workspace
```

### Linting

```bash
# Check formatting
cargo fmt --all -- --check

# Run clippy
cargo clippy --workspace --all-targets -- -D warnings

# Security audit
cargo audit
```

## Coding Standards

### Rust Style

- Follow the standard Rust style guide
- Run `cargo fmt` before committing
- All code must pass `cargo clippy -- -D warnings`
- Use `rustfmt` defaults (no custom `rustfmt.toml` overrides)

### Safety Rules

- **No panics in production code paths.** Use `Result` types and proper error handling.
- **`unsafe` blocks** require a `// SAFETY:` comment explaining the invariant being upheld.
- All `unsafe` code must be confined to Linux FFI crates where kernel interfaces require it.
- All system call return values must be checked and errors propagated as `Result`.
- No raw pointer arithmetic — use `ptr::read_unaligned` for fixed-size struct reads only.

### Error Handling

- Use `thiserror` for library error types
- Use `anyhow` for application-level error handling where appropriate
- Never use `.unwrap()` or `.expect()` in production code paths

## Commit Conventions

SentinelX uses [Conventional Commits](https://www.conventionalcommits.org/). Format:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type       | Description                                       |
|------------|---------------------------------------------------|
| `feat`     | New feature                                       |
| `fix`      | Bug fix                                           |
| `docs`     | Documentation only changes                        |
| `style`    | Formatting, no code change                        |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test`     | Adding or updating tests                          |
| `chore`    | Build process, CI, or auxiliary tool changes       |
| `perf`     | Performance improvement                           |
| `security` | Security fix                                      |

### Examples

```
feat(core): add evidence correlation engine
fix(netlink): handle truncated NLA messages
docs(readme): update installation instructions
security(audit): fix buffer overread in audit record parsing
```

## Branch Strategy

- **`main`** — Stable release branch. All PRs target `main`.
- **`feat/*`** — Feature branches for new functionality.
- **`fix/*`** — Bug fix branches.
- **`docs/*`** — Documentation-only branches.

Always branch from `main`. Keep your branch up to date with upstream:

```bash
git fetch upstream
git rebase upstream/main
```

## Pull Request Process

1. Ensure your code follows the coding standards above
2. Run the full CI check suite locally before pushing:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   cargo audit
   ```
3. Push your branch and open a PR against `main`
4. Fill out the PR template completely
5. Request a review from a maintainer
6. Address review feedback and push additional commits as needed
7. Once approved, a maintainer will merge your PR

### Review Checklist

- [ ] All CI checks pass (fmt, clippy, test, build, audit)
- [ ] New code has appropriate tests
- [ ] `unsafe` blocks have `// SAFETY:` comments
- [ ] No panics in production code paths
- [ ] Documentation updated if applicable
- [ ] Changelog entry added for user-facing changes

## Testing Requirements

- All existing tests must pass before merging
- New features must include tests
- Bug fixes must include a regression test
- Use the existing test patterns in the codebase for consistency
- Integration tests go in `crates/integration-tests/`

## Architecture Principles

SentinelX is built on these core principles:

- **Evidence-driven pipeline** — Detection is driven by collected evidence, not single-source alerts. Discovery → Metadata → Assessment → Evidence.
- **Graceful degradation** — Missing capabilities reduce functionality without crashing. Every provider has a degraded mode.
- **Safety-first** — All `unsafe` code is confined to FFI crates. No panics in production. Input validation on all external data.

## Issue Guidelines

- Use the provided issue templates (bug report or feature request)
- Include as much detail as possible
- For bugs, include environment info, steps to reproduce, and logs
- For features, describe the use case and expected behavior

Look for the **good first issue** label for issues that are well-suited for first-time contributors.
