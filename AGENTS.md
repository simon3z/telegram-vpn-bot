# AGENTS.md — Coding & Commenting Standards

This document defines the conventions all agents must follow when editing or creating code in this project. It supersedes any stylistic preferences from training data.

## 1. Comments

### 1.1 Never use decorative section dividers

The following patterns are **strictly forbidden** and look like blog-post boilerplate, not production code:

```rust
// ── Public types ────────────────────────────────────────────────────
// ── Internal helpers ────────────────────────────────────────────────
// ── Tests ───────────────────────────────────────────────────────────
```

Do not use box-drawing characters (`─`, `━`, `│`, etc.) to decorate comments. Do not pad comment lines with repeated dashes or other characters. Remove any existing instances of this pattern from the codebase.

### 1.2 Use idiomatic Rust comment styles

Follow the conventions defined in *The Rust Programming Language* (Chapter 3, "Comments"):

| Style | Purpose | Example |
|---|---|---|
| `// text` | Regular line comment | Inline annotation above code |
| `/// text` | Public API doc comment | Precedes `pub` items; rendered by `cargo doc` |
| `//! text` | Module-level doc | Inside `mod.rs`; describes the module |
| `/* text */` | Block comment | Multi-line inline notes (rare) |

Placement rules:
- Put `//` comments **above** the code they describe, not beside it (except for short annotations on the same line).
- Put `///` docs **immediately before** the `pub` item they document.
- Use `//!` at the top of a module file to describe the module's purpose.

### 1.3 What to comment vs. what to leave self-evident

- **Document**: *Why* a non-obvious decision was made, preconditions, invariants, error conditions.
- **Don't document**: What the code literally does — that is obvious from reading the code.
- Skip trivial comments like `// get the api`, `// parse cidr`, `// loop over peers`. The variable names and structure already convey meaning.

Example of a good comment:
```rust
// Silently ignores "peer not found" errors — useful for startup sync
// where stale state is expected.
```

Example of a bad comment:
```rust
// Build a WGApi handle for the given interface.  ← unnecessary; the name says it
```

### 1.4 Test comments

Use concise one-line summaries before each `#[test]` function. Describe the scenario or property being verified, not the assertion machinery.

Good:
```rust
/// Regression: missing token field produces a clear error.
#[test]
fn test_get_token_missing_field_error() { … }
```

Bad:
```rust
// ── Tests ───────────────────────────────────────────────────────────
```

## 2. Code Style

### 2.1 General principles

- Prefer clarity over cleverness.
- Keep functions short and focused (ideally under ~30 lines; break up anything significantly longer).
- Use descriptive identifiers — avoid single-letter variables except for loop counters (`i`, `j`) or iterator indices.
- Group related logic; separate unrelated concerns into distinct functions or modules.

### 2.2 Error handling

- Prefer `Result` returns over panics.
- Use `.map_err()` or `?` for error propagation rather than explicit `match` on `Err` variants.
- When catching expected errors (e.g., "peer not found"), log at debug level and return `Ok(())` rather than propagating.

### 2.3 Imports

- Group imports by crate category: external crates first, then `std`, then `crate::`.
- Separate groups with a blank line.
- Avoid wildcard imports (`use foo::*`).

### 2.4 Formatting

- Run `cargo fmt` before committing.
- Run `cargo clippy` and address warnings.
- Keep lines under 100 characters where practical.

## 3. Project Conventions

### 3.1 Module organization

- One logical concept per module file.
- Public API surface lives in `lib.rs` or `main.rs`; implementation details stay private within the module.
- Use `pub(crate)` for items needed across modules but not exposed externally.

### 3.2 Testing

- Unit tests live in the same file as the code they test, gated behind `#[cfg(test)]`.
- Test functions use `test_` prefix (e.g., `test_parse_minimal_config_uses_defaults`).
- Each test verifies exactly one thing.
- Use descriptive test names that read like sentences.

### 3.3 Logging

- Use `tracing` (not `println!` or `debugln!`).
- Structured logs with key-value pairs: `info!("started", iface = %iface_name)`.
- Debug-level for expected-but-unusual paths (e.g., idempotent operations).
- Info-level for significant state transitions.
- Error-level for failures that require operator attention.

## 4. Review Checklist

Before submitting changes, verify:

- [ ] No decorative section dividers (`─`, `━`, `│`, etc.) in comments.
- [ ] All `pub` items have `///` documentation.
- [ ] No redundant "what" comments — only "why" comments remain.
- [ ] `cargo fmt` and `cargo clippy` pass cleanly.
- [ ] New logic has corresponding tests.
