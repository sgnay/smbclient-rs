# AGENTS.md — smbclient-rs

## Critical Constraints

- **Windows only.** This library wraps the Windows `NETRESOURCEW` and `WNet*` APIs (`WNetAddConnection2W`, `WNetCancelConnection2W`, `NetShareEnum`, etc.). It cannot compile or run on Linux or macOS.
- **Do not run `cargo build` or `cargo test` on non-Windows.** They will fail with missing Windows API types. The only safe verification command on Linux is `cargo fmt --check`.

## Architecture

- Single-crate library + CLI tool.
- Entry points: `src/lib.rs` (library), `src/main.rs` (CLI).
- No workspace, no monorepo, no codegen.

## Testing

- Tests are integration tests against live Windows networking APIs (e.g., `localhost` IPC$). Results depend on the host's SMB configuration and network state.
- Do not expect deterministic pass/fail in CI or sandboxes without a real Windows SMB server.

## Tooling

- No custom `rustfmt.toml` or `clippy.toml` exists. Use default Rust conventions.
- `cargo fmt` works cross-platform and should be used to clean up formatting before submitting changes.
