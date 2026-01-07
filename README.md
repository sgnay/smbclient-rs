# smbclient-rs

A Windows SMB/Samba client library for Rust, providing easy-to-use APIs for connecting to, disconnecting from, and listing SMB shares.

## Features

- Connect to SMB shares using UNC paths
- Disconnect from SMB shares
- List available shares on a server
- Support for authentication (username/password)
- Optional drive letter mapping
- Configurable connection persistence
- Comprehensive error handling

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
smbclient-rs = "0.1.0"
```

## Usage

### Basic Example

```rust
use smbclient_rs::{SmbShare, Error};

fn main() -> Result<(), Error> {
    // Create a connection manager
    let smb_share = SmbShare::new(
        "192.168.1.100".to_string(),
        "myshare".to_string(),
        Some("username"),
        Some("password"),
        Some('Z'),  // Map to drive Z:
        false,      // Don't persist connection
        false,      // Don't use interactive mode
    );

    // Connect to the share
    smb_share.connect_unc()?;

    // List available shares
    match smb_share.list_shares() {
        Ok(shares) => {
            println!("Available shares: {:?}", shares);
        }
        Err(e) => eprintln!("Failed to list shares: {}", e),
    }

    // Disconnect
    smb_share.disconnect_unc()?;

    Ok(())
}
```

### Anonymous Access

```rust
let smb_share = SmbShare::new(
    "localhost".to_string(),
    "IPC$".to_string(),
    None::<String>,
    None::<String>,
    None,  // No drive mapping
    false,
    false,
);
```

## API Documentation

### `SmbShare` Struct

The main struct for managing SMB connections.

#### Methods

- `new()` - Creates a new SMB share connection manager
- `connect_unc()` - Connects to the SMB share using UNC path
- `disconnect_unc()` - Disconnects from the SMB share
- `list_shares()` - Lists all shares available on the server

### Error Handling

The library uses the `thiserror` crate for comprehensive error handling. All Windows SMB error codes are mapped to Rust enums for easy pattern matching.

## Command Line Tool

The package includes a command-line tool for testing connections:

```bash
# Basic usage
cargo run -- <server> <share> <username> <password>

# Example with authentication
cargo run -- 192.168.1.100 myshare user pass

# Anonymous access to local IPC share
cargo run -- localhost IPC$ "" ""
```

## Requirements

- Windows operating system (uses Windows Networking API)
- Rust 1.70 or later
- Appropriate network permissions

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Testing

Run the tests with:

```bash
cargo test
```

Note: Some tests require a running SMB server (like localhost with IPC$ share enabled).