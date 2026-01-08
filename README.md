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
- Enumerate system network connections
- Support for interactive credential input

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

### Enumerate Network Connections

```rust
use smbclient_rs::SmbShare;

fn list_network_connections() -> Result<(), Box<dyn std::error::Error>> {
    let connections = SmbShare::list_connect_unc()?;
    
    println!("Found {} network connections:", connections.len());
    for conn in connections {
        println!("Local: '{}', Remote: '{}', Type: '{}', Provider: '{}'",
                 conn.local_name, conn.remote_name, conn.connection_type, conn.provider_name);
    }
    
    Ok(())
}
```

### Error Handling

```rust
use smbclient_rs::{SmbShare, Error};

fn connect_with_error_handling() -> Result<(), Error> {
    let smb_share = SmbShare::new(
        "invalid-server".to_string(),
        "share".to_string(),
        None::<String>,
        None::<String>,
        None,
        false,
        false,
    );

    match smb_share.connect_unc() {
        Ok(_) => println!("Connection successful!"),
        Err(Error::BadNetName) => eprintln!("Network name is invalid or not found"),
        Err(Error::AccessDenied) => eprintln!("Access denied"),
        Err(Error::LogonFailure) => eprintln!("Logon failure"),
        Err(e) => eprintln!("Other error: {}", e),
    }

    Ok(())
}
```

## API Documentation

### `SmbShare` Struct

The main struct for managing SMB connections.

#### Constructor

```rust
pub fn new(
    server: String,
    share: String,
    username: Option<impl Into<String>>,
    password: Option<impl Into<String>>,
    driver: Option<char>,
    persist: bool,
    interactive: bool,
) -> Self
```

#### Methods

- `connect_unc() -> Result<()>` - Connects to the SMB share using UNC path
- `disconnect_unc() -> Result<()>` - Disconnects from the SMB share
- `list_shares() -> Result<Vec<String>>` - Lists all shares available on the server
- `list_connect_unc() -> Result<Vec<NetworkConnection>>` - Lists all network connections in the system (static method)

### `NetworkConnection` Struct

Represents information about a network connection.

```rust
pub struct NetworkConnection {
    pub local_name: String,      // Local device name (e.g., "X:", empty string for UNC connections)
    pub remote_name: String,     // Remote network resource (e.g., "\\\\192.168.1.100\\IPC$")
    pub connection_type: String, // Connection type (e.g., "disk", "print")
    pub provider_name: String,   // Provider name
}
```

### Error Handling

The library uses the `thiserror` crate for comprehensive error handling. All Windows SMB error codes are mapped to Rust enums for easy pattern matching.

Main error types include:
- `AccessDenied` - Access denied
- `BadNetName` - Network name is invalid
- `LogonFailure` - Logon failure
- `InvalidPassword` - Invalid password
- `NoNetwork` - Network is unavailable
- And other Windows SMB errors

## Command Line Tool

The package includes a command-line tool for testing connections:

```bash
# Basic usage
cargo run -- <server> <share> <username> <password>

# Example with authentication
cargo run -- 192.168.1.100 myshare user pass

# Anonymous access to local IPC share
cargo run -- localhost IPC$ "" ""

# Show help
cargo run -- --help
```

Tool features:
1. Connect to the specified SMB share
2. List all shares on the server
3. Display all network connections in the system
4. Disconnect

## Requirements

- Windows operating system (uses Windows Networking API)
- Rust 1.70 or later
- Appropriate network permissions
- Administrator privileges may be required for some operations

## Platform Support

This library is specifically designed for Windows platform as it uses Windows-specific APIs (`windows` crate). Compilation on non-Windows platforms will fail.

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

## Development Status

Current version: 0.1.0

This library is in early development stage, APIs may change. Feedback and contributions are welcome!

## Known Limitations

1. Windows platform only
2. Requires appropriate network permissions
3. Some operations may require administrator privileges
4. Error handling may not cover all edge cases

## Related Projects

- [windows-rs](https://github.com/microsoft/windows-rs) - Windows API bindings for Rust
- [smbprotocol](https://github.com/samba-team/samba) - SMB protocol implementation

## Support

For issues or suggestions, please submit a GitHub Issue.