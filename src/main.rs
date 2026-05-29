use clap::Parser;
use smbclient_rs::{NetworkConnection, SmbShare};

/// Windows SMB/Samba client tool — connect, enumerate, and disconnect SMB shares.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Server address (e.g. 192.168.1.100 or localhost)
    server: String,

    /// Share resource name (e.g. myshare or IPC$)
    share: String,

    /// Username for authentication (empty string for anonymous)
    username: String,

    /// Password for authentication (empty string for anonymous)
    password: String,

    /// Map to a drive letter (e.g. Z)
    #[arg(short, long)]
    drive: Option<char>,

    /// Persist the connection across sessions
    #[arg(short, long, default_value_t = false)]
    persist: bool,

    /// Allow interactive credential input
    #[arg(short, long, default_value_t = false)]
    interactive: bool,
}

fn print_connection_table(connections: &[NetworkConnection]) {
    if connections.is_empty() {
        println!("No network connections found.");
        return;
    }

    println!("Found {} network connection(s):", connections.len());
    println!("{}", "=".repeat(100));
    println!(
        "{:<10} {:<30} {:<15} {:<30}",
        "Local", "Remote", "Type", "Provider"
    );
    println!("{}", "-".repeat(100));

    for conn in connections {
        let local_display = if conn.local_name.is_empty() {
            "(UNC)"
        } else {
            &conn.local_name
        };

        println!(
            "{:<10} {:<30} {:<15} {:<30}",
            local_display, conn.remote_name, conn.connection_type, conn.provider_name
        );
    }

    println!("{}", "=".repeat(100));
}

fn main() {
    let cli = Cli::parse();

    println!("Connecting to server: {}", cli.server);

    let username_opt = if cli.username.is_empty() {
        None
    } else {
        Some(cli.username)
    };

    let password_opt = if cli.password.is_empty() {
        None
    } else {
        Some(cli.password)
    };

    let smb_share = SmbShare::new(
        cli.server,
        cli.share,
        username_opt,
        password_opt,
        cli.drive,
        cli.persist,
        cli.interactive,
    );

    match smb_share.connect_unc() {
        Ok(_) => println!("Connection successful!\n"),
        Err(e) => {
            eprintln!("Connection failed: {}\n", e);
            std::process::exit(1);
        }
    }

    match smb_share.list_shares() {
        Ok(shares) => {
            if shares.is_empty() {
                println!("No shares found");
            } else {
                println!("Found {} shares:\n", shares.len());
                println!("{}", "=".repeat(80));

                for share in shares {
                    println!("{}", share);
                }

                println!("{}", "=".repeat(80));
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }

    match SmbShare::list_connect_unc() {
        Ok(connections) => {
            println!("Listing all network connections in the system ...\n");
            print_connection_table(&connections);
        }
        Err(e) => {
            eprintln!("Error listing network connections: {}", e);
            std::process::exit(1);
        }
    }

    match smb_share.disconnect_unc() {
        Ok(_) => println!("Disconnection successful!"),
        Err(e) => eprintln!("Disconnection failed: {}", e),
    }
}
