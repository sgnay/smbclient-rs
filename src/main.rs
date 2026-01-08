use smbclient_rs::{NetworkConnection, SmbShare};

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
            "(UNC)".to_string()
        } else {
            conn.local_name.clone()
        };

        println!(
            "{:<10} {:<30} {:<15} {:<30}",
            local_display, conn.remote_name, conn.connection_type, conn.provider_name
        );
    }

    println!("{}", "=".repeat(100));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  {} <server> <share> <username> <password>", args[0]);
        eprintln!("Examples:");
        eprintln!("  {} 192.168.1.100 myshare user pass", args[0]);
        eprintln!("  {} localhost IPC$ \"\" \"\" (anonymous access)", args[0]);
        std::process::exit(1);
    }

    let server = &args[1];
    let share = &args[2];
    let username = &args[3];
    let password = &args[4];

    println!("Connecting to server: {}", server);

    // Convert empty strings to None
    let username_opt = if username.is_empty() {
        None
    } else {
        Some(username.to_string())
    };

    let password_opt = if password.is_empty() {
        None
    } else {
        Some(password.to_string())
    };

    let smb_share = SmbShare::new(
        server.to_string(),
        share.to_string(),
        username_opt,
        password_opt,
        None,
        false,
        false,
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
            println!("Listing all network connections in the system...\n");
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
