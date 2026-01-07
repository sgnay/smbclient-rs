use smbclient_rs::SmbShare;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 5 {
        eprintln!("Usage: {} <server> <share> <username> <password>", args[0]);
        eprintln!("Example: {} 192.168.1.100 myshare user pass", args[0]);
        eprintln!(
            "Example: {} localhost IPC$ \"\" \"\" (anonymous access)",
            args[0]
        );
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

    match smb_share.disconnect_unc() {
        Ok(_) => println!("Disconnection successful!"),
        Err(e) => eprintln!("Disconnection failed: {}", e),
    }
}
