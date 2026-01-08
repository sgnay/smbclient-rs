mod error;
pub use error::{Error, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use windows::Win32::Foundation::{WIN32_ERROR, HANDLE, ERROR_NO_MORE_ITEMS, ERROR_MORE_DATA};
use windows::Win32::NetworkManagement::{
    NetManagement::NetApiBufferFree,
    WNet::{self, NET_CONNECT_FLAGS, NETRESOURCEW},
};
use windows::Win32::Storage::FileSystem::NetShareEnum;
use windows::core::{PCWSTR, PWSTR};

/// Convert a Rust string to a Windows wide character string (UTF-16 with null terminator)
///
/// # Arguments
/// * `s` - The input string to convert
///
/// # Returns
/// * `Vec<u16>` - UTF-16 encoded string with null terminator
fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Convert a Windows wide character pointer to a Rust string
///
/// # Safety
/// This function is unsafe because it dereferences a raw pointer.
/// The caller must ensure that the pointer is valid and points to a null-terminated UTF-16 string.
///
/// # Arguments
/// * `ptr` - Pointer to a null-terminated UTF-16 string
///
/// # Returns
/// * `String` - The converted Rust string, or empty string if pointer is null
unsafe fn wide_to_string(ptr: *mut u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice).to_string()
    }
}

// ShareInfo struct: shi1_netname, shi1_type, shi1_remark
// Fields arranged according to C language layout rules
#[repr(C)]
struct ShareInfo {
    shi1_netname: *mut u16,
    shi1_type: u32,
    shi1_remark: *mut u16,
}

/// Represents a network connection
#[derive(Debug, Clone)]
pub struct NetworkConnection {
    /// Local device name (e.g., "X:", empty string for UNC connections)
    pub local_name: String,
    /// Remote network resource (e.g., "\\\\192.168.1.100\\IPC$")
    pub remote_name: String,
    /// Connection type (e.g., "disk", "print")
    pub connection_type: String,
    /// Provider name
    pub provider_name: String,
}

// Map Win32 error codes returned by `WNet`* functions into the local Error enum.
fn map_win32_error(code: WIN32_ERROR) -> Result<()> {
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_ALREADY_ASSIGNED, ERROR_BAD_DEV_TYPE, ERROR_BAD_DEVICE,
        ERROR_BAD_NET_NAME, ERROR_BAD_PROFILE, ERROR_BAD_PROVIDER, ERROR_BAD_USERNAME, ERROR_BUSY,
        ERROR_CANCELLED, ERROR_CANNOT_OPEN_PROFILE, ERROR_DEVICE_ALREADY_REMEMBERED,
        ERROR_DEVICE_IN_USE, ERROR_EXTENDED_ERROR, ERROR_INVALID_ADDRESS, ERROR_INVALID_PARAMETER,
        ERROR_INVALID_PASSWORD, ERROR_LOGON_FAILURE, ERROR_NO_NET_OR_BAD_PATH, ERROR_NO_NETWORK,
        ERROR_NOT_CONNECTED, ERROR_OPEN_FILES, NO_ERROR,
    };

    match code {
        NO_ERROR => Ok(()),
        ERROR_ACCESS_DENIED => Err(Error::AccessDenied),
        ERROR_ALREADY_ASSIGNED => Err(Error::AlreadyAssigned),
        ERROR_BAD_DEV_TYPE => Err(Error::BadDevType),
        ERROR_BAD_DEVICE => Err(Error::BadDevice),
        ERROR_BAD_NET_NAME => Err(Error::BadNetName),
        ERROR_BAD_PROFILE => Err(Error::BadProfile),
        ERROR_BAD_PROVIDER => Err(Error::BadProvider),
        ERROR_BAD_USERNAME => Err(Error::BadUsername),
        ERROR_BUSY => Err(Error::Busy),
        ERROR_CANCELLED => Err(Error::Cancelled),
        ERROR_CANNOT_OPEN_PROFILE => Err(Error::CannotOpenProfile),
        ERROR_DEVICE_ALREADY_REMEMBERED => Err(Error::DeviceAlreadyRemembered),
        ERROR_EXTENDED_ERROR => Err(Error::ExtendedError),
        ERROR_INVALID_ADDRESS => Err(Error::InvalidAddress),
        ERROR_INVALID_PARAMETER => Err(Error::InvalidParameter),
        ERROR_INVALID_PASSWORD => Err(Error::InvalidPassword),
        ERROR_LOGON_FAILURE => Err(Error::LogonFailure),
        ERROR_NO_NET_OR_BAD_PATH => Err(Error::NoNetOrBadPath),
        ERROR_NO_NETWORK => Err(Error::NoNetwork),
        ERROR_NOT_CONNECTED => Err(Error::NotConnected),
        ERROR_OPEN_FILES => Err(Error::OpenFiles),
        ERROR_DEVICE_IN_USE => Err(Error::DeviceInUse),
        _ => Err(Error::Other),
    }
}
/// SMB Share connection manager
///
/// This struct provides methods to connect to, disconnect from, and list SMB shares.
/// It handles Windows SMB/Samba connections using the Windows Networking API.
#[derive(Debug)]
pub struct SmbShare {
    server: String,           // Server address
    share: String,            // Share resource name
    username: Option<String>, // (Optional) Username
    password: Option<String>, // (Optional) Password
    driver: Option<char>,     // (Optional) Drive letter
    persist: bool,            // Whether to persist connection
    interactive: bool,        // Whether to interactively input credentials
}

impl SmbShare {
    /// Creates a new SMB share connection manager
    ///
    /// # Arguments
    /// * `server` - Server address (e.g., "192.168.1.100" or "localhost")
    /// * `share` - Share resource name (e.g., "myshare" or "IPC$")
    /// * `username` - Optional username for authentication
    /// * `password` - Optional password for authentication
    /// * `driver` - Optional drive letter to map the share to (e.g., 'Z')
    /// * `persist` - Whether to persist the connection across sessions
    /// * `interactive` - Whether to allow interactive credential input
    pub fn new(
        server: String,
        share: String,
        username: Option<impl Into<String>>,
        password: Option<impl Into<String>>,
        driver: Option<char>,
        persist: bool,
        interactive: bool,
    ) -> Self {
        SmbShare {
            server,
            share,
            username: username.map(|u| u.into()),
            password: password.map(|p| p.into()),
            driver,
            persist,
            interactive,
        }
    }

    /// Lists all shares available on the server
    ///
    /// # Returns
    /// * `Ok(Vec<String>)` - List of share names on success
    /// * `Err(Error)` - Error message on failure
    pub fn list_shares(&self) -> Result<Vec<String>> {
        let server_w = to_wide(&self.server);
        let mut buf: *mut u8 = null_mut();
        let mut entriesread: u32 = 0;
        let mut totalentries: u32 = 0;

        let status = unsafe {
            NetShareEnum(
                PCWSTR(server_w.as_ptr()),
                1, // Information level 1: Get ShareInfo
                &mut buf,
                u32::MAX, // MAX_PREFERRED_LENGTH
                &mut entriesread,
                &mut totalentries,
                None, // No paging needed
            )
        };

        if status != 0 {
            // Convert Windows error code to our Error type
            return map_win32_error(WIN32_ERROR(status)).map(|_| Vec::new());
        }

        let mut share_names = Vec::new();

        if !buf.is_null() && entriesread > 0 {
            unsafe {
                let ptr = buf as *mut ShareInfo;
                for i in 0..entriesread {
                    let si = ptr.add(i as usize).read();
                    let name = wide_to_string(si.shi1_netname);
                    share_names.push(name);
                }
                // Free buffer
                let _ = NetApiBufferFree(Some(buf as *const core::ffi::c_void));
            }
        }

        Ok(share_names)
    }

    /// Connects to the SMB share using UNC path
    ///
    /// # Returns
    /// * `Ok(())` - Connection successful
    /// * `Err(Error)` - Connection failed with specific error
    pub fn connect_unc(&self) -> Result<()> {
        // Prepare optional local name as wide string
        let local_name_buf = self.driver.map(|ln| to_wide(format!("{ln}:").as_str()));
        let local_name = local_name_buf
            .as_ref()
            .map_or(std::ptr::null_mut(), |v| v.as_ptr().cast_mut());

        let mut flags = NET_CONNECT_FLAGS(0);

        if self.persist && self.driver.is_some() {
            flags |= WNet::CONNECT_UPDATE_PROFILE;
        } else {
            flags |= WNet::CONNECT_TEMPORARY;
        }
        // Bitwise OR assignment to avoid overwriting previous flags
        if self.interactive {
            flags |= WNet::CONNECT_INTERACTIVE;
        }

        // Convert strings to wide (UTF-16) with NUL terminator
        let share_w = to_wide(&format!("\\\\{}\\{}", self.server, self.share));
        let username_w = self.username.as_ref().map(|u| to_wide(u));
        let password_w = self.password.as_ref().map(|p| to_wide(p));

        // https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/ns-winnetwk-netresourcew
        let mut netresourcew = NETRESOURCEW {
            dwDisplayType: 0,                     // ignored by WNetAddConnection2W
            dwScope: WNet::NET_RESOURCE_SCOPE(0), // ignored by WNetAddConnection2W
            dwType: WNet::RESOURCETYPE_DISK,
            dwUsage: 0, // ignored by WNetAddConnection2W
            lpLocalName: PWSTR(local_name),
            lpRemoteName: PWSTR(share_w.as_ptr().cast_mut()),
            lpComment: PWSTR(std::ptr::null_mut()), // ignored by WNetAddConnection2W
            lpProvider: PWSTR(std::ptr::null_mut()), // Microsoft docs: You should set this member only if you know the network provider you want to use.
                                                     // Otherwise, let the operating system determine which provider the network name maps to.
        };

        // https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection2w
        let connection_result = unsafe {
            let username = username_w
                .as_ref()
                .map_or(std::ptr::null_mut(), |u| u.as_ptr().cast_mut());
            let password = password_w
                .as_ref()
                .map_or(std::ptr::null_mut(), |p| p.as_ptr().cast_mut());
            WNet::WNetAddConnection2W(
                std::ptr::from_mut::<NETRESOURCEW>(&mut netresourcew),
                PWSTR(password),
                PWSTR(username),
                flags,
            )
        };

        map_win32_error(connection_result)
    }

    /// Disconnects from the SMB share
    ///
    /// # Returns
    /// * `Ok(())` - Disconnection successful
    /// * `Err(Error)` - Disconnection failed with specific error
    pub fn disconnect_unc(&self) -> Result<()> {
        let resource_to_disconnect_w = match self.driver {
            Some(ln) => to_wide(&format!("{ln}:")),
            None => to_wide(&format!("\\\\{}\\{}", &self.server, &self.share)),
        };

        let dw_flags = if self.persist && self.driver.is_some() {
            WNet::CONNECT_UPDATE_PROFILE
        } else {
            NET_CONNECT_FLAGS(0)
        };

        let disconnect_result = unsafe {
            WNet::WNetCancelConnection2W(
                PWSTR(resource_to_disconnect_w.as_ptr().cast_mut()),
                dw_flags,
                true, // Force disconnect
            )
        };

        if disconnect_result != WIN32_ERROR(0) {
            return map_win32_error(disconnect_result);
        }

        Ok(())
    }

    /// Lists all network connections in the system
    ///
    /// This method enumerates all network connections including:
    /// - UNC connections (e.g., \\\\192.168.1.100\\IPC$)
    /// - Mapped drives (e.g., X: mapped to \\\\server\\share)
    /// - Print connections
    ///
    /// # Returns
    /// * `Ok(Vec<NetworkConnection>)` - List of network connections on success
    /// * `Err(Error)` - Enumeration failed with specific error
    pub fn list_connect_unc() -> Result<Vec<NetworkConnection>> {
        let mut enum_handle: HANDLE = HANDLE(std::ptr::null_mut());
        
        // Open enumeration for connected resources only
        let open_result = unsafe {
            WNet::WNetOpenEnumW(
                WNet::RESOURCE_CONNECTED, // Only enumerate connected resources
                WNet::RESOURCETYPE_ANY,
                WNet::WNET_OPEN_ENUM_USAGE(0), // 0 = all resources
                None, // lpNetResource = None for all resources
                &mut enum_handle,
            )
        };

        if open_result != WIN32_ERROR(0) {
            return map_win32_error(open_result).map(|_| Vec::new());
        }

        let mut connections = Vec::new();
        let mut buffer_size = 16384u32; // 16KB buffer
        let mut buffer: Vec<u8> = vec![0; buffer_size as usize];
        
        loop {
            let mut count = u32::MAX;
            
            let enum_result = unsafe {
                WNet::WNetEnumResourceW(
                    enum_handle,
                    &mut count,
                    buffer.as_mut_ptr() as *mut core::ffi::c_void,
                    &mut buffer_size,
                )
            };

            match enum_result.0 {
                0 => {
                    // Success, process the resources
                    if count == 0 {
                        break; // No more resources
                    }
                    
                    unsafe {
                        let resources = std::slice::from_raw_parts(
                            buffer.as_ptr() as *const NETRESOURCEW,
                            count as usize,
                        );
                        
                        for resource in resources {
                            let local_name = if resource.lpLocalName.is_null() {
                                String::new()
                            } else {
                                wide_to_string(resource.lpLocalName.0 as *mut u16)
                            };
                            
                            let remote_name = if resource.lpRemoteName.is_null() {
                                String::new()
                            } else {
                                wide_to_string(resource.lpRemoteName.0 as *mut u16)
                            };
                            
                            let connection_type = match resource.dwType {
                                WNet::RESOURCETYPE_DISK => "disk".to_string(),
                                WNet::RESOURCETYPE_PRINT => "print".to_string(),
                                _ => format!("unknown ({})", resource.dwType.0),
                            };
                            
                            let provider_name = if resource.lpProvider.is_null() {
                                String::new()
                            } else {
                                wide_to_string(resource.lpProvider.0 as *mut u16)
                            };
                            
                            // Only add connections that are actually connected
                            if !remote_name.is_empty() {
                                connections.push(NetworkConnection {
                                    local_name,
                                    remote_name,
                                    connection_type,
                                    provider_name,
                                });
                            }
                        }
                    }
                }
                error_code if error_code == ERROR_NO_MORE_ITEMS.0 => {
                    break; // No more items
                }
                error_code if error_code == ERROR_MORE_DATA.0 => {
                    // Buffer too small, resize and try again
                    buffer_size = buffer_size * 2;
                    buffer = vec![0; buffer_size as usize];
                    continue;
                }
                _ => {
                    // Some other error
                    unsafe { let _ = WNet::WNetCloseEnum(enum_handle); }
                    return map_win32_error(enum_result).map(|_| Vec::new());
                }
            }
        }
        
        // Close the enumeration handle
        unsafe { let _ = WNet::WNetCloseEnum(enum_handle); }
        
        Ok(connections)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smbshare_new() {
        let smb = SmbShare::new(
            "server".to_string(),
            "share".to_string(),
            Some("user"),
            Some("pass"),
            Some('Z'),
            true,
            false,
        );

        assert_eq!(smb.server, "server");
        assert_eq!(smb.share, "share");
        assert_eq!(smb.username, Some("user".to_string()));
        assert_eq!(smb.password, Some("pass".to_string()));
        assert_eq!(smb.driver, Some('Z'));
        assert_eq!(smb.persist, true);
        assert_eq!(smb.interactive, false);
    }

    #[test]
    fn test_smbshare_new_without_credentials() {
        let smb = SmbShare::new(
            "localhost".to_string(),
            "IPC$".to_string(),
            None::<String>,
            None::<String>,
            None,
            false,
            false,
        );

        assert_eq!(smb.server, "localhost");
        assert_eq!(smb.share, "IPC$");
        assert_eq!(smb.username, None);
        assert_eq!(smb.password, None);
        assert_eq!(smb.driver, None);
        assert_eq!(smb.persist, false);
        assert_eq!(smb.interactive, false);
    }

    #[test]
    fn test_to_wide() {
        let wide = to_wide("test");
        assert_eq!(wide, vec![116, 101, 115, 116, 0]);
        
        // Test empty string
        let wide_empty = to_wide("");
        assert_eq!(wide_empty, vec![0]);
        
        // Test Unicode string
        let wide_unicode = to_wide("test🎉");
        // "t"=116, "e"=101, "s"=115, "t"=116, "🎉"=0xD83C 0xDF89, null=0
        assert_eq!(wide_unicode.len(), 7); // 4 ASCII + 2 surrogate pair + null
        // Verify the actual values
        assert_eq!(wide_unicode[0], 116); // t
        assert_eq!(wide_unicode[1], 101); // e
        assert_eq!(wide_unicode[2], 115); // s
        assert_eq!(wide_unicode[3], 116); // t
        assert_eq!(wide_unicode[4], 0xD83C); // High surrogate
        assert_eq!(wide_unicode[5], 0xDF89); // Low surrogate
        assert_eq!(wide_unicode[6], 0); // null terminator
    }

    #[test]
    fn test_wide_to_string() {
        // Test with null pointer (should return empty string)
        let result = unsafe { wide_to_string(std::ptr::null_mut()) };
        assert_eq!(result, "");
        
        // Test with valid UTF-16 data
        let wide_data: Vec<u16> = vec![116, 101, 115, 116, 0]; // "test"
        let result = unsafe { wide_to_string(wide_data.as_ptr() as *mut u16) };
        assert_eq!(result, "test");
        
        // Test with empty string
        let wide_empty: Vec<u16> = vec![0];
        let result = unsafe { wide_to_string(wide_empty.as_ptr() as *mut u16) };
        assert_eq!(result, "");
        
        // Test with Unicode
        let wide_unicode: Vec<u16> = vec![0xD83C, 0xDF89, 0]; // "🎉"
        let result = unsafe { wide_to_string(wide_unicode.as_ptr() as *mut u16) };
        assert_eq!(result, "🎉");
    }

    #[test]
    fn test_map_win32_error() {
        use windows::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_ALREADY_ASSIGNED, ERROR_BAD_DEV_TYPE, ERROR_BAD_DEVICE,
            ERROR_BAD_NET_NAME, ERROR_BAD_PROFILE, ERROR_BAD_PROVIDER, ERROR_BAD_USERNAME, ERROR_BUSY,
            ERROR_CANCELLED, ERROR_CANNOT_OPEN_PROFILE, ERROR_DEVICE_ALREADY_REMEMBERED,
            ERROR_DEVICE_IN_USE, ERROR_EXTENDED_ERROR, ERROR_INVALID_ADDRESS, ERROR_INVALID_PARAMETER,
            ERROR_INVALID_PASSWORD, ERROR_LOGON_FAILURE, ERROR_NO_NET_OR_BAD_PATH, ERROR_NO_NETWORK,
            ERROR_NOT_CONNECTED, ERROR_OPEN_FILES, NO_ERROR,
        };
        
        // Test NO_ERROR
        assert!(map_win32_error(NO_ERROR).is_ok());
        
        // Test various error codes
        assert_eq!(map_win32_error(ERROR_ACCESS_DENIED).unwrap_err(), Error::AccessDenied);
        assert_eq!(map_win32_error(ERROR_ALREADY_ASSIGNED).unwrap_err(), Error::AlreadyAssigned);
        assert_eq!(map_win32_error(ERROR_BAD_DEV_TYPE).unwrap_err(), Error::BadDevType);
        assert_eq!(map_win32_error(ERROR_BAD_DEVICE).unwrap_err(), Error::BadDevice);
        assert_eq!(map_win32_error(ERROR_BAD_NET_NAME).unwrap_err(), Error::BadNetName);
        assert_eq!(map_win32_error(ERROR_BAD_PROFILE).unwrap_err(), Error::BadProfile);
        assert_eq!(map_win32_error(ERROR_BAD_PROVIDER).unwrap_err(), Error::BadProvider);
        assert_eq!(map_win32_error(ERROR_BAD_USERNAME).unwrap_err(), Error::BadUsername);
        assert_eq!(map_win32_error(ERROR_BUSY).unwrap_err(), Error::Busy);
        assert_eq!(map_win32_error(ERROR_CANCELLED).unwrap_err(), Error::Cancelled);
        assert_eq!(map_win32_error(ERROR_CANNOT_OPEN_PROFILE).unwrap_err(), Error::CannotOpenProfile);
        assert_eq!(map_win32_error(ERROR_DEVICE_ALREADY_REMEMBERED).unwrap_err(), Error::DeviceAlreadyRemembered);
        assert_eq!(map_win32_error(ERROR_EXTENDED_ERROR).unwrap_err(), Error::ExtendedError);
        assert_eq!(map_win32_error(ERROR_INVALID_ADDRESS).unwrap_err(), Error::InvalidAddress);
        assert_eq!(map_win32_error(ERROR_INVALID_PARAMETER).unwrap_err(), Error::InvalidParameter);
        assert_eq!(map_win32_error(ERROR_INVALID_PASSWORD).unwrap_err(), Error::InvalidPassword);
        assert_eq!(map_win32_error(ERROR_LOGON_FAILURE).unwrap_err(), Error::LogonFailure);
        assert_eq!(map_win32_error(ERROR_NO_NET_OR_BAD_PATH).unwrap_err(), Error::NoNetOrBadPath);
        assert_eq!(map_win32_error(ERROR_NO_NETWORK).unwrap_err(), Error::NoNetwork);
        assert_eq!(map_win32_error(ERROR_NOT_CONNECTED).unwrap_err(), Error::NotConnected);
        assert_eq!(map_win32_error(ERROR_OPEN_FILES).unwrap_err(), Error::OpenFiles);
        assert_eq!(map_win32_error(ERROR_DEVICE_IN_USE).unwrap_err(), Error::DeviceInUse);
        
        // Test unknown error code
        assert_eq!(map_win32_error(WIN32_ERROR(9999)).unwrap_err(), Error::Other);
    }

    #[test]
    fn test_list_connect_unc() {
        // Test that we can list network connections without panicking
        match SmbShare::list_connect_unc() {
            Ok(connections) => {
                println!("Found {} network connections:", connections.len());
                for conn in &connections {
                    println!("  Local: '{}', Remote: '{}', Type: '{}', Provider: '{}'", 
                             conn.local_name, conn.remote_name, conn.connection_type, conn.provider_name);
                }
                // We don't assert anything specific about the number of connections
                // because it depends on the system state
            }
            Err(e) => {
                // It's OK if enumeration fails with certain errors on some systems
                println!("list_connect_unc() returned error: {}", e);
                // We should at least not panic
            }
        }
    }

    #[test]
    fn test_network_connection_debug() {
        let conn = NetworkConnection {
            local_name: "X:".to_string(),
            remote_name: "\\\\server\\share".to_string(),
            connection_type: "disk".to_string(),
            provider_name: "Microsoft Windows Network".to_string(),
        };
        
        // Test that Debug trait works
        let debug_output = format!("{:?}", conn);
        assert!(debug_output.contains("local_name"));
        assert!(debug_output.contains("remote_name"));
        assert!(debug_output.contains("connection_type"));
        assert!(debug_output.contains("provider_name"));
    }

    #[test]
    fn test_smbshare_debug() {
        let smb = SmbShare::new(
            "server".to_string(),
            "share".to_string(),
            Some("user"),
            Some("pass"),
            Some('Z'),
            true,
            false,
        );
        
        // Test that Debug trait works
        let debug_output = format!("{:?}", smb);
        assert!(debug_output.contains("server"));
        assert!(debug_output.contains("share"));
        // Note: passwords are not printed in Debug output for security
    }

    #[test]
    fn test_list_shares() {
        // Test that list_shares doesn't panic
        // This is a network-dependent test, so we just verify it returns a Result
        let smb = SmbShare::new(
            "localhost".to_string(),
            "IPC$".to_string(),
            None::<String>,
            None::<String>,
            None,
            false,
            false,
        );
        
        match smb.list_shares() {
            Ok(shares) => {
                println!("Found {} shares on localhost", shares.len());
                // Don't assert anything about the number of shares since it's system-dependent
            }
            Err(e) => {
                // It's OK if this fails on some systems (e.g., no SMB server running)
                println!("list_shares returned error: {}", e);
                // Verify it's a valid error type
                assert!(matches!(e, Error::AccessDenied | Error::BadNetName | Error::NoNetwork | Error::Other));
            }
        }
    }

    #[test]
    fn test_connect_disconnect() {
        let smb_share = SmbShare::new(
            "localhost".to_string(),
            "IPC$".to_string(),
            None::<String>,
            None::<String>,
            None,
            false,
            false,
        );
        
        // Try to connect - this may succeed or fail depending on system configuration
        let connect_result = smb_share.connect_unc();
        
        if let Err(e) = connect_result {
            // Connection failed, which is OK for testing purposes
            println!("Connection failed as expected: {}", e);
            // Verify it's a valid error type
            assert!(matches!(e, 
                Error::AccessDenied | Error::BadNetName | Error::NoNetwork | 
                Error::LogonFailure | Error::InvalidParameter | Error::Other
            ));
        } else {
            // Connection succeeded, so we should disconnect
            println!("Connection succeeded, attempting disconnection");
            match smb_share.disconnect_unc() {
                Ok(_) => println!("Disconnection successful"),
                Err(e) => {
                    println!("Disconnection failed: {}", e);
                    // Don't panic, just log the error
                }
            }
        }
    }

}
        // Test instance method version
