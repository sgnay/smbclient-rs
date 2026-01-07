mod error;
pub use error::{Error, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::NetworkManagement::{
    NetManagement::NetApiBufferFree,
    WNet::{self, CONNECT_UPDATE_PROFILE, NET_CONNECT_FLAGS, NETRESOURCEW},
};
use windows::Win32::Storage::FileSystem::NetShareEnum;
use windows::core::{PCWSTR, PWSTR};

// Convert &str to wide character string
fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

// Read string from wide character pointer
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
    /// * `Err(String)` - Error message on failure
    pub fn list_shares(&self) -> core::result::Result<Vec<String>, String> {
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
            return Err(format!("NetShareEnum failed, error code: {}", status));
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
        let mut netresource = NETRESOURCEW {
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
                std::ptr::from_mut::<NETRESOURCEW>(&mut netresource),
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
            CONNECT_UPDATE_PROFILE
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Test connection
        match smb_share.connect_unc() {
            Ok(_) => println!("Connection successful"),
            Err(e) => panic!("Connection failed: {}", e),
        }
        // Test disconnection
        match smb_share.disconnect_unc() {
            Ok(_) => println!("Disconnection successful"),
            Err(e) => panic!("Disconnection failed: {}", e),
        }
    }
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
    }
}
