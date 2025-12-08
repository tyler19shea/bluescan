use os_info;
use anyhow::Result;
use colored::*;
use gethostname::gethostname;
use crate::OSInfo;

impl OSInfo {
    pub fn gather() -> Result<Self> {
        let info = os_info::get();

        let hostname = gethostname()
            .to_string_lossy()
            .into_owned();

        let version_string = info.version().to_string();
        let os_name = info.os_type().to_string();


        Ok(OSInfo {
            os_name,
            version: version_string,
            hostname,
            arch: std::env::consts::ARCH.to_string(),
        })
    }
}

pub fn print_os_info() -> String {
    match OSInfo::gather() {
        Ok(info) => {
            format!("OS: {}\nVersion: {}\nHostname: {}\nArchitecture: {}", 
                info.os_name.green(),
                info.version,
                info.hostname,
                info.arch
            ).to_string()
        }
        Err(e) => {
            format!("Error Gathering OS Information: {}", e).to_string()
        }
    }
}
