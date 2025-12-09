use std::process::Command;

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

        let mut version_string = info.version().to_string();
        let os_name = info.os_type().to_string();

        if version_string == "Unknown" {
            let output = Command::new("uname")
                .arg("-r")
                .output()
                .unwrap();
            if output.status.success() {
                version_string = str::from_utf8(&output.stdout)
                    .expect("failed to gather kernel version")
                    .to_string()
                    .replace("\n", "");
            } 
        }


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