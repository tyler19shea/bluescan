// use serde::Serialize;
use wmi::WMIConnection;
use anyhow::Result;
use colored::*;
use crate::OSInfo;
use gethostname::gethostname;

// #[derive(Debug, Serialize)]
// pub struct OSInfo {
//     pub caption: String,
//     pub version: String,
//     pub build_number: String,
//     pub install_date: String
// }
impl OSInfo {
    pub fn gather() -> Result<Self> {
        let wmi_con = WMIConnection::new()?;

        #[derive(serde::Deserialize, Debug)]
        pub struct Win32OperatingSystem {
            #[serde(rename = "Caption")]
            caption_var: String,
            #[serde(rename = "Version")]
            version_var: String,
            #[serde(rename = "BuildNumber")]
            build_number_var: String,
            #[serde(rename = "InstallDate")]
            install_date_var: String
        }
        let results: Vec<Win32OperatingSystem> = wmi_con.raw_query("SELECT Caption, Version, BuildNumber, InstallDate FROM Win32_OperatingSystem")?;

        // #[derive(serde::Deserialize, Debug)]
        // pub struct Win32Processor {
        //     #[serde(rename = "Architecture")]
        //     architecture: String
        // }

        // let architecture_list: Vec<Win32Processor> = wmi_con.raw_query("SELECT Architecture FROM Win32_Processor")?;

        let os_results = &results[0];
        let arch = std::env::consts::ARCH.to_string();
        //let architecture = &architecture_list[0].architecture;

        let hostname_os = gethostname();
        let hostname_string = hostname_os.to_string_lossy().into_owned();

        Ok(OSInfo {
            os_name: os_results.caption_var.clone(),
            version: os_results.version_var.clone(),
            build_number: os_results.build_number_var.clone(),
            install_date: Some(os_results.install_date_var.clone()),
            hostname: hostname_string,
            arch: arch
        })

    }
    
}

pub fn print_os_info() -> String {
    match OSInfo::gather() {
        Ok(info) => {
            format!("OS: {}\nBuild: {}\nVersion: {}\nHostname: {}\nArchitecture: {}", 
                info.os_name.green(),
                info.build_number,
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