use serde::Serialize;
use wmi::WMIConnection;
use anyhow::Result;

#[derive(Debug, Serialize)]
pub struct OSInfo {
    pub caption: String,
    pub version: String,
    pub build_number: String,
    pub install_date: String
}
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

        let os_results = &results[0];

        Ok(OSInfo {
            caption: os_results.caption_var.clone(),
            version: os_results.version_var.clone(),
            build_number: os_results.build_number_var.clone(),
            install_date: os_results.install_date_var.clone()
        })

    }
    
}