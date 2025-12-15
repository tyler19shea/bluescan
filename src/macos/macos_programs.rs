use crate::InstalledProgram;
use serde::Deserialize;
use std::process::Command;

#[derive(Debug, Deserialize)]
struct MacApp {
    _name: String,
    version: Option<String>,
    //path: Option<String>,
    #[serde(rename = "lastModified")]
    last_modified: Option<String>,
    obtained_from: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SystemProfilerResponse {
    #[serde(rename = "SPApplicationsDataType")]
    spapplications_data_type: Vec<MacApp>,
}

pub fn get_installed_programs() -> Result<Vec<InstalledProgram>, Box<dyn std::error::Error>> {
    let output = Command::new("system_profiler")
        .args(&["SPApplicationsDataType", "-json"])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "system_profiler command failed with status: {}",
            output.status
        )
        .into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let response: SystemProfilerResponse = serde_json::from_str(&stdout)?;

    let programs = response
        .spapplications_data_type
        .into_iter()
        .map(|app| InstalledProgram {
            name: app._name,
            version: app.version,
            publisher: app.obtained_from,
            install_date: app.last_modified,
        })
        .collect();

    Ok(programs)
}