//use anyhow::Ok;
use anyhow::Result;
use serde::Serialize;
use winreg::enums::*;
use winreg::RegKey;

#[derive(Debug, Serialize)]
pub struct InstalledProgram {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_date: Option<String>
}

pub fn get_installed_programs() -> Result<Vec<InstalledProgram>>{
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    let paths= vec![
        r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ];

    let mut programs: Vec<InstalledProgram> = Vec::new();

    //HKLM 32 + 64 bit
    for path in &paths {
        if let Ok(subkey) = hklm.open_subkey(path) {
            read_uninstall_key(&subkey, &mut programs)?;
        }
    }
    if let Ok(subkey) = hkcu.open_subkey(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    ) {
        read_uninstall_key(&subkey, &mut programs)?;
    }
    Ok(programs)
}
fn read_uninstall_key (
    parent: &RegKey,
    output: &mut Vec<InstalledProgram>
) -> Result<()> {
    for subkey_name in parent.enum_keys().flatten() {
        if let Ok(subkey) = parent.open_subkey(&subkey_name) {
            if let Ok(name) = subkey.get_value::<String, _>("DisplayName"){
                 let version = subkey.get_value::<String, _>("DisplayVersion").ok();
                let publisher = subkey.get_value::<String, _>("Publisher").ok();
                let install_date = subkey.get_value::<String, _>("InstallDate").ok();

                output.push(InstalledProgram {
                    name,
                    version,
                    publisher,
                    install_date
                });
            }
        }
    }
    Ok(())
}