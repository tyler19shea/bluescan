use std::fs;
use std::process::Command;
use crate::OSInfo;
use colored::*;
use crate::InstalledProgram;

pub fn get_system_info() -> Result<OSInfo, Box<dyn std::error::Error>> {
    // Read /etc/os-release for distro info
    let os_release = fs::read_to_string("/etc/os-release")?;
    
    // Parse for NAME, VERSION_ID, BUILD_ID
    let os_name = parse_os_release(&os_release, "NAME");
    let os_version = parse_os_release(&os_release, "VERSION_ID");
    let os_build = parse_os_release(&os_release, "BUILD_ID")
        .or_else(|| parse_os_release(&os_release, "VERSION"));
    
    // Get kernel version
    let kernel = fs::read_to_string("/proc/version")?;
    
    // Get hostname
    let hostname = fs::read_to_string("/etc/hostname")?
        .trim()
        .to_string();
    
    // Get architecture
    let arch = std::env::consts::ARCH.to_string();
    
    Ok(OSInfo {
        os_name: os_name.unwrap_or_default(),
        version: os_version.unwrap_or_default(),
        build_number: os_build.unwrap_or_default(),
        install_date: None,
        hostname,
        arch: arch
    })
}

pub fn print_os_info() -> String {
    match get_system_info() {
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

// pub fn get_installed_programs() -> Result<Vec<InstalledProgram>, Box<dyn std::error::Error>> {
//     let mut programs = Vec::new();
    
//     // Detect package manager and query accordingly
//     if is_debian_based() {
//         programs.extend(get_dpkg_packages()?);
//     } else if is_redhat_based() {
//         programs.extend(get_rpm_packages()?);
//     } else if is_arch_based() {
//         programs.extend(get_pacman_packages()?);
//     }
    
//     // Also check snap packages
//     programs.extend(get_snap_packages().unwrap_or_default());
    
//     // Flatpak
//     programs.extend(get_flatpak_packages().unwrap_or_default());
    
//     Ok(programs)
// }

// fn get_dpkg_packages() -> Result<Vec<InstalledProgram>, Box<dyn std::error::Error>> {
//     let output = Command::new("dpkg-query")
//         .args(&["-W", "-f=${Package}\t${Version}\t${Maintainer}\n"])
//         .output()?;
    
//     let stdout = String::from_utf8_lossy(&output.stdout);
//     let mut programs = Vec::new();
    
//     for line in stdout.lines() {
//         let parts: Vec<&str> = line.split('\t').collect();
//         if parts.len() >= 2 {
//             programs.push(InstalledProgram {
//                 name: parts[0].to_string(),
//                 version: parts[1].to_string(),
//                 publisher: parts.get(2).map(|s| s.to_string()),
//                 install_date: None, // dpkg doesn't easily provide this
//             });
//         }
//     }
    
//     Ok(programs)
// }

// fn get_rpm_packages() -> Result<Vec<InstalledProgram>, Box<dyn std::error::Error>> {
//     let output = Command::new("rpm")
//         .args(&["-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"])
//         .output()?;
    
//     let stdout = String::from_utf8_lossy(&output.stdout);
//     let mut programs = Vec::new();
    
//     for line in stdout.lines() {
//         let parts: Vec<&str> = line.split('\t').collect();
//         if parts.len() >= 2 {
//             programs.push(InstalledProgram {
//                 name: parts[0].to_string(),
//                 version: parts[1].to_string(),
//                 publisher: parts.get(2).map(|s| s.to_string()),
//                 install_date: None,
//             });
//         }
//     }
    
//     Ok(programs)
// }

// fn is_debian_based() -> bool {
//     std::path::Path::new("/usr/bin/dpkg").exists()
// }

// fn is_redhat_based() -> bool {
//     std::path::Path::new("/usr/bin/rpm").exists()
// }

// fn is_arch_based() -> bool {
//     std::path::Path::new("/usr/bin/pacman").exists()
// }

// Helper function
fn parse_os_release(content: &str, key: &str) -> Option<String> {
    content
        .lines()
        .find(|line| line.starts_with(key))
        .and_then(|line| line.split('=').nth(1))
        .map(|val| val.trim_matches('"').to_string())
}