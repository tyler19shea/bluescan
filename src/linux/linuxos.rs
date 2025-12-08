use std::process::Command;
use crate::InstalledProgram;

pub fn get_installed_programs() -> Result<Vec<InstalledProgram>, Box<dyn std::error::Error>> {
    let mut programs = Vec::new();
    
    // Detect package manager and query accordingly
    if is_debian_based() {
        programs.extend(get_dpkg_packages()?);
    } else if is_redhat_based() {
        programs.extend(get_rpm_packages()?);
    } else if is_arch_based() {
        programs.extend(get_pacman_packages()?);
    }
    
    // Also check snap packages
    programs.extend(get_snap_packages().unwrap_or_default());
    
    // Flatpak
    programs.extend(get_flatpak_packages().unwrap_or_default());
    
    Ok(programs)
}

fn get_dpkg_packages() -> Result<Vec<InstalledProgram>, Box<dyn std::error::Error>> {
    let output = Command::new("dpkg-query")
        .args(&["-W", "-f=${Package}\t${Version}\t${Maintainer}\n"])
        .output()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut programs = Vec::new();
    
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 2 {
            programs.push(InstalledProgram {
                name: parts[0].to_string(),
                version: Some(parts[1].to_string()),
                publisher: parts.get(2).map(|s| s.to_string()),
                install_date: None, // dpkg doesn't easily provide this
            });
        }
    }
    
    Ok(programs)
}

fn get_rpm_packages() -> Result<Vec<InstalledProgram>, Box<dyn std::error::Error>> {
    let output = Command::new("rpm")
        .args(&["-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"])
        .output()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut programs = Vec::new();
    
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 2 {
            programs.push(InstalledProgram {
                name: parts[0].to_string(),
                version: Some(parts[1].to_string()),
                publisher: parts.get(2).map(|s| s.to_string()),
                install_date: None,
            });
        }
    }
    
    Ok(programs)
}

fn get_pacman_packages() -> Result<Vec<InstalledProgram>, Box<dyn std::error::Error>> {
    let output = Command::new("pacman")
        .args(&["-Q"])
        .output()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut programs = Vec::new();
    
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            programs.push(InstalledProgram {
                name: parts[0].to_string(),
                version: Some(parts[1].to_string()),
                publisher: None, // pacman -Q doesn't provide maintainer info easily
                install_date: None,
            });
        }
    }
    
    Ok(programs)
}

fn get_snap_packages() -> Result<Vec<InstalledProgram>, Box<dyn std::error::Error>> {
    // Check if snap is installed
    if !std::path::Path::new("/usr/bin/snap").exists() {
        return Ok(Vec::new());
    }
    
    let output = Command::new("snap")
        .args(&["list"])
        .output()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut programs = Vec::new();
    
    // Skip the header line
    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            programs.push(InstalledProgram {
                name: parts[0].to_string(),
                version: Some(parts[1].to_string()),
                publisher: parts.get(3).map(|s| s.to_string()), // Publisher is usually in column 4
                install_date: None,
            });
        }
    }
    
    Ok(programs)
}

fn get_flatpak_packages() -> Result<Vec<InstalledProgram>, Box<dyn std::error::Error>> {
    // Check if flatpak is installed
    if !std::path::Path::new("/usr/bin/flatpak").exists() {
        return Ok(Vec::new());
    }
    
    let output = Command::new("flatpak")
        .args(&["list", "--app", "--columns=name,version,origin"])
        .output()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut programs = Vec::new();
    
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if !parts.is_empty() {
            programs.push(InstalledProgram {
                name: parts[0].to_string(),
                version: parts.get(1).and_then(|s| {
                    let s = s.trim();
                    if s.is_empty() { None } else { Some(s.to_string()) }
                }),
                publisher: parts.get(2).map(|s| s.to_string()),
                install_date: None,
            });
        }
    }
    
    Ok(programs)
}

fn is_debian_based() -> bool {
    std::path::Path::new("/usr/bin/dpkg").exists()
}

fn is_redhat_based() -> bool {
    std::path::Path::new("/usr/bin/rpm").exists()
}

fn is_arch_based() -> bool {
    std::path::Path::new("/usr/bin/pacman").exists()
}

// Helper function
// fn parse_os_release(content: &str, key: &str) -> Option<String> {
//     content
//         .lines()
//         .find(|line| line.starts_with(key))
//         .and_then(|line| line.split('=').nth(1))
//         .map(|val| val.trim_matches('"').to_string())
// }