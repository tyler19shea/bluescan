mod windows;
mod nvd_query;

use colored::*;
// use windows::os_info::get_os_info;
use windows::installed_programs::get_installed_programs;
use std::env::args;

use crate::windows::installed_programs::InstalledProgram;

#[tokio::main]
async fn main() -> anyhow::Result<()>{
    let args: Vec<String> = args().collect();
    let programs = get_installed_programs()?;

    println!("{}", "=== BlueScan-AI (Windows Edition) ===".blue().bold());
    if args.len() < 2 {
        println!("Usuage is bluescan_ai <option> (i.e. 'bluescan_ai.exe -o)")
    } else if args.len() < 5 {
        if args.contains(&"-o".to_string()) {
            println!("{}", windows::os_info::get_os_info());
        } if args.contains(&"-p".to_string()) {
            println!("{}: {}", "Installed Programs".green(), programs.len());
        } if args.contains(&"-a".to_string()) {
            for p in &programs {
                println!("{} - {}", p.name.purple(), p.version.clone().unwrap_or("N/A".into()));
            }
        } if args.contains(&"-s".to_string()) {
            for p in &programs {
                get_vulns(p).await?;
            }
        }
        
    } else {
        println!("Too many arguments")
    }

    Ok(())
}

async fn get_vulns(program: &InstalledProgram) -> anyhow::Result<()> {
    let version = program.version.clone().unwrap_or("".into());
    let query = format!("{} {}", program.name, version);
    let vuln = nvd_query::search_vulns_nvd(&query).await?;
    if vuln.is_empty() {
        println!("No known vulnerabilities for {} {}", program.name, program.version.clone().unwrap_or("N/A".into()))
    } else {
        println!("Vulnerabilities for {} {:?}:", program.name, program.version);
        for v in vuln {
            println!("  - {}", v);
        }
    }
    Ok(())
}