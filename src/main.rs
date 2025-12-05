mod windows;
mod nvd_query;
mod osv_query; 

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
        println!("Usage: bluescan_ai <option>");
        println!("Options:");
        println!("  -o  Show OS information");
        println!("  -p  Show number of installed programs");
        println!("  -a  Show all installed programs");
        println!("  -s  Scan for vulnerabilities (NVD)");
        println!("  -v  Scan for vulnerabilities (OSV - faster, no rate limits)");
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
            println!("{}", "Scanning with NVD (may be slow due to rate limits)...".yellow());
            for p in &programs {
                get_vulns_nvd(p).await?;
            }
        } if args.contains(&"-v".to_string()) {
            println!("{}", "Scanning with OSV (fast, no rate limits)...".green());
            scan_with_osv(&programs).await?;
        }
        
    } else {
        println!("Too many arguments")
    }

    Ok(())
}

async fn get_vulns_nvd(program: &InstalledProgram) -> anyhow::Result<()> {
    let version = program.version.clone().unwrap_or("".into());
    let query = format!("{} {}", program.name, version);
    let vuln = nvd_query::search_vulns_nvd(&query).await?;
    if vuln.is_empty() {
        println!("No known vulnerabilities for {} {}", program.name, version);
    } else {
        println!("Vulnerabilities for {} {:?}:", program.name, version);
        for v in vuln {
            println!("  - {}", v);
        }
    }
    Ok(())
}

async fn scan_with_osv(programs: &[InstalledProgram]) -> anyhow::Result<()> {
    let mut vulnerable_count = 0;
    let mut safe_count = 0;
    let mut unchecked_count = 0;
    let mut unverified_count = 0;
    let mut scanned_count = 0;
    
    println!("\n{}", "Starting vulnerability scan...".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    
    for program in programs {
        scanned_count += 1;
        let version = program.version.clone().unwrap_or("unknown".into());
        
        print!("[{}/{}] Checking {} {}... ", 
               scanned_count, programs.len(), program.name.bright_white(), version.dimmed());
        
        match osv_query::search_vulns_osv(program).await {
            Ok(osv_query::ScanResult::Vulnerable(vulns)) => {
                println!("{} {} vulnerabilities found", "⚠".red(), vulns.len());
                vulnerable_count += 1;
                for v in &vulns {
                    println!("    {}", v.yellow());
                }
            }
            Ok(osv_query::ScanResult::Safe) => {
                println!("{}", "✓ Safe (checked in package ecosystems)".green());
                safe_count += 1;
            }
            Ok(osv_query::ScanResult::Unchecked(_reason)) => {
                println!("{}", _reason.yellow());
                unverified_count += 1;
                // Optionally show reason in verbose mode:
                // println!("    {}", reason.dimmed());
            }
            Err(e) => {
                println!("{} Error: {}", "✗".red(), e.to_string().dimmed());
                unchecked_count += 1;
            }
        }
        
        // Small delay to be nice to the API
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    
    println!("\n{}", "=".repeat(60).cyan());
    println!("{}", "Scan Complete!".cyan().bold());
    println!("Total programs scanned: {}", scanned_count);
    println!("Vulnerable programs: {}", 
             if vulnerable_count > 0 { 
                 vulnerable_count.to_string().red().to_string() 
             } else { 
                 vulnerable_count.to_string().green().to_string() 
             });
    println!("Safe programs: {}", safe_count.to_string().green());
    println!("Unverified programs {}", unverified_count.to_string().yellow());
    println!("Could not check: {} (not in package ecosystems)", unchecked_count.to_string().yellow());
    
    // Add warning if many programs couldn't be checked
    if unverified_count > safe_count + vulnerable_count || unchecked_count > safe_count + vulnerable_count {
        println!("\n{}", "⚠ WARNING:".yellow().bold());
        println!("Some or most programs could not be verfied because they're not found in likely package ecosystems.");
        println!("OSV primarily covers open-source packages from npm, PyPI, Maven, etc.");
        println!("For comprehensive Windows application scanning, consider using NVD API (with API key)");
        println!("or a dedicated Windows vulnerability scanner.");
    }
    
    Ok(())
}