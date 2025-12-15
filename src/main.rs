#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

mod nvd_query;
mod osv_query; 
mod get_os_info;

use std::{fs::{File, OpenOptions}, io::{self, Write}, result::Result::Ok};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use log::{info};
use serde::Serialize;
use simplelog::{Config, LevelFilter, WriteLogger};
use std::env::args;

#[derive(Debug, Serialize)]
pub struct InstalledProgram {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_date: Option<String>
}

#[derive(Debug, Serialize)]
pub struct OSInfo {
    pub os_name: String,
    pub version: String,
    pub hostname: String,
    pub arch: String
}

#[tokio::main]
async fn main() -> anyhow::Result<()>{
    // let _ = WriteLogger::init(LevelFilter::Info, Config::default(), File::create("bluescan.log").unwrap());
    let args: Vec<String> = args().collect();
    let programs = get_installed_programs();

    println!("{}", "=== BlueScan ===".blue().bold());
    if args.len() < 2 {
        println!("Usage: bluescan <option>");
        println!("Options:");
        println!("  -o  Show OS information");
        println!("  -p  Show number of installed programs");
        println!("  -a  Show all installed programs");
        println!("  -s  Scan for vulnerabilities (NVD)");
        println!("  -v  Scan for vulnerabilities (OSV - faster, no rate limits)");
        println!("  -h  HYBRID scan: OSV first, NVD fallback (RECOMMENDED)");
    } else if args.len() < 5 {
        if args.contains(&"-o".to_string()) {
            println!("{}", get_os_info::print_os_info());
        } if args.contains(&"-p".to_string()) {
            println!("{}: {}", "Installed Programs".green(), programs.len());
        } if args.contains(&"-a".to_string()) {
            for p in &programs {
                println!("{} - {}", p.name.purple(), p.version.clone().unwrap_or("N/A".into()));
            }
        } if args.contains(&"-s".to_string()) {
            let _ = WriteLogger::init(LevelFilter::Info, Config::default(), File::create("bluescan.log").unwrap());
            println!("{}", "Scanning with NVD (may be slow due to rate limits)...".yellow());
            get_vulns_nvd(&programs).await?;
        } if args.contains(&"-v".to_string()) {
            let _ = WriteLogger::init(LevelFilter::Info, Config::default(), File::create("bluescan.log").unwrap());
            println!("{}", "Scanning with OSV (fast, no rate limits)...".green());
            scan_with_osv(&programs).await?;
        } if args.contains(&"-h".to_string()) {
            let _ = WriteLogger::init(LevelFilter::Info, Config::default(), File::create("bluescan.log").unwrap());
            println!("{}", "HYBRID SCAN: OSV + NVD fallback (RECOMMENDED)".cyan().bold());
            hybrid_scan(&programs).await?;
        }
        
    } else {
        println!("Too many arguments")
    }

    Ok(())
}


fn get_installed_programs() -> Vec<InstalledProgram> {
    #[cfg(target_os = "linux")]
    match linux::linuxos::get_installed_programs() {
        Ok(programs) => programs,
        Err(e) => {
            eprintln!("Error getting installed programs: {}", e);
            Vec::new()
        }
    }
    #[cfg(target_os = "windows")]
    match windows::installed_programs::get_installed_programs() {
        Ok(programs) => programs,
        Err(e) => {
            eprintln!("Error getting installed programs: {}", e);
            Vec::new()
        }
    }
    #[cfg(target_os = "macos")]
    match macos::macos_programs::get_installed_programs() {
        Ok(programs) => programs,
        Err(e) => {
            eprintln!("Error getting installed programs: {}", e);
            Vec::new()
        }
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        eprintln!("Unsupported OS: This feature is only available on Windows and Linux.");
        Vec::new()
    }
 
}

async fn hybrid_scan(programs: &[InstalledProgram]) -> anyhow::Result<()> {
    let mut vulnerable_count = 0;
    let mut safe_count = 0;
    let mut nvd_checked_count = 0;
    let mut vulnerable_programs: Vec<String> = Vec::new();
    let bar = ProgressBar::new(programs.len() as u64);
    bar.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
        .unwrap()
        .progress_chars("#>-"));
    
    println!("\n{}", "Starting HYBRID vulnerability scan...".cyan().bold());
    println!("{}", "Strategy: Try OSV first (fast), fallback to NVD for unchecked programs".dimmed());
    println!("{}", "=".repeat(70).cyan());
    
    for program in programs {
        bar.inc(1);
        let version = program.version.clone().unwrap_or("unknown".into());
        
        info!("\n[{}/{}] {}", bar.position(), bar.length().unwrap(), 
                 format!("{} {}", program.name.bright_white(), version.dimmed()).bold());
        
        // STEP 1: Try OSV first (fast, no rate limits)
        match osv_query::search_vulns_osv(program).await {
            Ok(osv_query::ScanResult::Vulnerable(vulns)) => {
                info!("  {} OSV: Found {} vulnerabilities", "⚠".red(), vulns.len());
                vulnerable_count += 1;
                for v in &vulns {
                    info!("    {}", v.yellow());
                }
                continue; // Found in OSV, no need to check NVD
            }
            Ok(osv_query::ScanResult::Safe) => {
                info!("  {} OSV: Checked in package ecosystems - Safe", "✓".green());
                safe_count += 1;
                continue; // Verified safe in OSV
            }
            Ok(osv_query::ScanResult::Unchecked(_reason)) => {
                info!("  {} OSV: Not in package ecosystem", "○".dimmed());
                info!("  {} Falling back to NVD...", "→".cyan());
                // Fall through to NVD check
            }
            Err(e) => {
                info!("  {} OSV Error: {}", "✗".red(), e.to_string().dimmed());
                // Fall through to NVD check
            }
        }
        
        // STEP 2: Check NVD for programs not in OSV
        nvd_checked_count += 1;
        
        // Add delay to respect NVD rate limits (5 requests per 30 seconds)
        if nvd_checked_count > 1 {
            info!("  {} Waiting 6 seconds (NVD rate limit)...", "⏱".yellow());
            tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;
        }
        
        match check_nvd_with_timeout(program).await {
            Ok(vulns) => {
                if vulns.is_empty() {
                    info!("  {} NVD: No known vulnerabilities", "✓".green());
                    safe_count += 1;
                } else {
                    info!("  {} NVD: Found {} vulnerabilities", "⚠".red(), vulns.len());
                    vulnerable_count += 1;
                    for v in &vulns {
                        info!("    {}", v.yellow());
                    }
                    vulnerable_programs.extend(vulns);
                }
            }
            Err(e) => {
                info!("  {} NVD Error: {}", "✗".red(), e.to_string().dimmed());
            }
        }
    }
    bar.finish_with_message("Scan complete");
    match write_file(&vulnerable_programs) {
        Ok(_) => info!("Wrote vulnerable programs to vulnerable.txt"),
        Err(e) => info!("Error writing to file {}", e),
    }
    println!("\n{}", "=".repeat(70).cyan());
    println!("{}", "Scan Complete!".cyan().bold());
    println!("Total programs scanned: {}", bar.length().unwrap());
    println!("Vulnerable programs: {}", 
             if vulnerable_count > 0 { 
                 vulnerable_count.to_string().red().to_string() 
             } else { 
                 vulnerable_count.to_string().green().to_string() 
             });
    println!("Safe programs: {}", safe_count.to_string().green());
    println!("Programs checked with NVD: {}", nvd_checked_count.to_string().cyan());
    println!("Vulnerable programs:");
    for v in vulnerable_programs {
        println!("{}", v);
    }
    
    Ok(())
}

async fn check_nvd_with_timeout(program: &InstalledProgram) -> anyhow::Result<Vec<String>> {
    let version = program.version.clone().unwrap_or("".into());
    let query = format!("{} {}", program.name, version);
    
    // Add timeout to prevent hanging on NVD
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(15),
        nvd_query::search_vulns_nvd(&query)
    ).await {
        Ok(result) => result,
        Err(_) => {
            Err(anyhow::anyhow!("NVD request timed out after 15 seconds"))
        }
    }
}

async fn get_vulns_nvd(programs: &[InstalledProgram]) -> anyhow::Result<()> {
    let mut vulnerable_count = 0;
    let mut safe_count = 0;
    let mut failed_count = 0;
    let mut vulnerable_programs: Vec<String> = Vec::new();
    let bar = ProgressBar::new(programs.len() as u64);
    bar.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
        .unwrap()
        .progress_chars("#>-"));
    
    println!("\n{}", "Starting NVD vulnerability scan...".cyan().bold());
    for program in programs {
        bar.inc(1);
        tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;
        match check_nvd_with_timeout(program).await {
            Ok(vulns) => {
                if vulns.is_empty() {
                    match &program.version {
                        Some(version) => info!("  {} NVD: No known vulnerabilities of {} {:?}", "✓".green(), program.name, version),
                        None => info!("No Version found for {}", program.name),
                    }
                    safe_count += 1;
                } else {
                    info!("  {} NVD: Found {} vulnerabilities", "⚠".red(), vulns.len());
                    for v in &vulns {
                        info!("    {}", v.yellow());
                    }
                    vulnerable_programs.extend(vulns);
                    vulnerable_count += 1;
                }
            }
            Err(e) => {
                info!("  {} NVD Error: {}", "✗".red(), e.to_string().dimmed());
                failed_count += 1;
            }
        }
    }
    bar.finish_with_message("Scan complete");
    match write_file(&vulnerable_programs) {
        Ok(_) => info!("Wrote vulnerable programs to vulnerable.txt"),
        Err(e) => info!("Error writing to file {}", e),
    }
    println!("\n{}", "=".repeat(70).cyan());
    println!("{}", "Scan Complete!".cyan().bold());
    println!("Total programs scanned: {}", bar.length().unwrap());
    println!("Vulnerable programs: {}", 
             if vulnerable_count > 0 { 
                 vulnerable_count.to_string().red().to_string() 
             } else { 
                 vulnerable_count.to_string().green().to_string() 
             });
    println!("Safe programs: {}", safe_count.to_string().green());
    if failed_count != 0 {
        println!("Failed  scanned programs: {}", failed_count.to_string().red());
    }
    println!("Vulnerable programs:");
    for v in vulnerable_programs {
        println!("{}", v);
    }
    Ok(())
}

async fn scan_with_osv(programs: &[InstalledProgram]) -> anyhow::Result<()> {
    let mut vulnerable_count = 0;
    let mut safe_count = 0;
    let mut unchecked_count = 0;
    let mut unverified_count = 0;
    let mut vulnerable_programs: Vec<String> = Vec::new();
    let bar = ProgressBar::new(programs.len() as u64);
    bar.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {msg}")
        .unwrap()
        .progress_chars("#>-"));
    
    println!("\n{}", "Starting vulnerability scan...".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    
    for program in programs {
        bar.inc(1);
        let version = program.version.clone().unwrap_or("unknown".into());
        
        info!("[{}/{}] Checking {} {}... ", 
               bar.position(), bar.length().unwrap(), program.name.bright_white(), version.dimmed());
        
        match osv_query::search_vulns_osv(program).await {
            Ok(osv_query::ScanResult::Vulnerable(vulns)) => {
                info!("{} {} vulnerabilities found", "⚠".red(), vulns.len());
                vulnerable_count += 1;
                for v in &vulns {
                    info!("    {}", v.yellow());
                }
                vulnerable_programs.extend(vulns);
            }
            Ok(osv_query::ScanResult::Safe) => {
                info!("{}", "✓ Safe (checked in package ecosystems)".green());
                safe_count += 1;
            }
            Ok(osv_query::ScanResult::Unchecked(_reason)) => {
                info!("{}", _reason.yellow());
                unverified_count += 1;
                // Optionally show reason in verbose mode:
                // info!("    {}", reason.dimmed());
            }
            Err(e) => {
                info!("{} Error: {}", "✗".red(), e.to_string().dimmed());
                unchecked_count += 1;
            }
        }
        
        // Small delay to be nice to the API
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    bar.finish_with_message("Scan complete");
    match write_file(&vulnerable_programs) {
        Ok(_) => info!("Wrote vulnerable programs to vulnerable.txt"),
        Err(e) => info!("Error writing to file {}", e),
    }
    println!("\n{}", "=".repeat(60).cyan());
    println!("{}", "Scan Complete!".cyan().bold());
    println!("Total programs scanned: {}", bar.length().unwrap());
    println!("Vulnerable programs: {}", 
             if vulnerable_count > 0 { 
                 vulnerable_count.to_string().red().to_string() 
             } else { 
                 vulnerable_count.to_string().green().to_string() 
             });
    println!("Safe programs: {}", safe_count.to_string().green());
    println!("Unverified programs {}", unverified_count.to_string().yellow());
    println!("Could not check: {} (not in package ecosystems)", unchecked_count.to_string().yellow());

    println!("Vulnerable programs:");
    for v in vulnerable_programs {
        println!("{}", v);
    }
    
    // Add warning if many programs couldn't be checked
    if unverified_count > safe_count + vulnerable_count || unchecked_count > safe_count + vulnerable_count {
        println!("\n{}", "⚠ WARNING:".yellow().bold());
        println!("Some or most programs could not be verfied because they're not found in likely package ecosystems.");
        println!("OSV primarily covers open-source packages from npm, PyPI, Maven, etc.");
        println!("For comprehensive Windows application scanning, consider using NVD");
        println!("or a dedicated Windows vulnerability scanner.");
    }
    
    Ok(())
}

fn write_file(vulns: &Vec<String>) -> io::Result<()> {
    let file_path = std::path::Path::new("vulnerable.txt");
    if file_path.exists() {
        std::fs::remove_file(file_path)?;
    }
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(file_path)
        .expect("Unable to write to file");
    for v in vulns{
        file.write_all(v.as_bytes()).expect("Unable to append to file");
        file.write_all(b"\n").expect("Unable to append to file");
    }
    Ok(())
}