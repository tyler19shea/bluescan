mod os_info;
mod installed_programs;

use colored::*;
use os_info::OSInfo;
use installed_programs::get_installed_programs;
use std::env::args;

fn main() -> anyhow::Result<()>{
    let args: Vec<String> = args().collect();
    let programs = get_installed_programs()?;

    println!("{}", "=== BlueScan-AI (Windows Edition) ===".blue().bold());
    if args.len() < 2 {
        println!("Usuage is bluescan_ai <option> (i.e. 'bluescan_ai.exe -o)")
    } else if args.len() < 5 {
        if args.contains(&"-o".to_string()) {
            match OSInfo::gather() {
                Ok(info) => {
                    println!("OS: {}", info.caption.green());
                    println!("Build: {}", info.build_number);
                    println!("Version: {}", info.version);
                }
                Err(e) => {
                    eprintln!("{} {:?}", "Failed to Gather OS info:".red(), e);
                }
            }
        } if args.contains(&"-p".to_string()) {
            println!("{}: {}", "Installed Programs".green(), programs.len());
        } if args.contains(&"-a".to_string()) {
            for p in programs {
                println!("{} - {}", p.name.purple(), p.version.clone().unwrap_or("N/A".into()));
            }
        }
        
    } else {
        println!("Too many arguments")
    }

    Ok(())
}
