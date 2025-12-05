use anyhow::Result;
use serde::{Deserialize, Serialize};
use crate::windows::installed_programs::InstalledProgram;
use std::result::Result::Ok;

#[derive(Debug, Serialize)]
struct OsvQuery {
    package: Option<Package>,
    version: Option<String>,
}

#[derive(Debug, Serialize)]
struct Package {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    vulns: Vec<Vulnerability>,
}

#[derive(Debug, Deserialize)]
struct Vulnerability {
    id: String,
    summary: Option<String>,
    //details: Option<String>,
    severity: Option<Vec<Severity>>,
    //#[serde(rename = "database_specific")]
    //database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct Severity {
    #[serde(rename = "type")]
    severity_type: String,
    score: Option<String>,
}

#[derive(Debug)]
pub enum ScanResult {
    /// Found vulnerabilities (program was successfully checked)
    Vulnerable(Vec<String>),
    
    /// No vulnerabilities found (program was successfully checked)
    Safe,
    
    /// Could not check this program (not in any known ecosystem)
    Unchecked(String), // String contains reason
}

// Common ecosystems for Windows programs
const ECOSYSTEMS: &[&str] = &[
    "PyPI",
    "npm", 
    "NuGet",
    "Maven",
    "crates.io",
    "Go",
    "Packagist",
    "RubyGems",
];

/// Try multiple strategies to find vulnerabilities
pub async fn search_vulns_osv(program: &InstalledProgram) -> Result<ScanResult> {
    println!("  → Starting OSV scan for: {}", program.name);
    
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    
    let version = program.version.clone().unwrap_or_default();
    let mut checked_any_ecosystem = false;
    let mut check_likely_ecosystem: bool = false;
    
    // STRATEGY 1: Try likely ecosystems
    println!("  → Strategy 1: Trying likely ecosystems...");
    let likely_ecosystems = guess_ecosystems(&program.name);
    
    if !likely_ecosystems.is_empty() {
        println!("    Likely ecosystems: {:?}", likely_ecosystems);
        checked_any_ecosystem = true;
        check_likely_ecosystem = true;
        
        for ecosystem in &likely_ecosystems {
            println!("    Querying OSV with ecosystem: {}", ecosystem);
            if let Ok(results) = query_osv_with_ecosystem(&client, &program.name, &version, ecosystem).await {
                if !results.is_empty() {
                    println!("    ✓ Found vulnerabilities in {} ecosystem!", ecosystem);
                    return Ok(ScanResult::Vulnerable(results));
                }
            }
        }
        println!("    Checked likely ecosystems - no vulnerabilities found");
    } else {
        println!("    No likely ecosystems detected for this program");
    }
    
    // STRATEGY 2: Try all ecosystems
    println!("  → Strategy 2: Trying all ecosystems...");
    for &ecosystem in ECOSYSTEMS {
        if likely_ecosystems.contains(&ecosystem) {
            continue;
        }
        checked_any_ecosystem = true;
        
        if let Ok(results) = query_osv_with_ecosystem(&client, &program.name, &version, ecosystem).await {
            if !results.is_empty() {
                println!("    ✓ Found vulnerabilities in {} ecosystem!", ecosystem);
                return Ok(ScanResult::Vulnerable(results));
            }
        }
    }
    
    // STRATEGY 3: Try name variations
    println!("\n  → Strategy 3: Trying name variations...");
    let name_variations = get_name_variations(&program.name);
    
    for name_var in &name_variations {
        if name_var == &program.name || name_var == &program.name.to_lowercase() {
            continue;
        }
        
        for &ecosystem in ECOSYSTEMS {
            checked_any_ecosystem = true;
            
            if let Ok(results) = query_osv_with_ecosystem(&client, name_var, &version, ecosystem).await {
                if !results.is_empty() {
                    println!("    ✓ Found vulnerabilities using name '{}' in {} ecosystem!", name_var, ecosystem);
                    return Ok(ScanResult::Vulnerable(results));
                }
            }
        }
    }
    
    // DECISION POINT
    if checked_any_ecosystem && check_likely_ecosystem {
        println!("  → Program checked across ecosystems - appears safe");
        Ok(ScanResult::Safe)
    } else if checked_any_ecosystem {
        Ok(ScanResult::Unchecked(
            format!("\nProgram '{}' was checked but not able to verify ecosystem", program.name)))
    } else {
        println!("  → Could not check this program (not in any known ecosystem)");
        Ok(ScanResult::Unchecked(
            format!("Program '{}' is not in any known package ecosystem (npm, PyPI, NuGet, etc.). \
                    This is common for standalone Windows applications.", program.name)
        ))
    }
}

/// Query OSV API with specific ecosystem
async fn query_osv_with_ecosystem(
    client: &reqwest::Client,
    name: &str,
    version: &str,
    ecosystem: &str,
) -> Result<Vec<String>> {
    let url = "https://api.osv.dev/v1/query";
    
    let query = OsvQuery {
        package: Some(Package {
            name: name.to_string(),
            ecosystem: ecosystem.to_string(),
        }),
        version: if version.is_empty() {
            None
        } else {
            Some(version.to_string())
        },
    };
    
    print!("→ Sending to OSV: ecosystem='{}'::", ecosystem);

    let response = client
        .post(url)
        .json(&query)
        .send()
        .await?;
    
    if !response.status().is_success() {
        println!("      ✗ OSV returned error status: {}", response.status());
        return Ok(Vec::new());
    }

    
    let osv_response: OsvResponse = response.json().await?;
    
    if osv_response.vulns.is_empty() {
         println!("      ✓ Found {} vulnerabilities!", osv_response.vulns.len());
        return Ok(Vec::new());
    }

    println!("      ✓ Found {} vulnerabilities!", osv_response.vulns.len());
    
    let mut results = Vec::new();
    
    for vuln in osv_response.vulns {
        let summary = vuln.summary.clone().unwrap_or_else(|| "No summary available".to_string());
        let (cvss_score, severity_type) = extract_cvss_info(&vuln);
        
        let score_str = if let Some(score) = cvss_score {
            format!("CVSS Score: {} ({})", score, severity_type.unwrap_or_default())
        } else {
            "No CVSS Score available".to_string()
        };
        
        results.push(format!(
            "{} - {}\n\t{}",
            vuln.id,
            summary,
            score_str
        ));
    }
    
    Ok(results)
}

/// Extract CVSS score from vulnerability data
fn extract_cvss_info(vuln: &Vulnerability) -> (Option<String>, Option<String>) {
    if let Some(severities) = &vuln.severity {
        for severity in severities {
            if severity.severity_type.contains("CVSS") {
                return (
                    severity.score.clone(),
                    Some(severity.severity_type.clone()),
                );
            }
        }
    }
    (None, None)
}

/// Guess likely ecosystems based on program name
fn guess_ecosystems(name: &str) -> Vec<&'static str> {
    let name_lower = name.to_lowercase();
    let mut ecosystems = Vec::new();
    
    println!("    Analyzing program name: '{}'", name);
    
    // Python-related keywords
    if name_lower.contains("python") || name_lower.contains("pip") || name_lower.contains("conda") {
        println!("      → Detected Python-related keywords → PyPI");
        ecosystems.push("PyPI");
    }
    
    // Node.js-related keywords
    if name_lower.contains("node") || name_lower.contains("npm") || name_lower.contains("yarn") {
        println!("      → Detected Node.js-related keywords → npm");
        ecosystems.push("npm");
    }
    
    // .NET-related keywords
    if name_lower.contains(".net") || name_lower.contains("nuget") || name_lower.contains("dotnet") {
        println!("      → Detected .NET-related keywords → NuGet");
        ecosystems.push("NuGet");
    }
    
    // Java-related keywords
    if name_lower.contains("java") || name_lower.contains("maven") || name_lower.contains("jdk") {
        println!("      → Detected Java-related keywords → Maven");
        ecosystems.push("Maven");
    }
    
    // Rust-related keywords
    if name_lower.contains("rust") || name_lower.contains("cargo") {
        println!("      → Detected Rust-related keywords → crates.io");
        ecosystems.push("crates.io");
    }
    
    // Go-related keywords
    if name_lower.contains("golang") || name_lower.contains(" go ") {
        println!("      → Detected Go-related keywords → Go");
        ecosystems.push("Go");
    }
    
    // PHP-related keywords
    if name_lower.contains("php") || name_lower.contains("composer") {
        println!("      → Detected PHP-related keywords → Packagist");
        ecosystems.push("Packagist");
    }
    
    // Ruby-related keywords
    if name_lower.contains("ruby") || name_lower.contains("gem") {
        println!("      → Detected Ruby-related keywords → RubyGems");
        ecosystems.push("RubyGems");
    }
    
    if ecosystems.is_empty() {
        println!("      → No specific ecosystem detected");
    }
    
    ecosystems
}

/// Generate name variations to improve matching
fn get_name_variations(name: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    // Original name
    variations.push(name.to_string());
    
    // Lowercase
    variations.push(name.to_lowercase());
    
    // Remove common prefixes/suffixes
    let cleaned = name
        .to_lowercase()
        .replace(" runtime", "")
        .replace(" sdk", "")
        .replace(" framework", "")
        .replace("microsoft ", "")
        .replace(" for windows", "")
        .trim()
        .to_string();
    
    if cleaned != name.to_lowercase() {
        variations.push(cleaned.clone());
    }
    
    // Replace spaces with hyphens (common in package names)
    variations.push(name.replace(" ", "-").to_lowercase());
    
    // Remove spaces entirely
    variations.push(name.replace(" ", "").to_lowercase());
    
    // Remove version numbers from name
    let without_version = name
        .split(|c: char| c.is_numeric() || c == '.')
        .next()
        .unwrap_or(name)
        .trim()
        .to_string();
    
    if without_version != name {
        variations.push(without_version.to_lowercase());
    }
    
    // Remove duplicates
    variations.sort();
    variations.dedup();
    
    variations
}

// Possibly implementing at a later time
// Alternative: Search by keyword (useful when package name is unknown)
// pub async fn search_vulns_by_keyword(keyword: &str) -> Result<Vec<String>> {
//     let client = reqwest::Client::new();
//     let url = "https://api.osv.dev/v1/query";
    
//     // OSV doesn't have a direct keyword search, so we try common ecosystems
//     let mut all_results = Vec::new();
    
//     for &ecosystem in ECOSYSTEMS {
//         let query = OsvQuery {
//             package: Some(Package {
//                 name: keyword.to_string(),
//                 ecosystem: ecosystem.to_string(),
//             }),
//             version: None,
//         };
        
//         if let Ok(response) = client.post(url).json(&query).send().await {
//             if let Ok(osv_response) = response.json::<OsvResponse>().await {
//                 for vuln in osv_response.vulns {
//                     all_results.push(format!("{} ({})", vuln.id, ecosystem));
//                 }
//             }
//         }
//     }
    
//     Ok(all_results)
// }