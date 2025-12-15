# BlueScan

BlueScan is a cross-platform command-line tool written in Rust that identifies installed programs on your system and scans them for known vulnerabilities. It leverages both the National Vulnerability Database (NVD) and the Open Source Vulnerability (OSV) database to provide comprehensive security scanning.

## Features

- **Cross-Platform:** Works on **Windows**, **Linux**, and **macOS**.
- **Application Scanning:** Detects installed applications to analyze.
- **Dual Vulnerability Sources:**
    - **NVD Scan:** Scans against the NIST National Vulnerability Database. This is thorough but subject to strict rate limits.
    - **OSV Scan:** Scans against the Open Source Vulnerability database. This is much faster and has no rate limits, ideal for open-source packages.
- **Hybrid Scan:** A recommended mode that provides the best of both worlds. It queries the fast OSV API first and then falls back to the NVD for any programs not found in OSV's ecosystems.
- **System Information:** Displays basic OS and hardware details.

## Building from Source

Ensure you have Rust and Cargo installed. You can get them from [rustup.rs](https://rustup.rs/).

1.  **Clone the repository:**
    ```sh
    git clone <repository-url>
    cd bluescan
    ```

2.  **Build the project:**
    ```sh
    cargo build --release
    ```

The final executable will be located at `./target/release/bluescan`.

## Usage

Run the executable with one of the following options:

```
Usage: bluescan <option>

Options:
  -o  Show OS information
  -p  Show number of installed programs
  -a  Show all installed programs
  -s  Scan for vulnerabilities (NVD)
  -v  Scan for vulnerabilities (OSV - faster, no rate limits)
  -h  HYBRID scan: OSV first, NVD fallback (RECOMMENDED)
```

### Example

To run the recommended hybrid scan:

```sh
./target/release/bluescan -h
```

In addition to console output, a detailed log of the scan process, including all checks and findings, is written to `bluescan.log` in the project root directory.
