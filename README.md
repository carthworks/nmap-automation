# nmap-automation

An automated nmap reconnaissance tool that performs network scanning and generates detailed HTML reports with attack suggestions.

## Features

- **Automated nmap scanning** with service detection and OS fingerprinting
- **HTML report generation** with Bootstrap styling for professional presentation
- **Attack suggestions** based on discovered services and vulnerabilities
- **Comprehensive data extraction** including:
  - Open ports and services
  - Service versions and banners
  - Script output (SSL certificates, HTTP headers, etc.)
  - OS detection results
  - rDNS/PTR records
  - Timing and latency information

## Requirements

- Python 3.7+
- nmap (must be in system PATH)
- jinja2 package

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd nmap-automation
```

2. Install Python dependencies:
```bash
pip install jinja2
```

3. Ensure nmap is installed and accessible:
```bash
nmap --version
```

## Usage

### Basic Usage

```bash
python auto_recon.py <target>
```

### Examples

```bash
# Scan a single IP
python auto_recon.py 192.168.1.1

# Scan a domain
python auto_recon.py www.example.com

# Scan a network range
python auto_recon.py 192.168.1.0/24

# Custom output filename
python auto_recon.py 192.168.1.1 -o my_scan_report
```

### Command Line Options

- `target` - IP address, domain, or CIDR range to scan
- `-o, --output` - Output file stem (default: `report_YYYYMMDD_HHMMSS`)

## Output Files

The tool generates two files:
- `<output>.xml` - Raw nmap XML output
- `<output>.html` - Formatted HTML report with attack suggestions

## Attack Mapping

The tool includes built-in attack suggestions for common services:

| Service | Vulnerabilities | Attack Methods |
|---------|----------------|----------------|
| FTP | Anonymous login, FTP bounce | Hydra brute-force, Metasploit |
| SSH | Weak credentials, Shellshock | SSH key cracking, Brute-force |
| HTTP/HTTPS | Directory listing, Outdated CMS | Nikto, dirb/gobuster, Burp Suite |
| SMB | Null sessions, MS17-010 | enum4linux, smbclient |
| MySQL | Default credentials | Hydra, sqlmap |
| RDP | BlueKeep (CVE-2019-0708) | RDP brute-force, Metasploit |

## Sample Output

The HTML report includes:
- Host information (IP, hostname, status, latency)
- rDNS records
- Open ports with service details
- Script output (certificates, headers, etc.)
- Vulnerability assessments
- Attack recommendations
- OS detection results

## Troubleshooting

### Common Issues

1. **"nmap failed: Assertion failed"** (Windows)
   - This is a known issue with nmap 7.96/7.97 on Windows
   - The tool automatically handles this by avoiding problematic script options

2. **"jinja2 package not found"**
   ```bash
   pip install jinja2
   ```

3. **"nmap: command not found"**
   - Install nmap and ensure it's in your system PATH
   - Windows: Download from https://nmap.org/download.html
   - Linux: `sudo apt install nmap` or `sudo yum install nmap`

### XML Parsing Issues

If you encounter XML parsing errors, check:
- Target is reachable
- nmap completed successfully
- XML file is not empty or corrupted

## Security Notice

This tool is intended for:
- **Authorized penetration testing**
- **Security assessments of your own networks**
- **Educational purposes**

**Do not use this tool against systems you do not own or have explicit permission to test.**

## License

This project is provided as-is for educational and authorized security testing purposes.

## Contributing

Feel free to submit issues and enhancement requests!
<<<<<<< HEAD
=======
<img width="886" height="1316" alt="image" src="https://github.com/user-attachments/assets/b981a009-986d-4c47-9391-aa5fb2bb6bc2" />

>>>>>>> aa89bcacaba4e2781c4a4b5dd13d3b943ed23eeb

