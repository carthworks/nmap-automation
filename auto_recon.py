#!/usr/bin/env python3
"""
auto_recon.py — automated nmap scan + attack-suggestion helper
Requires: python3, nmap (binary in $PATH)
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

try:
    import jinja2  # pip install jinja2
except ImportError:
    print("Error: jinja2 package not found. Install with: pip install jinja2")
    sys.exit(1)

# ----------------------------------------------------------------------
# Static data
# ----------------------------------------------------------------------
ATTACK_MAP: Dict[str, Dict[str, List[str]]] = {
    "ftp": {
        "vuln": ["Anonymous login", "FTP bounce", "CVE-1999-0497"],
        "attack": ["Hydra brute-force", "Metasploit: auxiliary/scanner/ftp/ftp_login"],
    },
    "ssh": {
        "vuln": ["Weak credentials", "Shellshock (older versions)"],
        "attack": ["Hydra SSH login", "SSH key cracking", "Brute-force"],
    },
    "http": {
        "vuln": ["Directory listing", "Outdated CMS", "Insecure headers"],
        "attack": ["Nikto scan", "dirb/gobuster", "Burp Suite mapping", "Searchsploit"],
    },
    "https": {
        "vuln": ["SSL misconfig", "Self-signed certs"],
        "attack": ["sslscan", "testssl.sh", "Burp Suite (HTTPS)"],
    },
    "smb": {
        "vuln": ["Null sessions", "MS17-010 (EternalBlue)", "Open shares"],
        "attack": ["enum4linux", "Metasploit smb exploits", "smbclient"],
    },
    "mysql": {
        "vuln": ["Default creds", "Remote access without firewall"],
        "attack": ["Hydra", "sqlmap", "mysql command line"],
    },
    "rdp": {
        "vuln": ["BlueKeep (CVE-2019-0708)"],
        "attack": ["rdp brute-force", "Metasploit: exploit/windows/rdp/bluekeep"],
    },
}

# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------
logging.basicConfig(
    format="[%(asctime)s] %(levelname)s: %(message)s",
    level=logging.INFO,
    datefmt="%H:%M:%S",
)

# ----------------------------------------------------------------------
# Core logic
# ----------------------------------------------------------------------
# ------------------------------------------------------------
# 1.  run_nmap  — quick sanity check
# ------------------------------------------------------------
def run_nmap(target: str, out_stem: Path) -> Path:
    xml_file = out_stem.with_suffix(".xml")
    cmd = [
        "nmap", "-sC", "-sV", "-O", "-T4",
        "-oX", str(xml_file), target,
    ]
    logging.info("Executing: %s", " ".join(cmd))
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        logging.error("nmap failed: %s", exc.stderr)
        sys.exit(1)

    size = xml_file.stat().st_size
    logging.info("XML file size = %d bytes", size)
    if size < 200:          # heuristic: basically empty
        logging.error("XML file looks empty; nothing to parse.")
        sys.exit(1)

    return xml_file


def parse_nmap(xml_file: Path) -> List[Tuple[str, List[Dict[str, str]]]]:
    try:
        tree = ET.parse(xml_file)
    except ET.ParseError as exc:
        logging.error("Cannot parse XML: %s", exc)
        sys.exit(1)

    root = tree.getroot()
    results: List[Tuple[str, List[Dict[str, str]]]] = []

    for host in root.findall("host"):
        # Get IPv4 address
        addr_elem = host.find("address[@addrtype='ipv4']")
        addr = addr_elem.get("addr") if addr_elem is not None else "Unknown"
        
        # Get hostname
        hostname_elem = host.find("hostnames/hostname[@type='user']")
        hostname = hostname_elem.get("name") if hostname_elem is not None else ""
        
        # Get PTR record
        ptr_elem = host.find("hostnames/hostname[@type='PTR']")
        ptr_record = ptr_elem.get("name") if ptr_elem is not None else ""
        
        # Get host status and latency
        status_elem = host.find("status")
        host_status = status_elem.get("state") if status_elem is not None else "unknown"
        
        # Get timing info
        times_elem = host.find("times")
        latency = ""
        if times_elem is not None:
            srtt = times_elem.get("srtt")
            if srtt:
                latency = f"({float(srtt)/1000:.3f}s latency)"

        ports_info: List[Dict[str, str]] = []
        
        # Find ports section
        ports_elem = host.find("ports")
        if ports_elem is not None:
            # Get filtered ports count
            extraports = ports_elem.find("extraports")
            filtered_count = extraports.get("count") if extraports is not None else "0"
            
            for port in ports_elem.findall("port"):
                state_elem = port.find("state")
                if state_elem is not None and state_elem.get("state") == "open":
                    port_id = port.get("portid", "0")
                    protocol = port.get("protocol", "tcp")
                    
                    # Get service details
                    service_elem = port.find("service")
                    service = service_elem.get("name") if service_elem is not None else "unknown"
                    product = service_elem.get("product", "") if service_elem is not None else ""
                    version = service_elem.get("version", "") if service_elem is not None else ""
                    tunnel = service_elem.get("tunnel", "") if service_elem is not None else ""
                    
                    # Get script output
                    scripts = []
                    for script in port.findall("script"):
                        script_id = script.get("id", "")
                        script_output = script.get("output", "")
                        if script_output:
                            scripts.append(f"{script_id}: {script_output}")
                    
                    service_version = f"{service}"
                    if tunnel:
                        service_version = f"{tunnel}/{service}"
                    if product:
                        service_version += f" {product}"
                    if version:
                        service_version += f" {version}"

                    ports_info.append({
                        "port": f"{port_id}/{protocol}",
                        "state": "open",
                        "service": service_version,
                        "scripts": scripts,
                        "vuln": ATTACK_MAP.get(service, {}).get("vuln", ["Unknown / manual investigation"]),
                        "attack": ATTACK_MAP.get(service, {}).get("attack", ["Manual recon recommended"]),
                    })

        # Get OS detection
        os_info = []
        os_elem = host.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                name = osmatch.get("name", "")
                accuracy = osmatch.get("accuracy", "")
                if name:
                    os_info.append(f"{name} ({accuracy}% accuracy)")

        host_data = {
            "addr": addr,
            "hostname": hostname,
            "ptr_record": ptr_record,
            "status": host_status,
            "latency": latency,
            "filtered_ports": filtered_count,
            "os_info": os_info,
            "ports": ports_info
        }

        if not ports_info:
            logging.warning("Host %s — no open ports discovered", addr)

        results.append((addr, [host_data]))

    if not results:
        logging.error("No hosts found in XML. Is the target reachable?")
        sys.exit(1)

    return results

def generate_html_report(
    scan_data: List[Tuple[str, List[Dict[str, str]]]], output_file: Path
) -> None:
    """Render a Jinja2 template into a clean HTML report."""
    template_src = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Nmap Recon Report</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { padding-top: 70px; }
    .vuln { color: #d63384; }
    .attack { color: #fd7e14; }
    .script-output { font-family: monospace; font-size: 0.9em; background: #f8f9fa; padding: 0.5rem; margin: 0.25rem 0; border-radius: 0.25rem; }
  </style>
</head>
<body>
<nav class="navbar navbar-dark bg-dark fixed-top">
  <div class="container-fluid">
    <span class="navbar-brand mb-0 h1">Nmap Recon Report</span>
    <span class="text-light">Generated {{ timestamp }}</span>
  </div>
</nav>

<div class="container">
  {% for host_ip, host_data_list in scan_data %}
    {% for host_data in host_data_list %}
    <div class="card mb-4">
      <div class="card-header h5">
        Nmap scan report for 
        {% if host_data.hostname %}{{ host_data.hostname }} ({{ host_data.addr }}){% else %}{{ host_data.addr }}{% endif %}
      </div>
      <div class="card-body">
        <p><strong>Host is {{ host_data.status }}</strong> {{ host_data.latency }}</p>
        {% if host_data.ptr_record %}
        <p><strong>rDNS record:</strong> {{ host_data.ptr_record }}</p>
        {% endif %}
        {% if host_data.filtered_ports and host_data.filtered_ports != "0" %}
        <p><strong>Not shown:</strong> {{ host_data.filtered_ports }} filtered tcp ports</p>
        {% endif %}
        
        {% if host_data.ports %}
          <h6>PORT&nbsp;&nbsp;&nbsp;&nbsp;STATE&nbsp;&nbsp;SERVICE&nbsp;&nbsp;&nbsp;VERSION</h6>
          {% for p in host_data.ports %}
            <div class="mb-3 border-start border-primary ps-3">
              <strong>{{ p.port }}</strong>&nbsp;&nbsp;{{ p.state }}&nbsp;&nbsp;<span class="text-primary">{{ p.service }}</span>
              {% if p.scripts %}
                {% for script in p.scripts %}
                <div class="script-output">{{ script }}</div>
                {% endfor %}
              {% endif %}
              <div class="mt-2">
                <div class="vuln"><strong>Possible Vulnerabilities:</strong>
                  <ul>
                    {% for v in p.vuln %}
                      <li>{{ v }}</li>
                    {% endfor %}
                  </ul>
                </div>
                <div class="attack"><strong>Suggested Attacks:</strong>
                  <ul>
                    {% for a in p.attack %}
                      <li>{{ a }}</li>
                    {% endfor %}
                  </ul>
                </div>
              </div>
            </div>
          {% endfor %}
        {% else %}
          <p>No open ports found.</p>
        {% endif %}
        
        {% if host_data.os_info %}
        <div class="mt-3">
          <h6>OS Detection:</h6>
          {% for os in host_data.os_info %}
          <p>{{ os }}</p>
          {% endfor %}
        </div>
        {% endif %}
      </div>
    </div>
    {% endfor %}
  {% endfor %}
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
    """
    env = jinja2.Environment()
    html = env.from_string(template_src).render(
        scan_data=scan_data,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    output_file.write_text(html, encoding="utf-8")
    logging.info("HTML report saved to %s", output_file)


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def cli() -> None:
    parser = argparse.ArgumentParser(description="Auto Recon + Attack suggestion tool")
    parser.add_argument("target", help="IP address or CIDR, e.g. 192.168.1.0/24")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path(f"report_{datetime.now():%Y%m%d_%H%M%S}"),
        help="Output file stem (no extension)",
    )
    args = parser.parse_args()

    xml_path = run_nmap(args.target, args.output)
    scan_data = parse_nmap(xml_path)
    generate_html_report(scan_data, args.output.with_suffix(".html"))


if __name__ == "__main__":
    cli()
