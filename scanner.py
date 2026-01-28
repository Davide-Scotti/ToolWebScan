#!/usr/bin/env python3
"""
Simple Security Scanner - Core scanning functionality
"""

import subprocess
import json
import time
from datetime import datetime
from pathlib import Path

class SimpleScanner:
    def __init__(self):
        self.scan_results = []
        self.output_dir = Path("scan_results")
        self.output_dir.mkdir(exist_ok=True)
    
    def run_nmap_scan(self, target_url):
        """Run basic nmap scan"""
        print(f"🔍 Running Nmap scan on {target_url}")
        
        try:
            # Extract hostname from URL
            if "://" in target_url:
                hostname = target_url.split("://")[1].split("/")[0]
            else:
                hostname = target_url
            
            cmd = ["nmap", "-sV", "--script=vuln", "-oX", "-", hostname]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                return {
                    "tool": "nmap",
                    "status": "completed",
                    "output": result.stdout[:1000] + "..." if len(result.stdout) > 1000 else result.stdout
                }
        except Exception as e:
            return {"tool": "nmap", "status": "failed", "error": str(e)}
    
    def run_nikto_scan(self, target_url):
        """Run Nikto scan"""
        print(f"🔍 Running Nikto scan on {target_url}")
        
        try:
            cmd = ["nikto", "-h", target_url, "-Format", "txt"]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return {
                "tool": "nikto",
                "status": "completed",
                "output": result.stdout
            }
        except Exception as e:
            return {"tool": "nikto", "status": "failed", "error": str(e)}
    
    def run_whatweb_scan(self, target_url):
        """Run WhatWeb scan"""
        print(f"🔍 Running WhatWeb scan on {target_url}")
        
        try:
            cmd = ["whatweb", target_url, "--color=never"]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            return {
                "tool": "whatweb",
                "status": "completed",
                "output": result.stdout
            }
        except Exception as e:
            return {"tool": "whatweb", "status": "failed", "error": str(e)}
    
    def run_dirb_scan(self, target_url):
        """Run DIRB scan"""
        print(f"🔍 Running DIRB scan on {target_url}")
        
        try:
            cmd = ["dirb", target_url]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return {
                "tool": "dirb",
                "status": "completed",
                "output": result.stdout
            }
        except Exception as e:
            return {"tool": "dirb", "status": "failed", "error": str(e)}
    
    def run_gobuster_scan(self, target_url):
        """Run GoBuster scan"""
        print(f"🔍 Running GoBuster scan on {target_url}")
        
        try:
            # Use common wordlist
            cmd = ["gobuster", "dir", "-u", target_url, "-w", "/usr/share/wordlists/dirb/common.txt"]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return {
                "tool": "gobuster",
                "status": "completed",
                "output": result.stdout
            }
        except Exception as e:
            return {"tool": "gobuster", "status": "failed", "error": str(e)}

def scan_url(url, tools=None):
    """Main scan function"""
    if tools is None:
        tools = ["nmap", "nikto", "whatweb"]
    
    scanner = SimpleScanner()
    results = []
    
    for tool in tools:
        if tool == "nmap":
            results.append(scanner.run_nmap_scan(url))
        elif tool == "nikto":
            results.append(scanner.run_nikto_scan(url))
        elif tool == "whatweb":
            results.append(scanner.run_whatweb_scan(url))
        elif tool == "dirb":
            results.append(scanner.run_dirb_scan(url))
        elif tool == "gobuster":
            results.append(scanner.run_gobuster_scan(url))
        else:
            results.append({"tool": tool, "status": "skipped", "error": "Tool not supported"})
    
    # Save results
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = scanner.output_dir / f"scan_{scan_id}.json"
    
    result_data = {
        "scan_id": scan_id,
        "target": url,
        "start_time": datetime.now().isoformat(),
        "tools": tools,
        "results": results,
        "summary": {
            "total_tools": len(tools),
            "completed": sum(1 for r in results if r.get("status") == "completed"),
            "failed": sum(1 for r in results if r.get("status") == "failed")
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(result_data, f, indent=2)
    
    return result_data

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        url = sys.argv[1]
        tools = sys.argv[2:] if len(sys.argv) > 2 else None
        result = scan_url(url, tools)
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python scanner.py <url> [tool1 tool2 ...]")
        print("Available tools: nmap, nikto, whatweb, dirb, gobuster")