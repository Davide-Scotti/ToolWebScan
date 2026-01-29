#!/usr/bin/env python3
"""
Advanced Security Scanner Orchestrator
"""

import subprocess
import json
import sys
from datetime import datetime
from pathlib import Path
import logging
from typing import Dict
import argparse
from colorama import Fore, Style, init

init(autoreset=True)

class SecurityOrchestrator:
    def __init__(self, target_url: str, output_dir: str = "scan_results"):
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {
            "scan_id": self.scan_id,
            "target": target_url,
            "start_time": datetime.now().isoformat(),
            "tools": {},
            "vulnerabilities": [],
            "summary": {}
        }
        
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging"""
        log_file = self.output_dir / f"scan_{self.scan_id}.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def print_banner(self):
        """Print banner"""
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║   {Fore.YELLOW}🔐 ADVANCED SECURITY SCANNER ORCHESTRATOR 🔐{Fore.CYAN}        ║
║   {Fore.WHITE}Web App + Infrastructure Testing{Fore.CYAN}                      ║
╚═══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    def check_tool_availability(self) -> Dict[str, bool]:
        """Check which tools are available"""
        tools = {
            "nmap": "nmap",
            "nikto": "nikto",
            "whatweb": "whatweb",
            "testssl": "testssl.sh"
        }
        
        available = {}
        print(f"\n{Fore.CYAN}🔍 Checking tool availability...{Style.RESET_ALL}")
        
        for name, cmd in tools.items():
            try:
                result = subprocess.run(
                    ["which", cmd], 
                    capture_output=True, 
                    text=True
                )
                available[name] = result.returncode == 0
                
                if available[name]:
                    print(f"  {Fore.GREEN}✓ {name.upper()}: Available{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.YELLOW}⚠  {name.upper()}: Not found{Style.RESET_ALL}")
            except:
                available[name] = False
                print(f"  {Fore.YELLOW}⚠  {name.upper()}: Not found{Style.RESET_ALL}")
        
        return available
    
    def run_webapp_scan(self):
        """Run Web Application Scanner - PRIORITÀ MASSIMA"""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"🎯 Running Web Application Security Tests")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        try:
            from webapp_scanner import WebAppScanner
            
            scanner = WebAppScanner(self.target_url)
            vulns = scanner.scan()
            
            self.results["tools"]["webapp_scanner"] = {
                "status": "completed",
                "vulnerabilities_found": len(vulns),
                "tests": "XSS, SQLi, Path Traversal, Command Injection, SSRF, XXE"
            }
            self.results["vulnerabilities"].extend(vulns)
            
            print(f"  {Fore.GREEN}✓ Web scan completed: {len(vulns)} vulnerabilities{Style.RESET_ALL}")
            
        except ImportError:
            self.logger.error("webapp_scanner.py not found - install beautifulsoup4")
            self.results["tools"]["webapp_scanner"] = {
                "status": "failed",
                "error": "Module not found"
            }
        except Exception as e:
            self.logger.error(f"Web scan failed: {e}")
            self.results["tools"]["webapp_scanner"] = {
                "status": "failed",
                "error": str(e)
            }
    
    def run_nmap_scan(self):
        """Run Nmap port scan"""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"🔍 Running Nmap Port Scan")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        output_file = self.output_dir / f"nmap_{self.scan_id}.xml"
        
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.target_url)
            hostname = parsed.netloc or parsed.path
            
            cmd = [
                "nmap",
                "-sV",
                "--script=vuln",
                "-oX", str(output_file),
                hostname
            ]
            
            self.logger.info(f"Running Nmap: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            vulns = []
            if "VULNERABLE" in process.stdout.upper():
                vulns.append({
                    "tool": "nmap",
                    "name": "Port Vulnerability Detected",
                    "severity": "medium",
                    "description": "Nmap detected potential vulnerabilities",
                    "output": process.stdout[:500]
                })
            
            self.results["tools"]["nmap"] = {
                "status": "completed",
                "vulnerabilities_found": len(vulns),
                "output_file": str(output_file)
            }
            self.results["vulnerabilities"].extend(vulns)
            
            print(f"  {Fore.GREEN}✓ Nmap completed: {len(vulns)} issues{Style.RESET_ALL}")
            
        except subprocess.TimeoutExpired:
            self.logger.error("Nmap timeout")
        except Exception as e:
            self.logger.error(f"Nmap failed: {e}")
            self.results["tools"]["nmap"] = {"status": "failed", "error": str(e)}
    
    def run_nikto_scan(self):
        """Run Nikto"""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"🔎 Running Nikto Web Server Scan")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        output_file = self.output_dir / f"nikto_{self.scan_id}.txt"
        
        try:
            cmd = [
                "nikto",
                "-h", self.target_url,
                "-output", str(output_file),
                "-Tuning", "x"
            ]
            
            self.logger.info(f"Running Nikto: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            vulns = []
            for line in process.stdout.split('\n'):
                if '+' in line and any(kw in line.lower() for kw in ['vuln', 'error', 'issue', 'warning']):
                    vulns.append({
                        "tool": "nikto",
                        "name": "Web Server Issue",
                        "severity": "medium",
                        "description": line.strip()
                    })
            
            self.results["tools"]["nikto"] = {
                "status": "completed",
                "vulnerabilities_found": len(vulns),
                "output_file": str(output_file)
            }
            self.results["vulnerabilities"].extend(vulns)
            
            print(f"  {Fore.GREEN}✓ Nikto completed: {len(vulns)} issues{Style.RESET_ALL}")
                
        except subprocess.TimeoutExpired:
            self.logger.error("Nikto timeout")
        except Exception as e:
            self.logger.error(f"Nikto failed: {e}")
            self.results["tools"]["nikto"] = {"status": "failed", "error": str(e)}
    
    def run_whatweb_scan(self):
        """Run WhatWeb"""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"🌐 Running WhatWeb Technology Detection")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        try:
            cmd = [
                "whatweb",
                self.target_url,
                "--color=never"
            ]
            
            self.logger.info(f"Running WhatWeb: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            self.results["tools"]["whatweb"] = {
                "status": "completed",
                "output": process.stdout
            }
            
            print(f"  {Fore.GREEN}✓ WhatWeb completed{Style.RESET_ALL}")
            
        except Exception as e:
            self.logger.error(f"WhatWeb failed: {e}")
            self.results["tools"]["whatweb"] = {"status": "failed", "error": str(e)}
    
    def run_testssl_scan(self):
        """Run testssl.sh"""
        print(f"\n{Fore.YELLOW}{'='*60}")
        print(f"🔒 Running SSL/TLS Security Scan")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        output_file = self.output_dir / f"testssl_{self.scan_id}.txt"
        
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.target_url)
            hostname = parsed.netloc or parsed.path
            
            cmd = [
                "testssl.sh",
                "--warnings", "off",
                hostname
            ]
            
            self.logger.info(f"Running testssl.sh: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            vulns = []
            for line in process.stdout.split('\n'):
                if any(kw in line.upper() for kw in ['VULNERABLE', 'WEAK', 'INSECURE']):
                    vulns.append({
                        "tool": "testssl",
                        "name": "SSL/TLS Issue",
                        "severity": "high",
                        "description": line.strip()
                    })
            
            with open(output_file, 'w') as f:
                f.write(process.stdout)
            
            self.results["tools"]["testssl"] = {
                "status": "completed",
                "vulnerabilities_found": len(vulns),
                "output_file": str(output_file)
            }
            self.results["vulnerabilities"].extend(vulns)
            
            print(f"  {Fore.GREEN}✓ SSL/TLS completed: {len(vulns)} issues{Style.RESET_ALL}")
                
        except subprocess.TimeoutExpired:
            self.logger.error("testssl timeout")
        except Exception as e:
            self.logger.error(f"testssl failed: {e}")
            self.results["tools"]["testssl"] = {"status": "failed", "error": str(e)}
    
    def generate_summary(self):
        """Generate summary"""
        total_vulns = len(self.results["vulnerabilities"])
        
        severity_count = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for vuln in self.results["vulnerabilities"]:
            severity = vuln.get("severity", "medium").lower()
            if severity in severity_count:
                severity_count[severity] += 1
        
        self.results["summary"] = {
            "total_vulnerabilities": total_vulns,
            "by_severity": severity_count,
            "tools_run": len([t for t in self.results["tools"].values() if t.get("status") == "completed"]),
            "scan_duration": (datetime.now() - datetime.fromisoformat(self.results["start_time"])).total_seconds()
        }
        
        self.results["end_time"] = datetime.now().isoformat()
    
    def print_summary(self):
        """Print summary"""
        summary = self.results["summary"]
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"📊 SCAN SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        print(f"\n{Fore.WHITE}Target: {self.target_url}{Style.RESET_ALL}")
        print(f"Scan ID: {self.scan_id}")
        print(f"Duration: {summary['scan_duration']:.2f}s")
        print(f"Tools: {summary['tools_run']}")
        
        print(f"\n{Fore.WHITE}Vulnerabilities:{Style.RESET_ALL}")
        print(f"  {Fore.RED}🔴 Critical: {summary['by_severity']['critical']}{Style.RESET_ALL}")
        print(f"  {Fore.RED}🟠 High: {summary['by_severity']['high']}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}🟡 Medium: {summary['by_severity']['medium']}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}🟢 Low: {summary['by_severity']['low']}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Total: {summary['total_vulnerabilities']}{Style.RESET_ALL}")
        
        print(f"\n{Fore.WHITE}Report: {self.output_dir}/summary_{self.scan_id}.json{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    def save_results(self):
        """Save results"""
        output_file = self.output_dir / f"summary_{self.scan_id}.json"
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.logger.info(f"Results saved to {output_file}")
    
    def run_full_scan(self):
        """Run ALL scans"""
        self.print_banner()
        
        print(f"\n{Fore.CYAN}🎯 Target: {self.target_url}{Style.RESET_ALL}")
        print(f"🆔 Scan ID: {self.scan_id}\n")
        
        # 1. WEB APP SCANNER (PRIORITÀ MASSIMA)
        self.run_webapp_scan()
        
        # 2. INFRASTRUCTURE TOOLS
        available_tools = self.check_tool_availability()
        
        if available_tools.get("nmap"):
            self.run_nmap_scan()
        
        if available_tools.get("nikto"):
            self.run_nikto_scan()
        
        if available_tools.get("whatweb"):
            self.run_whatweb_scan()
        
        if available_tools.get("testssl"):
            self.run_testssl_scan()
        
        # 3. SUMMARY
        self.generate_summary()
        self.save_results()
        self.print_summary()


def main():
    parser = argparse.ArgumentParser(description="Advanced Security Scanner")
    parser.add_argument('url', help='Target URL')
    parser.add_argument('-o', '--output', default='scan_results', help='Output dir')
    parser.add_argument('-y', '--yes', '--non-interactive', 
                       action='store_true',
                       dest='non_interactive',
                       help='Skip authorization prompt')
    
    args = parser.parse_args()
    
    if not args.non_interactive:
        print(f"\n{Fore.RED}⚠️  SECURITY NOTICE{Style.RESET_ALL}")
        print(f"Target: {args.url}")
        print("Only scan systems you own or have authorization!")
        
        consent = input(f"\n{Fore.GREEN}Continue? (yes/NO): {Style.RESET_ALL}")
        if consent.lower() != 'yes':
            print("Cancelled.")
            sys.exit(0)
    else:
        print(f"{Fore.YELLOW}⚠️  Non-interactive mode{Style.RESET_ALL}\n")
    
    orchestrator = SecurityOrchestrator(args.url, args.output)
    orchestrator.run_full_scan()


if __name__ == "__main__":
    main()