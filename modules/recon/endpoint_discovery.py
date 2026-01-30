#!/usr/bin/env python3
"""
Advanced Endpoint Discovery
- Crawling ricorsivo
- Estrazione endpoint da JavaScript
- Sitemap.xml, robots.txt parsing
- API endpoint detection
"""

import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import json

class EndpointDiscovery:
    def __init__(self, target_url, max_depth=3):
        self.target = target_url
        self.max_depth = max_depth
        self.discovered_endpoints = set()
        self.api_endpoints = set()
        self.js_files = set()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'SecurityScanner/2.0'})
    
    def discover_all(self):
        """Main discovery orchestrator"""
        # 1. Standard crawling
        self._crawl_recursive(self.target, depth=0)
        
        # 2. Robots.txt & Sitemap
        self._parse_robots()
        self._parse_sitemap()
        
        # 3. JavaScript analysis
        self._extract_js_endpoints()
        
        # 4. API endpoint guessing
        self._guess_api_endpoints()
        
        return {
            'endpoints': list(self.discovered_endpoints),
            'api_endpoints': list(self.api_endpoints),
            'js_files': list(self.js_files),
            'total': len(self.discovered_endpoints)
        }
    
    def _crawl_recursive(self, url, depth=0, visited=None):
        """Recursive crawler"""
        if visited is None:
            visited = set()
        
        if depth > self.max_depth or url in visited:
            return
        
        visited.add(url)
        
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all links
            for link in soup.find_all(['a', 'link'], href=True):
                href = link['href']
                absolute_url = urljoin(url, href)
                
                # Same domain only
                if urlparse(absolute_url).netloc == urlparse(self.target).netloc:
                    self.discovered_endpoints.add(absolute_url)
                    
                    # Recurse
                    if depth < self.max_depth:
                        self._crawl_recursive(absolute_url, depth + 1, visited)
            
            # Extract forms (POST endpoints)
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                form_url = urljoin(url, action)
                
                self.discovered_endpoints.add(f"{method} {form_url}")
            
            # Extract JavaScript files
            for script in soup.find_all('script', src=True):
                js_url = urljoin(url, script['src'])
                if urlparse(js_url).netloc == urlparse(self.target).netloc:
                    self.js_files.add(js_url)
        
        except Exception as e:
            pass
    
    def _parse_robots(self):
        """Parse robots.txt"""
        robots_url = urljoin(self.target, '/robots.txt')
        
        try:
            response = self.session.get(robots_url, timeout=5)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line.startswith('Disallow:') or line.startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            endpoint = urljoin(self.target, path)
                            self.discovered_endpoints.add(endpoint)
        except:
            pass
    
    def _parse_sitemap(self):
        """Parse sitemap.xml"""
        sitemap_urls = [
            urljoin(self.target, '/sitemap.xml'),
            urljoin(self.target, '/sitemap_index.xml'),
        ]
        
        for sitemap_url in sitemap_urls:
            try:
                response = self.session.get(sitemap_url, timeout=5)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'xml')
                    
                    # Extract all <loc> tags
                    for loc in soup.find_all('loc'):
                        url = loc.text.strip()
                        if urlparse(url).netloc == urlparse(self.target).netloc:
                            self.discovered_endpoints.add(url)
            except:
                pass
    
    def _extract_js_endpoints(self):
        """Extract endpoints from JavaScript files"""
        url_patterns = [
            r'["\']([/a-zA-Z0-9_\-./]+\.(?:php|asp|aspx|jsp|do|action))["\']',
            r'["\']([/a-zA-Z0-9_\-./]+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
            r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
            r'api/[a-zA-Z0-9_\-/]+'
        ]
        
        for js_url in list(self.js_files)[:10]:  # Limit to first 10 JS files
            try:
                response = self.session.get(js_url, timeout=10)
                js_content = response.text
                
                for pattern in url_patterns:
                    matches = re.findall(pattern, js_content)
                    for match in matches:
                        # Build absolute URL
                        if match.startswith('/'):
                            endpoint = urljoin(self.target, match)
                        elif match.startswith('http'):
                            endpoint = match
                        else:
                            endpoint = urljoin(js_url, match)
                        
                        # Filter same domain
                        if urlparse(endpoint).netloc == urlparse(self.target).netloc:
                            self.discovered_endpoints.add(endpoint)
                            
                            # Mark as potential API
                            if '/api/' in endpoint or endpoint.endswith('.json'):
                                self.api_endpoints.add(endpoint)
            except:
                pass
    
    def _guess_api_endpoints(self):
        """Guess common API endpoints"""
        common_api_paths = [
            '/api/v1/', '/api/v2/', '/api/',
            '/rest/', '/graphql', '/swagger.json',
            '/api/users', '/api/login', '/api/auth',
            '/api/products', '/api/items', '/api/data'
        ]
        
        for path in common_api_paths:
            api_url = urljoin(self.target, path)
            
            try:
                response = self.session.head(api_url, timeout=3, allow_redirects=False)
                if response.status_code in [200, 301, 302, 401, 403]:
                    self.api_endpoints.add(api_url)
                    self.discovered_endpoints.add(api_url)
            except:
                pass