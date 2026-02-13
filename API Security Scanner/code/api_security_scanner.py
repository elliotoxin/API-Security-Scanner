"""
elliotoxin | 2026
API Security Scanner
Enterprise-grade API vulnerability scanner for testing OWASP API Top 10 vulnerabilities
"""

import json
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(Enum):
    """Types of vulnerabilities to test"""
    BROKEN_AUTH = "broken_authentication"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    EXCESSIVE_DATA_EXPOSURE = "excessive_data_exposure"
    LACK_OF_ENCRYPTION = "lack_of_encryption"
    INJECTION = "injection"
    BROKEN_OBJECT_LEVEL_AUTH = "broken_object_level_auth"
    MASS_ASSIGNMENT = "mass_assignment"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    RATE_LIMITING = "rate_limiting"
    INSUFFICIENT_LOGGING = "insufficient_logging"


@dataclass
class Vulnerability:
    """Represents a detected vulnerability"""
    type: VulnerabilityType
    severity: VulnerabilitySeverity
    endpoint: str
    method: str
    title: str
    description: str
    evidence: str
    remediation: str
    cvss_score: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ScanResult:
    """Complete scan result"""
    api_url: str
    scan_start: str
    scan_end: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    endpoints_tested: int = 0
    success_rate: float = 0.0
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'api_url': self.api_url,
            'scan_start': self.scan_start,
            'scan_end': self.scan_end,
            'endpoints_tested': self.endpoints_tested,
            'success_rate': self.success_rate,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': [asdict(v) for v in self.vulnerabilities],
            'severity_breakdown': self._get_severity_breakdown()
        }
    
    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Get vulnerability count by severity"""
        breakdown = {severity.value: 0 for severity in VulnerabilitySeverity}
        for vuln in self.vulnerabilities:
            breakdown[vuln.severity.value] += 1
        return breakdown


class APIEndpoint:
    """Represents an API endpoint to test"""
    
    def __init__(self, method: str, path: str, requires_auth: bool = False,
                 parameters: Optional[Dict] = None):
        self.method = method.upper()
        self.path = path
        self.requires_auth = requires_auth
        self.parameters = parameters or {}


class SecurityScanner:
    """Main API Security Scanner"""
    
    def __init__(self, base_url: str, timeout: int = 10, 
                 concurrent_requests: int = 5):
        """
        Initialize the security scanner
        
        Args:
            base_url: Target API base URL
            timeout: Request timeout in seconds
            concurrent_requests: Number of concurrent requests
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.concurrent_requests = concurrent_requests
        self.vulnerabilities: List[Vulnerability] = []
        self.endpoints_tested = 0
        
    async def scan(self, endpoints: List[APIEndpoint]) -> ScanResult:
        """
        Perform security scan on API endpoints
        
        Args:
            endpoints: List of API endpoints to scan
            
        Returns:
            ScanResult containing all findings
        """
        scan_start = datetime.now().isoformat()
        logger.info(f"Starting API security scan for {self.base_url}")
        
        self.vulnerabilities = []
        self.endpoints_tested = 0
        
        # Run scans concurrently
        connector = aiohttp.TCPConnector(limit=self.concurrent_requests)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [self._test_endpoint(session, endpoint) for endpoint in endpoints]
            await asyncio.gather(*tasks, return_exceptions=True)
        
        scan_end = datetime.now().isoformat()
        self.endpoints_tested = len(endpoints)
        
        result = ScanResult(
            api_url=self.base_url,
            scan_start=scan_start,
            scan_end=scan_end,
            vulnerabilities=self.vulnerabilities,
            endpoints_tested=self.endpoints_tested,
            success_rate=self._calculate_success_rate(endpoints)
        )
        
        logger.info(f"Scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
        return result
    
    async def _test_endpoint(self, session: aiohttp.ClientSession, 
                            endpoint: APIEndpoint) -> None:
        """Test a single endpoint for vulnerabilities"""
        try:
            url = f"{self.base_url}{endpoint.path}"
            
            # Test 1: Authentication bypass
            await self._test_auth_bypass(session, url, endpoint)
            
            # Test 2: SQL Injection
            await self._test_sql_injection(session, url, endpoint)
            
            # Test 3: Missing Rate Limiting
            await self._test_rate_limiting(session, url, endpoint)
            
            # Test 4: Broken Object Level Authorization
            await self._test_object_level_auth(session, url, endpoint)
            
            # Test 5: Security misconfiguration
            await self._test_security_headers(session, url, endpoint)
            
            logger.info(f"✓ Tested {endpoint.method} {endpoint.path}")
            
        except Exception as e:
            logger.error(f"Error testing {endpoint.method} {endpoint.path}: {str(e)}")
    
    async def _test_auth_bypass(self, session: aiohttp.ClientSession,
                               url: str, endpoint: APIEndpoint) -> None:
        """Test for broken authentication"""
        if not endpoint.requires_auth:
            return
        
        # Test with empty credentials
        headers = {'Authorization': ''}
        try:
            async with session.request(endpoint.method, url, headers=headers) as resp:
                if resp.status in [200, 201]:
                    self.vulnerabilities.append(Vulnerability(
                        type=VulnerabilityType.BROKEN_AUTH,
                        severity=VulnerabilitySeverity.CRITICAL,
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        title="Authentication Bypass - Empty Bearer Token",
                        description="API accepted empty authentication token",
                        evidence=f"HTTP {resp.status} response with empty Authorization header",
                        remediation="Implement proper authentication validation",
                        cvss_score=9.8
                    ))
        except Exception as e:
            logger.debug(f"Auth bypass test failed: {e}")
    
    async def _test_sql_injection(self, session: aiohttp.ClientSession,
                                 url: str, endpoint: APIEndpoint) -> None:
        """Test for SQL injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "1' UNION SELECT NULL--",
            "admin'--",
            "1'; DROP TABLE users--"
        ]
        
        for payload in payloads:
            try:
                params = {'id': payload, 'search': payload}
                async with session.request(endpoint.method, url, params=params) as resp:
                    content = await resp.text()
                    
                    # Simple detection - look for SQL errors
                    sql_indicators = ['SQL syntax', 'mysql_fetch', 'SQL error', 'ORA-']
                    if any(indicator in content for indicator in sql_indicators):
                        self.vulnerabilities.append(Vulnerability(
                            type=VulnerabilityType.INJECTION,
                            severity=VulnerabilitySeverity.CRITICAL,
                            endpoint=endpoint.path,
                            method=endpoint.method,
                            title="SQL Injection Vulnerability",
                            description="Endpoint vulnerable to SQL injection attacks",
                            evidence=f"SQL error revealed with payload: {payload}",
                            remediation="Use parameterized queries and prepared statements",
                            cvss_score=9.9
                        ))
                        break
            except Exception as e:
                logger.debug(f"SQL injection test failed: {e}")
    
    async def _test_rate_limiting(self, session: aiohttp.ClientSession,
                                 url: str, endpoint: APIEndpoint) -> None:
        """Test for lack of rate limiting"""
        # Send multiple requests rapidly
        responses = []
        try:
            for i in range(10):
                async with session.request(endpoint.method, url) as resp:
                    responses.append(resp.status)
            
            # Check if all requests succeeded (429 = rate limited, which is good)
            if all(status != 429 for status in responses):
                self.vulnerabilities.append(Vulnerability(
                    type=VulnerabilityType.RATE_LIMITING,
                    severity=VulnerabilitySeverity.HIGH,
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    title="Missing Rate Limiting",
                    description="API does not implement rate limiting",
                    evidence="Sent 10 consecutive requests without 429 responses",
                    remediation="Implement rate limiting using token bucket or similar algorithm",
                    cvss_score=7.5
                ))
        except Exception as e:
            logger.debug(f"Rate limiting test failed: {e}")
    
    async def _test_object_level_auth(self, session: aiohttp.ClientSession,
                                     url: str, endpoint: APIEndpoint) -> None:
        """Test for broken object-level authorization"""
        # Test accessing different user IDs
        test_ids = ['1', '2', '999', 'admin']
        
        for test_id in test_ids:
            try:
                test_url = url + f"/{test_id}" if '{id}' not in url else url.replace('{id}', test_id)
                async with session.request(endpoint.method, test_url) as resp:
                    if resp.status == 200:
                        # Successfully accessed different resource IDs
                        content = await resp.text()
                        if content and len(content) > 10:
                            self.vulnerabilities.append(Vulnerability(
                                type=VulnerabilityType.BROKEN_OBJECT_LEVEL_AUTH,
                                severity=VulnerabilitySeverity.HIGH,
                                endpoint=endpoint.path,
                                method=endpoint.method,
                                title="Broken Object Level Authorization",
                                description="Can access resources with different IDs without proper authorization",
                                evidence=f"Successfully accessed resource with ID: {test_id}",
                                remediation="Implement proper authorization checks for each resource",
                                cvss_score=7.1
                            ))
                            break
            except Exception as e:
                logger.debug(f"Object level auth test failed: {e}")
    
    async def _test_security_headers(self, session: aiohttp.ClientSession,
                                    url: str, endpoint: APIEndpoint) -> None:
        """Test for missing security headers"""
        required_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Strict-Transport-Security': 'max-age',
            'Content-Security-Policy': 'default-src'
        }
        
        try:
            async with session.request(endpoint.method, url) as resp:
                missing_headers = []
                for header, expected_value in required_headers.items():
                    if header not in resp.headers:
                        missing_headers.append(header)
                
                if missing_headers:
                    self.vulnerabilities.append(Vulnerability(
                        type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                        severity=VulnerabilitySeverity.MEDIUM,
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        title="Missing Security Headers",
                        description=f"Missing security headers: {', '.join(missing_headers)}",
                        evidence=f"Headers not found: {missing_headers}",
                        remediation="Add security headers to all API responses",
                        cvss_score=5.3
                    ))
        except Exception as e:
            logger.debug(f"Security headers test failed: {e}")
    
    def _calculate_success_rate(self, endpoints: List[APIEndpoint]) -> float:
        """Calculate successful endpoint tests"""
        if not endpoints:
            return 0.0
        return (self.endpoints_tested / len(endpoints)) * 100


async def main():
    """Example usage"""
    # Define endpoints to scan
    endpoints = [
        APIEndpoint('GET', '/api/users', requires_auth=True),
        APIEndpoint('GET', '/api/users/{id}', requires_auth=True),
        APIEndpoint('POST', '/api/users', requires_auth=True),
        APIEndpoint('PUT', '/api/users/{id}', requires_auth=True),
        APIEndpoint('DELETE', '/api/users/{id}', requires_auth=True),
        APIEndpoint('GET', '/api/products'),
        APIEndpoint('GET', '/api/products/{id}'),
        APIEndpoint('POST', '/api/auth/login'),
    ]
    
    # Create scanner
    scanner = SecurityScanner(
        base_url='http://localhost:3000',
        timeout=10,
        concurrent_requests=5
    )
    
    # Run scan
    result = await scanner.scan(endpoints)
    
    # Print results
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == '__main__':
    asyncio.run(main())
