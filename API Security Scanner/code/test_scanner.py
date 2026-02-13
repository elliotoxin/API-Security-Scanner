"""
elliotoxin | 2026
Unit Tests for API Security Scanner
"""

import pytest
import asyncio
import json
from unittest.mock import patch, MagicMock, AsyncMock
from api_security_scanner import (
    SecurityScanner, APIEndpoint, Vulnerability, ScanResult,
    VulnerabilitySeverity, VulnerabilityType
)


class TestAPIEndpoint:
    """Test APIEndpoint class"""
    
    def test_endpoint_creation(self):
        """Test creating an API endpoint"""
        endpoint = APIEndpoint('GET', '/api/users')
        assert endpoint.method == 'GET'
        assert endpoint.path == '/api/users'
        assert endpoint.requires_auth == False
    
    def test_endpoint_with_auth(self):
        """Test endpoint with authentication requirement"""
        endpoint = APIEndpoint('POST', '/api/users', requires_auth=True)
        assert endpoint.requires_auth == True
    
    def test_endpoint_with_parameters(self):
        """Test endpoint with parameters"""
        params = {'id': 1, 'name': 'test'}
        endpoint = APIEndpoint('GET', '/api/users', parameters=params)
        assert endpoint.parameters == params
    
    def test_method_uppercase(self):
        """Test that method is converted to uppercase"""
        endpoint = APIEndpoint('post', '/api/users')
        assert endpoint.method == 'POST'


class TestVulnerability:
    """Test Vulnerability class"""
    
    def test_vulnerability_creation(self):
        """Test creating a vulnerability"""
        vuln = Vulnerability(
            type=VulnerabilityType.BROKEN_AUTH,
            severity=VulnerabilitySeverity.CRITICAL,
            endpoint='/api/users',
            method='GET',
            title='Auth Bypass',
            description='Test description',
            evidence='Test evidence',
            remediation='Test fix'
        )
        
        assert vuln.type == VulnerabilityType.BROKEN_AUTH
        assert vuln.severity == VulnerabilitySeverity.CRITICAL
        assert vuln.cvss_score == 0.0
    
    def test_vulnerability_with_cvss_score(self):
        """Test vulnerability with CVSS score"""
        vuln = Vulnerability(
            type=VulnerabilityType.INJECTION,
            severity=VulnerabilitySeverity.CRITICAL,
            endpoint='/api/search',
            method='GET',
            title='SQL Injection',
            description='Test',
            evidence='Test',
            remediation='Test',
            cvss_score=9.9
        )
        
        assert vuln.cvss_score == 9.9


class TestScanResult:
    """Test ScanResult class"""
    
    def test_scan_result_creation(self):
        """Test creating scan result"""
        result = ScanResult(
            api_url='http://localhost:3000',
            scan_start='2024-01-01T00:00:00',
            scan_end='2024-01-01T00:05:00'
        )
        
        assert result.api_url == 'http://localhost:3000'
        assert result.endpoints_tested == 0
        assert len(result.vulnerabilities) == 0
    
    def test_scan_result_to_dict(self):
        """Test converting scan result to dictionary"""
        result = ScanResult(
            api_url='http://localhost:3000',
            scan_start='2024-01-01T00:00:00',
            scan_end='2024-01-01T00:05:00',
            endpoints_tested=5,
            success_rate=100.0
        )
        
        result_dict = result.to_dict()
        
        assert result_dict['api_url'] == 'http://localhost:3000'
        assert result_dict['endpoints_tested'] == 5
        assert result_dict['success_rate'] == 100.0
        assert 'severity_breakdown' in result_dict
    
    def test_severity_breakdown(self):
        """Test severity breakdown calculation"""
        vuln1 = Vulnerability(
            type=VulnerabilityType.BROKEN_AUTH,
            severity=VulnerabilitySeverity.CRITICAL,
            endpoint='/api/users',
            method='GET',
            title='Test',
            description='Test',
            evidence='Test',
            remediation='Test'
        )
        
        vuln2 = Vulnerability(
            type=VulnerabilityType.RATE_LIMITING,
            severity=VulnerabilitySeverity.HIGH,
            endpoint='/api/data',
            method='POST',
            title='Test',
            description='Test',
            evidence='Test',
            remediation='Test'
        )
        
        result = ScanResult(
            api_url='http://localhost:3000',
            scan_start='2024-01-01T00:00:00',
            scan_end='2024-01-01T00:05:00',
            vulnerabilities=[vuln1, vuln2]
        )
        
        breakdown = result._get_severity_breakdown()
        assert breakdown['critical'] == 1
        assert breakdown['high'] == 1
        assert breakdown['medium'] == 0


class TestSecurityScanner:
    """Test SecurityScanner class"""
    
    def test_scanner_creation(self):
        """Test creating a security scanner"""
        scanner = SecurityScanner('http://localhost:3000')
        
        assert scanner.base_url == 'http://localhost:3000'
        assert scanner.timeout == 10
        assert scanner.concurrent_requests == 5
    
    def test_base_url_trailing_slash_removal(self):
        """Test that trailing slashes are removed from base URL"""
        scanner = SecurityScanner('http://localhost:3000/')
        assert scanner.base_url == 'http://localhost:3000'
    
    def test_custom_timeout(self):
        """Test custom timeout configuration"""
        scanner = SecurityScanner('http://localhost:3000', timeout=30)
        assert scanner.timeout == 30
    
    def test_custom_concurrent_requests(self):
        """Test custom concurrent requests configuration"""
        scanner = SecurityScanner('http://localhost:3000', concurrent_requests=10)
        assert scanner.concurrent_requests == 10
    
    @pytest.mark.asyncio
    async def test_scan_with_empty_endpoints(self):
        """Test scanning with empty endpoint list"""
        scanner = SecurityScanner('http://localhost:3000')
        result = await scanner.scan([])
        
        assert result.endpoints_tested == 0
        assert len(result.vulnerabilities) == 0
    
    def test_calculate_success_rate(self):
        """Test success rate calculation"""
        scanner = SecurityScanner('http://localhost:3000')
        scanner.endpoints_tested = 5
        
        endpoints = [
            APIEndpoint('GET', '/api/users'),
            APIEndpoint('POST', '/api/users'),
            APIEndpoint('GET', '/api/users/{id}'),
            APIEndpoint('PUT', '/api/users/{id}'),
            APIEndpoint('DELETE', '/api/users/{id}')
        ]
        
        success_rate = scanner._calculate_success_rate(endpoints)
        assert success_rate == 100.0
    
    def test_calculate_success_rate_partial(self):
        """Test success rate calculation with partial results"""
        scanner = SecurityScanner('http://localhost:3000')
        scanner.endpoints_tested = 3
        
        endpoints = [
            APIEndpoint('GET', '/api/users'),
            APIEndpoint('POST', '/api/users'),
            APIEndpoint('GET', '/api/users/{id}'),
            APIEndpoint('PUT', '/api/users/{id}'),
            APIEndpoint('DELETE', '/api/users/{id}')
        ]
        
        success_rate = scanner._calculate_success_rate(endpoints)
        assert success_rate == 60.0


class TestVulnerabilityTypes:
    """Test different vulnerability types"""
    
    def test_broken_auth_type(self):
        """Test broken authentication type"""
        assert VulnerabilityType.BROKEN_AUTH.value == 'broken_authentication'
    
    def test_injection_type(self):
        """Test injection type"""
        assert VulnerabilityType.INJECTION.value == 'injection'
    
    def test_rate_limiting_type(self):
        """Test rate limiting type"""
        assert VulnerabilityType.RATE_LIMITING.value == 'rate_limiting'


class TestSeverityLevels:
    """Test severity level definitions"""
    
    def test_critical_severity(self):
        """Test critical severity"""
        assert VulnerabilitySeverity.CRITICAL.value == 'critical'
    
    def test_high_severity(self):
        """Test high severity"""
        assert VulnerabilitySeverity.HIGH.value == 'high'
    
    def test_medium_severity(self):
        """Test medium severity"""
        assert VulnerabilitySeverity.MEDIUM.value == 'medium'
    
    def test_low_severity(self):
        """Test low severity"""
        assert VulnerabilitySeverity.LOW.value == 'low'
    
    def test_info_severity(self):
        """Test informational severity"""
        assert VulnerabilitySeverity.INFO.value == 'info'


def test_imports():
    """Test that all modules can be imported"""
    from api_security_scanner import (
        SecurityScanner,
        APIEndpoint,
        Vulnerability,
        ScanResult,
        VulnerabilitySeverity,
        VulnerabilityType
    )
    
    assert SecurityScanner is not None
    assert APIEndpoint is not None
    assert Vulnerability is not None
    assert ScanResult is not None
    assert VulnerabilitySeverity is not None
    assert VulnerabilityType is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
