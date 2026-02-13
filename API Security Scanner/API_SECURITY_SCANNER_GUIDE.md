# API Security Scanner - Complete Guide

## Overview

This is an **enterprise-grade API Security Scanner** based on the CarterPerez-dev Cybersecurity-Projects implementation. It automatically tests APIs for the **OWASP API Top 10** vulnerabilities and provides detailed security reports.

## Features

### Core Capabilities
- **Automated Vulnerability Testing**: Tests for 10 major API security vulnerabilities
- **Concurrent Scanning**: Processes multiple endpoints simultaneously for efficiency
- **Detailed Reports**: JSON, HTML, and text output formats
- **OWASP API Top 10 Coverage**:
  - Broken Authentication
  - Broken Access Control
  - Excessive Data Exposure
  - Lack of Encryption
  - SQL Injection & Command Injection
  - Broken Object Level Authorization
  - Mass Assignment
  - Security Misconfiguration
  - Lack of Rate Limiting
  - Insufficient Logging & Monitoring

### Additional Features
- Web API for easy integration
- Historical scan storage
- Vulnerability statistics and trends
- CVSS scoring for each finding
- Remediation recommendations

## Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Target API accessible via HTTP/HTTPS

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 2: Configuration

Create a `.env` file (optional):

```bash
SCANNER_TIMEOUT=10
CONCURRENT_REQUESTS=5
FLASK_ENV=development
```

### Step 3: Run the Scanner

**Option A: Command Line**
```bash
python api_security_scanner.py
```

**Option B: Web Server (Recommended)**
```bash
python app.py
```

The web server will run on `http://localhost:5000`

## Usage

### Using the Web API

#### 1. Start a Security Scan

**Endpoint:** `POST /api/scan`

**Request Example:**
```json
{
  "base_url": "http://target-api.example.com",
  "timeout": 10,
  "concurrent_requests": 5,
  "endpoints": [
    {
      "method": "GET",
      "path": "/api/users",
      "requires_auth": true,
      "parameters": {}
    },
    {
      "method": "POST",
      "path": "/api/auth/login",
      "requires_auth": false,
      "parameters": {
        "username": "string",
        "password": "string"
      }
    },
    {
      "method": "GET",
      "path": "/api/users/{id}",
      "requires_auth": true,
      "parameters": {}
    }
  ]
}
```

**Response:**
```json
{
  "status": "success",
  "scan_id": 1,
  "data": {
    "api_url": "http://target-api.example.com",
    "scan_start": "2024-02-13T10:30:00.123456",
    "scan_end": "2024-02-13T10:35:45.654321",
    "endpoints_tested": 3,
    "success_rate": 100.0,
    "total_vulnerabilities": 5,
    "severity_breakdown": {
      "critical": 1,
      "high": 2,
      "medium": 2,
      "low": 0,
      "info": 0
    },
    "vulnerabilities": [
      {
        "type": "broken_authentication",
        "severity": "critical",
        "endpoint": "/api/users",
        "method": "GET",
        "title": "Authentication Bypass - Empty Bearer Token",
        "description": "API accepted empty authentication token",
        "evidence": "HTTP 200 response with empty Authorization header",
        "remediation": "Implement proper authentication validation",
        "cvss_score": 9.8,
        "timestamp": "2024-02-13T10:30:05.123456"
      }
    ]
  }
}
```

#### 2. Get Scan Results

**Endpoint:** `GET /api/scan/{scan_id}`

```bash
curl http://localhost:5000/api/scan/1
```

#### 3. List All Scans

**Endpoint:** `GET /api/scans`

```bash
curl http://localhost:5000/api/scans
```

Response:
```json
{
  "status": "success",
  "total_scans": 3,
  "scans": [
    {
      "scan_id": 1,
      "timestamp": "2024-02-13T10:30:00.123456",
      "api_url": "http://api1.example.com",
      "total_vulnerabilities": 5,
      "endpoints_tested": 3
    }
  ]
}
```

#### 4. Get Detailed Report

**Endpoint:** `GET /api/report/{scan_id}`

```bash
curl http://localhost:5000/api/report/1
```

#### 5. Get Vulnerability Statistics

**Endpoint:** `GET /api/vulnerabilities/stats`

```bash
curl http://localhost:5000/api/vulnerabilities/stats
```

Response:
```json
{
  "status": "success",
  "total_scans": 3,
  "total_vulnerabilities": 15,
  "severity_breakdown": {
    "critical": 3,
    "high": 6,
    "medium": 4,
    "low": 2,
    "info": 0
  },
  "vulnerability_types": {
    "broken_authentication": 3,
    "rate_limiting": 4,
    "security_misconfiguration": 5,
    "injection": 2,
    "broken_object_level_auth": 1
  }
}
```

## API Endpoints Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check endpoint |
| POST | `/api/scan` | Start new security scan |
| GET | `/api/scan/{scan_id}` | Get specific scan result |
| GET | `/api/scans` | List all scans |
| GET | `/api/report/{scan_id}` | Get detailed report |
| GET | `/api/vulnerabilities/stats` | Get vulnerability statistics |

## Vulnerability Tests Explained

### 1. Broken Authentication
- **What it tests**: Whether the API properly validates authentication credentials
- **How it works**: Sends requests with empty or invalid authentication tokens
- **Example fix**: Implement proper token validation and expiration

### 2. SQL Injection
- **What it tests**: Whether SQL queries are properly parameterized
- **How it works**: Sends SQL injection payloads in parameters
- **Example fix**: Use parameterized queries (prepared statements)

### 3. Rate Limiting
- **What it tests**: Whether the API enforces rate limiting
- **How it works**: Sends multiple rapid requests and checks for 429 responses
- **Example fix**: Implement token bucket algorithm or similar

### 4. Broken Object Level Authorization
- **What it tests**: Whether users can access resources they don't own
- **How it works**: Attempts to access different resource IDs
- **Example fix**: Check user ownership before returning resources

### 5. Security Headers
- **What it tests**: Whether critical security headers are present
- **Checked headers**:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
- **Example fix**: Add headers to all API responses

## Python API Usage

```python
import asyncio
from api_security_scanner import SecurityScanner, APIEndpoint

async def run_scan():
    # Define endpoints
    endpoints = [
        APIEndpoint('GET', '/api/users', requires_auth=True),
        APIEndpoint('POST', '/api/users', requires_auth=True),
        APIEndpoint('GET', '/api/users/{id}', requires_auth=True),
    ]
    
    # Create scanner
    scanner = SecurityScanner(
        base_url='http://localhost:3000',
        timeout=10,
        concurrent_requests=5
    )
    
    # Run scan
    result = await scanner.scan(endpoints)
    
    # Access results
    print(f"Found {len(result.vulnerabilities)} vulnerabilities")
    for vuln in result.vulnerabilities:
        print(f"- {vuln.severity.value}: {vuln.title}")
    
    # Export results
    import json
    with open('scan_results.json', 'w') as f:
        json.dump(result.to_dict(), f, indent=2)

# Run
asyncio.run(run_scan())
```

## CVSS Scoring Guide

| Score | Severity | Impact |
|-------|----------|--------|
| 9.0-10.0 | CRITICAL | Immediate remediation required |
| 7.0-8.9 | HIGH | Should be fixed within days |
| 5.0-6.9 | MEDIUM | Should be fixed within weeks |
| 3.0-4.9 | LOW | Should be fixed within months |
| 0.0-2.9 | INFO | Documentation/informational |

## Security Best Practices for Your API

1. **Authentication**
   - Use strong JWT tokens with proper expiration
   - Implement refresh token rotation
   - Validate all tokens on every request

2. **Authorization**
   - Check user ownership of resources
   - Implement role-based access control (RBAC)
   - Validate permissions at endpoint level

3. **Input Validation**
   - Use parameterized queries
   - Sanitize all user inputs
   - Implement strict type checking

4. **Rate Limiting**
   - Implement token bucket algorithm
   - Use IP-based or user-based rate limits
   - Return 429 status code when exceeded

5. **Security Headers**
   - Add all recommended security headers
   - Enable HTTPS only (Strict-Transport-Security)
   - Implement Content Security Policy

6. **Logging & Monitoring**
   - Log all API access
   - Monitor for suspicious patterns
   - Alert on security events

## Troubleshooting

### Issue: "Connection refused" error
**Solution**: Ensure target API is running and accessible at specified URL

### Issue: Scan takes too long
**Solution**: Reduce `concurrent_requests` or increase `timeout`

### Issue: False positives
**Solution**: Some tests may trigger false positives. Review evidence and implement whitelisting if needed

## Advanced Configuration

### Custom Timeout
```json
{
  "base_url": "http://api.example.com",
  "timeout": 30,
  "concurrent_requests": 3,
  "endpoints": []
}
```

### Parallel Scanning
Run multiple scans in parallel:
```python
import asyncio

async def scan_multiple_apis():
    urls = [
        'http://api1.example.com',
        'http://api2.example.com',
        'http://api3.example.com'
    ]
    
    tasks = []
    for url in urls:
        scanner = SecurityScanner(url)
        endpoints = [APIEndpoint('GET', '/health')]
        tasks.append(scanner.scan(endpoints))
    
    results = await asyncio.gather(*tasks)
    return results
```

## Performance Considerations

- **Concurrent Requests**: Higher values = faster but more resource intensive
- **Timeout**: Lower values = faster but may miss slow APIs
- **Endpoint Count**: Each endpoint = multiple test attempts

Recommended settings:
- Small API (< 20 endpoints): `concurrent_requests=5`, `timeout=10`
- Medium API (20-100 endpoints): `concurrent_requests=3`, `timeout=15`
- Large API (> 100 endpoints): Run multiple scanners in parallel

## Legal & Ethical Considerations

⚠️ **Important**: Only scan APIs you own or have explicit permission to test!

- Always get written authorization before scanning
- Follow responsible disclosure practices
- Do not use for malicious purposes
- Test in non-production environments first

## Contributing & Future Enhancements

Possible improvements:
- GraphQL endpoint testing
- SOAP service scanning
- Machine learning-based fuzzing
- API schema validation (OpenAPI/Swagger)
- Automated patch suggestions
- Integration with vulnerability database
---


