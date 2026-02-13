# API Security Scanner - Quick Start Guide

## 5-Minute Setup

### Step 1: Install Python (if not already installed)
```bash
# Check if Python is installed
python --version  # Should be 3.8 or higher
```

### Step 2: Clone or Download Files
Download these files to your project directory:
- `api_security_scanner.py` - Main scanner module
- `app.py` - Flask web server
- `requirements.txt` - Dependencies

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Start the Web Server
```bash
python app.py
```

You should see:
```
 * Running on http://0.0.0.0:5000
```

## Your First Scan (Using cURL)

### Run a scan on localhost API:
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "base_url": "http://localhost:3000",
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
          "username": "test",
          "password": "test"
        }
      }
    ]
  }'
```

### View Results
```bash
# Get results from scan #1
curl http://localhost:5000/api/report/1

# List all scans
curl http://localhost:5000/api/scans

# Get vulnerability statistics
curl http://localhost:5000/api/vulnerabilities/stats
```

## Using Python API

```python
import asyncio
from api_security_scanner import SecurityScanner, APIEndpoint

async def main():
    # Define endpoints to test
    endpoints = [
        APIEndpoint('GET', '/api/users', requires_auth=True),
        APIEndpoint('POST', '/api/auth/login'),
        APIEndpoint('GET', '/api/products'),
    ]
    
    # Create scanner
    scanner = SecurityScanner('http://api.example.com')
    
    # Run scan
    result = await scanner.scan(endpoints)
    
    # Print results
    print(f"Found {len(result.vulnerabilities)} vulnerabilities:")
    for v in result.vulnerabilities:
        print(f"  [{v.severity.value}] {v.title}")
        print(f"    Endpoint: {v.method} {v.endpoint}")
        print(f"    Fix: {v.remediation}\n")

# Run it
asyncio.run(main())
```

## What the Scanner Tests

| Test | What it checks | What it looks for |
|------|---|---|
| **Authentication** | Can you bypass login? | Empty tokens accepted |
| **SQL Injection** | Can you break SQL queries? | Database errors revealed |
| **Rate Limiting** | Can you spam the API? | No 429 rate limit responses |
| **Authorization** | Can you access others' data? | Access to different user IDs |
| **Security Headers** | Is the API hardened? | Missing X-Frame-Options, CSP, etc |

## Understanding Results

### Critical Vulnerabilities (Score 9.0-10.0)
🔴 **Fix immediately!**
- Example: "Empty authentication token accepted"
- Impact: Attackers can impersonate any user
- Fix: Validate all tokens before accepting requests

### High Severity (Score 7.0-8.9)
🟠 **Fix within days**
- Example: "Can access other users' data"
- Impact: Privacy breach, data exposure
- Fix: Check who owns each resource

### Medium Severity (Score 5.0-6.9)
🟡 **Fix within weeks**
- Example: "No rate limiting"
- Impact: API can be abused/DoS
- Fix: Add rate limit checks

### Low Severity (Score 3.0-4.9)
🔵 **Fix within months**
- Example: "Missing security headers"
- Impact: Minor security hardening needed
- Fix: Add security headers to responses

## Common Issues & Fixes

### "Connection refused" 
Your target API isn't running. Start it first or check the URL.

### "401 Unauthorized" on protected endpoints
The scanner isn't sending auth credentials yet. This is expected - the scanner tests if you can access protected endpoints WITHOUT proper auth.

### Scan takes forever
Reduce `concurrent_requests` (try 2-3 instead of 5).

### False positives
Some tests might trigger on your specific API. Review the evidence and whitelist if needed.

## Best Practices for Your API

1. **Always validate authentication**
   ```python
   if not request.headers.get('Authorization'):
       return 401 Unauthorized
   ```

2. **Use parameterized queries**
   ```python
   # ✓ GOOD
   cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
   
   # ✗ BAD
   cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
   ```

3. **Implement rate limiting**
   ```python
   from flask_limiter import Limiter
   limiter = Limiter(app, key_func=lambda: request.remote_addr)
   
   @limiter.limit("100 per hour")
   def my_endpoint():
       pass
   ```

4. **Add security headers**
   ```python
   response.headers['X-Content-Type-Options'] = 'nosniff'
   response.headers['X-Frame-Options'] = 'DENY'
   response.headers['Strict-Transport-Security'] = 'max-age=31536000'
   ```

5. **Check authorization for each request**
   ```python
   def get_user_data(user_id):
       current_user = get_current_user()  # From token
       if current_user.id != user_id:
           return 403 Forbidden
       return get_user(user_id)
   ```

## Next Steps

- 📖 Read the full [API_SECURITY_SCANNER_GUIDE.md](API_SECURITY_SCANNER_GUIDE.md)
- 🔗 Check [example_scans.py](example_scans.py) for more examples
- ✅ Run tests: `pytest test_scanner.py`
- 🚀 Deploy to production with confidence

## Useful Commands

```bash
# Run the web server
python app.py

# Run Python scanner directly
python api_security_scanner.py

# Run tests
pytest test_scanner.py -v

# Check health
curl http://localhost:5000/health

# View all scans in JSON
curl http://localhost:5000/api/scans | python -m json.tool
```

## Support

- 📖 Full docs: See API_SECURITY_SCANNER_GUIDE.md
- 🐛 Found a bug? Check the troubleshooting section
- 💡 Ideas? Open an issue on GitHub

---

**Happy scanning! 🔒**
