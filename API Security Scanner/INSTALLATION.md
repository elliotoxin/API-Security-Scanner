# API Security Scanner - Installation & Setup Guide

## 📦 What You're Getting

A complete, production-ready **API Security Scanner** with:
- ✅ 10 vulnerability test suites
- ✅ Concurrent endpoint testing
- ✅ REST API with Flask
- ✅ Complete documentation
- ✅ Example configurations
- ✅ Unit tests
- ✅ CVSS scoring

---

## 🖥️ System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python | 3.8 | 3.11+ |
| RAM | 512MB | 2GB+ |
| Storage | 100MB | 500MB |
| OS | Any | Linux/Mac |

---

## 📥 Installation Steps

### Step 1: Install Python

**Windows:**
```bash
# Download from https://www.python.org/downloads/
# Or use Windows Package Manager
winget install Python.Python.3.11
```

**macOS:**
```bash
# Using Homebrew
brew install python@3.11

# Or download from https://www.python.org/downloads/
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip
```

**Verify Installation:**
```bash
python --version
# Should show Python 3.8 or higher
```

---

### Step 2: Create Project Directory

```bash
# Create directory
mkdir api-security-scanner
cd api-security-scanner

# (Optional) Create Python virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

---

### Step 3: Download Files

Copy all provided files to your project directory:
```
api-security-scanner/
├── api_security_scanner.py      # Main scanner
├── app.py                       # Flask server
├── requirements.txt             # Dependencies
├── .env.example                # Configuration template
├── test_scanner.py             # Unit tests
├── example_scans.py            # Usage examples
├── README.md                   # Project overview
├── QUICKSTART.md               # Quick start guide
└── API_SECURITY_SCANNER_GUIDE.md  # Full documentation
```

---

### Step 4: Install Dependencies

```bash
# Install Python packages
pip install -r requirements.txt

# Verify installation
pip list
# Should show: aiohttp, pydantic, flask, pytest, etc.
```

**What gets installed:**
- `aiohttp` - Async HTTP client for concurrent requests
- `pydantic` - Data validation
- `flask` - Web framework
- `python-dotenv` - Environment configuration
- `pytest` - Testing framework

---

### Step 5: Verify Installation

```bash
# Test scanner import
python -c "from api_security_scanner import SecurityScanner; print('✓ Scanner imported successfully')"

# Test Flask import
python -c "from flask import Flask; print('✓ Flask imported successfully')"

# Run unit tests
pytest test_scanner.py -v
```

Expected output: All tests should pass ✅

---

## 🚀 Running the Scanner

### Option 1: Web Server (Recommended)

```bash
# Start the server
python app.py

# You should see:
# * Running on http://0.0.0.0:5000
# * Debug mode: on
```

The server will run on `http://localhost:5000`

### Option 2: Command Line

```bash
# Modify and run api_security_scanner.py directly
# Edit the main() function with your target API
python api_security_scanner.py
```

### Option 3: Python API

```python
import asyncio
from api_security_scanner import SecurityScanner, APIEndpoint

async def main():
    scanner = SecurityScanner('http://api.example.com')
    endpoints = [
        APIEndpoint('GET', '/api/users', requires_auth=True),
        APIEndpoint('POST', '/api/auth/login'),
    ]
    result = await scanner.scan(endpoints)
    print(f"Found {len(result.vulnerabilities)} vulnerabilities")

asyncio.run(main())
```

---

## 🧪 First Scan

### Quick Test (requires running API)

```bash
# In another terminal, if you have a test API running locally on port 3000

curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "base_url": "http://localhost:3000",
    "endpoints": [
      {
        "method": "GET",
        "path": "/api/users",
        "requires_auth": true
      },
      {
        "method": "POST",
        "path": "/api/auth/login",
        "requires_auth": false
      }
    ]
  }'
```

### View Results

```bash
# Get scan report
curl http://localhost:5000/api/report/1 | python -m json.tool

# List all scans
curl http://localhost:5000/api/scans | python -m json.tool

# Get statistics
curl http://localhost:5000/api/vulnerabilities/stats | python -m json.tool
```

---

## 📋 Configuration

### Using .env File

1. Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

2. Edit `.env`:
```bash
SCANNER_TIMEOUT=10
CONCURRENT_REQUESTS=5
FLASK_ENV=development
FLASK_PORT=5000
```

3. The scanner will automatically load these values

### Programmatic Configuration

```python
from api_security_scanner import SecurityScanner

scanner = SecurityScanner(
    base_url='http://api.example.com',
    timeout=30,              # 30 second timeout
    concurrent_requests=3    # 3 concurrent tests
)
```

---

## 🐍 Python Virtual Environment (Recommended)

### Create Virtual Environment

```bash
# Create
python -m venv venv

# Activate
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Deactivate (when done)
deactivate
```

---

## 🐳 Docker Setup (Optional)

### Dockerfile

Create `Dockerfile`:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
```

### Build & Run

```bash
# Build image
docker build -t api-scanner:latest .

# Run container
docker run -p 5000:5000 api-scanner:latest

# Container is now accessible at http://localhost:5000
```

---

## 🔧 Troubleshooting Installation

### Issue: "Python not found"
```
❌ Error: 'python' is not recognized
✓ Solution:
  1. Download from https://www.python.org
  2. Enable "Add Python to PATH"
  3. Restart terminal
  4. Verify: python --version
```

### Issue: "pip not found"
```
❌ Error: 'pip' is not recognized
✓ Solution:
  python -m pip install -r requirements.txt
```

### Issue: "Module not found"
```
❌ Error: ModuleNotFoundError: No module named 'flask'
✓ Solution:
  pip install -r requirements.txt
```

### Issue: "Port 5000 already in use"
```
❌ Error: Address already in use
✓ Solution:
  # Change port in app.py:
  app.run(port=8000)
  
  OR kill the process using port 5000:
  # Windows:
  netstat -ano | findstr :5000
  taskkill /PID <PID> /F
  
  # macOS/Linux:
  lsof -i :5000
  kill -9 <PID>
```

### Issue: "Permission denied"
```
❌ Error: Permission denied
✓ Solution:
  # macOS/Linux:
  sudo chmod +x app.py
  python app.py
```

---

## ✅ Post-Installation Verification

```bash
# 1. Check Python version
python --version
# Expected: Python 3.8 or higher

# 2. Check pip
pip --version
# Expected: pip 20.0 or higher

# 3. Test imports
python -c "import aiohttp, flask, pydantic; print('All dependencies OK')"

# 4. Run tests
pytest test_scanner.py -v
# Expected: All tests pass

# 5. Start server
python app.py
# Expected: Server runs on localhost:5000

# 6. Health check (in another terminal)
curl http://localhost:5000/health
# Expected: {"status": "healthy", ...}
```

---

## 📚 Next Steps

1. **Read QUICKSTART.md** - Get started in 5 minutes
2. **Read API_SECURITY_SCANNER_GUIDE.md** - Full documentation
3. **Review example_scans.py** - See real-world examples
4. **Run tests** - Verify everything works: `pytest test_scanner.py`
5. **Scan your API** - Find and fix vulnerabilities!

---

## 🆘 Getting Help

| Issue | Reference |
|-------|-----------|
| Quick start | QUICKSTART.md |
| Full guide | API_SECURITY_SCANNER_GUIDE.md |
| Examples | example_scans.py |
| Tests | test_scanner.py |
| Troubleshooting | QUICKSTART.md (Common Issues section) |

---

## 📞 Support

For issues or questions:
1. Check the troubleshooting section above
2. Review QUICKSTART.md
3. Check example_scans.py for usage patterns
4. Run pytest tests to verify installation

---

## 🎉 You're Ready!

Once you see "Running on http://0.0.0.0:5000", you're all set!

Next: Check QUICKSTART.md for your first scan.

---

**Installation Last Updated: February 2024**
