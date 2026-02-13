"""
elliotoxin | 2026
Example API Security Scanner Requests
These examples demonstrate how to use the scanner API
"""

# Example 1: Scan a Simple E-Commerce API
ecommerce_scan = {
    "base_url": "http://api.ecommerce-example.com",
    "timeout": 15,
    "concurrent_requests": 5,
    "endpoints": [
        # Public endpoints (no auth required)
        {
            "method": "GET",
            "path": "/api/products",
            "requires_auth": False,
            "parameters": {}
        },
        {
            "method": "GET",
            "path": "/api/products/{id}",
            "requires_auth": False,
            "parameters": {}
        },
        {
            "method": "POST",
            "path": "/api/auth/register",
            "requires_auth": False,
            "parameters": {
                "email": "user@example.com",
                "password": "securepassword"
            }
        },
        {
            "method": "POST",
            "path": "/api/auth/login",
            "requires_auth": False,
            "parameters": {
                "email": "user@example.com",
                "password": "securepassword"
            }
        },
        # Protected endpoints (require authentication)
        {
            "method": "GET",
            "path": "/api/users/profile",
            "requires_auth": True,
            "parameters": {}
        },
        {
            "method": "GET",
            "path": "/api/users/{id}/orders",
            "requires_auth": True,
            "parameters": {}
        },
        {
            "method": "POST",
            "path": "/api/orders",
            "requires_auth": True,
            "parameters": {
                "product_id": 1,
                "quantity": 1
            }
        },
        {
            "method": "PUT",
            "path": "/api/users/{id}",
            "requires_auth": True,
            "parameters": {
                "name": "John Doe",
                "email": "john@example.com"
            }
        }
    ]
}

# Example 2: Scan a Healthcare API
healthcare_scan = {
    "base_url": "http://api.healthcare-example.com",
    "timeout": 20,
    "concurrent_requests": 3,
    "endpoints": [
        # Patient endpoints
        {
            "method": "GET",
            "path": "/api/v1/patients",
            "requires_auth": True,
            "parameters": {}
        },
        {
            "method": "GET",
            "path": "/api/v1/patients/{id}",
            "requires_auth": True,
            "parameters": {}
        },
        {
            "method": "POST",
            "path": "/api/v1/patients",
            "requires_auth": True,
            "parameters": {
                "name": "Patient Name",
                "dob": "1990-01-01",
                "ssn": "123-45-6789"
            }
        },
        # Appointment endpoints
        {
            "method": "GET",
            "path": "/api/v1/appointments",
            "requires_auth": True,
            "parameters": {}
        },
        {
            "method": "POST",
            "path": "/api/v1/appointments",
            "requires_auth": True,
            "parameters": {
                "patient_id": 1,
                "doctor_id": 1,
                "date": "2024-03-01T10:00:00"
            }
        },
        # Medical records
        {
            "method": "GET",
            "path": "/api/v1/records/{patient_id}",
            "requires_auth": True,
            "parameters": {}
        }
    ]
}

# Example 3: Scan a Social Media API
social_media_scan = {
    "base_url": "http://api.socialmedia-example.com",
    "timeout": 10,
    "concurrent_requests": 5,
    "endpoints": [
        # User endpoints
        {
            "method": "GET",
            "path": "/api/users/{username}",
            "requires_auth": False,
            "parameters": {}
        },
        {
            "method": "POST",
            "path": "/api/auth/signup",
            "requires_auth": False,
            "parameters": {
                "username": "newuser",
                "email": "user@example.com",
                "password": "securepassword"
            }
        },
        # Post endpoints
        {
            "method": "GET",
            "path": "/api/posts",
            "requires_auth": False,
            "parameters": {}
        },
        {
            "method": "GET",
            "path": "/api/posts/{id}",
            "requires_auth": False,
            "parameters": {}
        },
        {
            "method": "POST",
            "path": "/api/posts",
            "requires_auth": True,
            "parameters": {
                "content": "This is a test post",
                "media": []
            }
        },
        # Comments
        {
            "method": "POST",
            "path": "/api/posts/{id}/comments",
            "requires_auth": True,
            "parameters": {
                "content": "Great post!"
            }
        },
        # Likes
        {
            "method": "POST",
            "path": "/api/posts/{id}/like",
            "requires_auth": True,
            "parameters": {}
        },
        # Follow
        {
            "method": "POST",
            "path": "/api/users/{id}/follow",
            "requires_auth": True,
            "parameters": {}
        }
    ]
}

# Example 4: Scan a Banking API
banking_scan = {
    "base_url": "http://api.banking-example.com",
    "timeout": 20,
    "concurrent_requests": 3,
    "endpoints": [
        # Authentication
        {
            "method": "POST",
            "path": "/api/auth/login",
            "requires_auth": False,
            "parameters": {
                "account_number": "123456789",
                "pin": "1234"
            }
        },
        # Account endpoints
        {
            "method": "GET",
            "path": "/api/accounts",
            "requires_auth": True,
            "parameters": {}
        },
        {
            "method": "GET",
            "path": "/api/accounts/{account_id}",
            "requires_auth": True,
            "parameters": {}
        },
        {
            "method": "GET",
            "path": "/api/accounts/{account_id}/balance",
            "requires_auth": True,
            "parameters": {}
        },
        # Transaction endpoints
        {
            "method": "GET",
            "path": "/api/accounts/{account_id}/transactions",
            "requires_auth": True,
            "parameters": {}
        },
        {
            "method": "POST",
            "path": "/api/transfers",
            "requires_auth": True,
            "parameters": {
                "from_account": "123456789",
                "to_account": "987654321",
                "amount": 1000
            }
        }
    ]
}

# Example 5: Minimal Scan
minimal_scan = {
    "base_url": "http://localhost:3000",
    "endpoints": [
        {
            "method": "GET",
            "path": "/api/health",
            "requires_auth": False,
            "parameters": {}
        },
        {
            "method": "GET",
            "path": "/api/users",
            "requires_auth": True,
            "parameters": {}
        }
    ]
}

if __name__ == "__main__":
    import json
    import requests
    
    # Example usage with requests library
    SCANNER_URL = "http://localhost:5000"
    
    # Start a scan
    response = requests.post(
        f"{SCANNER_URL}/api/scan",
        json=ecommerce_scan
    )
    
    scan_result = response.json()
    print(json.dumps(scan_result, indent=2))
    
    if response.status_code == 200:
        scan_id = scan_result.get('scan_id')
        print(f"\nScan completed with ID: {scan_id}")
        print(f"Found {scan_result['data']['total_vulnerabilities']} vulnerabilities")
        
        # Get report
        report_response = requests.get(
            f"{SCANNER_URL}/api/report/{scan_id}"
        )
        report = report_response.json()
        print(json.dumps(report, indent=2))
