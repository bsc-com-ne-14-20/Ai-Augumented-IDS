#!/usr/bin/env python3
"""
Validation script for AA-IDS setup.

Checks:
1. All required files exist
2. Rule engine loads successfully
3. Flask app can be created
4. API endpoints are registered
"""

import sys
from pathlib import Path

# Add project root to path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

def check_files():
    """Check that all required files exist."""
    print("Checking required files...")
    
    required_files = [
        "app.py",
        "config.py",
        ".env.example",
        "backend/__init__.py",
        "backend/api/routes.py",
        "backend/engines/rule_engine.py",
        "backend/engines/rules.json",
        "backend/pipeline/orchestrator.py",
        "backend/pipeline/preprocessor.py",
        "backend/sockets/events.py",
    ]
    
    missing = []
    for file_path in required_files:
        full_path = _PROJECT_ROOT / file_path
        if not full_path.exists():
            missing.append(file_path)
            print(f"  ✗ Missing: {file_path}")
        else:
            print(f"  ✓ Found: {file_path}")
    
    if missing:
        print(f"\n❌ {len(missing)} required file(s) missing!")
        return False
    
    print("\n✅ All required files present")
    return True


def check_rule_engine():
    """Check that rule engine loads successfully."""
    print("\nChecking rule engine...")
    
    try:
        from backend.engines.rule_engine import is_rule_engine_loaded, _RULES
        
        if not is_rule_engine_loaded():
            print("  ✗ Rule engine failed to load")
            return False
        
        print(f"  ✓ Rule engine loaded: {len(_RULES)} rules")
        
        # Check that rules have required fields
        for rule in _RULES:
            if "id" not in rule:
                print(f"  ✗ Rule missing 'id' field: {rule}")
                return False
        
        print("  ✓ All rules have required fields")
        return True
        
    except Exception as e:
        print(f"  ✗ Error loading rule engine: {e}")
        return False


def check_flask_app():
    """Check that Flask app can be created."""
    print("\nChecking Flask app...")
    
    try:
        from app import create_app
        
        app = create_app()
        print("  ✓ Flask app created successfully")
        
        # Check that API blueprint is registered
        blueprints = list(app.blueprints.keys())
        print(f"  ✓ Registered blueprints: {blueprints}")
        
        if "api" not in blueprints:
            print("  ✗ API blueprint not registered")
            return False
        
        print("  ✓ API blueprint registered")
        return True
        
    except Exception as e:
        print(f"  ✗ Error creating Flask app: {e}")
        import traceback
        traceback.print_exc()
        return False


def check_api_endpoints():
    """Check that API endpoints are accessible."""
    print("\nChecking API endpoints...")
    
    try:
        from app import create_app
        
        app = create_app()
        client = app.test_client()
        
        # Test health endpoint
        response = client.get("/api/v1/health")
        if response.status_code != 200:
            print(f"  ✗ Health endpoint returned {response.status_code}")
            return False
        
        print("  ✓ GET /api/v1/health returns 200")
        
        data = response.get_json()
        required_fields = ["status", "models_loaded", "db_connected"]
        for field in required_fields:
            if field not in data:
                print(f"  ✗ Health response missing field: {field}")
                return False
        
        print("  ✓ Health endpoint returns correct schema")
        return True
        
    except Exception as e:
        print(f"  ✗ Error testing API endpoints: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all validation checks."""
    print("="*60)
    print("AA-IDS Setup Validation")
    print("="*60)
    
    checks = [
        ("File Structure", check_files),
        ("Rule Engine", check_rule_engine),
        ("Flask App", check_flask_app),
        ("API Endpoints", check_api_endpoints),
    ]
    
    results = []
    for name, check_func in checks:
        try:
            result = check_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n❌ {name} check failed with exception: {e}")
            results.append((name, False))
    
    print("\n" + "="*60)
    print("Validation Summary")
    print("="*60)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}  {name}")
    
    all_passed = all(result for _, result in results)
    
    print("="*60)
    if all_passed:
        print("✅ All validation checks passed!")
        print("\nYou can now run the server with:")
        print("  python app.py")
        return 0
    else:
        print("❌ Some validation checks failed")
        print("\nPlease fix the issues above before running the server.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
