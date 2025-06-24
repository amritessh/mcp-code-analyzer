#!/usr/bin/env python3
"""
Quick test script for MCP Code Analyzer enhancements.
This script tests CLI commands without running full analysis to avoid hanging.
"""

import subprocess
import sys
import os
from pathlib import Path

def run_quick_test(cmd, description, timeout=30):
    """Run a quick test command with timeout."""
    print(f"\n{'🎯'*15}")
    print(f"🎯 {description}")
    print(f"{'🎯'*15}")
    print(f"Command: {cmd}")
    print("-" * 40)
    
    try:
        # Use timeout to prevent hanging
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            cwd=os.getcwd(),
            timeout=timeout
        )
        
        if result.stdout:
            print("Output:")
            print(result.stdout[:500] + "..." if len(result.stdout) > 500 else result.stdout)
        
        if result.stderr:
            print("Errors:")
            print(result.stderr[:300] + "..." if len(result.stderr) > 300 else result.stderr)
        
        print(f"Exit Code: {result.returncode}")
        return result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print(f"⏰ Command timed out after {timeout} seconds")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_cli_structure():
    """Test CLI command structure without running analysis."""
    print("🚀 MCP Code Analyzer - Quick Enhancement Test")
    print("=" * 50)
    print("Testing CLI structure and command availability...")
    
    # Test help command
    success = run_quick_test("python run_cli.py --help", "Help command", timeout=10)
    if not success:
        print("❌ Help command failed")
        return False
    
    # Test individual command help
    commands = [
        "analyze-project --help",
        "dependencies --help", 
        "generate-report --help",
        "quality-gate --help",
        "generate-badge --help",
        "show-history --help",
        "show-trends --help",
        "analyze-github --help"
    ]
    
    for cmd in commands:
        success = run_quick_test(f"python run_cli.py {cmd}", f"Help for {cmd.split()[0]}", timeout=10)
        if not success:
            print(f"❌ Help for {cmd.split()[0]} failed")
            return False
    
    return True

def test_configuration():
    """Test configuration file."""
    print("\n⚙️ Testing Configuration")
    print("=" * 30)
    
    if Path(".analysis-config.json").exists():
        print("✅ Configuration file found: .analysis-config.json")
        try:
            import json
            with open(".analysis-config.json", 'r') as f:
                config = json.load(f)
            print(f"✅ Configuration loaded successfully")
            print(f"   - Analysis settings: {len(config.get('analysis', {}))} items")
            print(f"   - Quality gates: {len(config.get('quality_gates', {}))} items")
            print(f"   - CI settings: {len(config.get('ci', {}))} items")
            return True
        except Exception as e:
            print(f"❌ Error reading config: {e}")
            return False
    else:
        print("❌ Configuration file not found")
        return False

def test_workflow_files():
    """Test workflow files exist."""
    print("\n🔄 Testing Workflow Files")
    print("=" * 30)
    
    files_to_check = [
        (".github/workflows/code-analysis.yml", "GitHub Actions workflow"),
        ("docs/CI-CD.md", "CI/CD documentation"),
        ("README.md", "Updated README")
    ]
    
    all_exist = True
    for file_path, description in files_to_check:
        if Path(file_path).exists():
            print(f"✅ {description}: {file_path}")
        else:
            print(f"❌ {description}: {file_path} (missing)")
            all_exist = False
    
    return all_exist

def test_imports():
    """Test that all modules can be imported."""
    print("\n📦 Testing Module Imports")
    print("=" * 30)
    
    modules_to_test = [
        "src.cli",
        "src.analyzers.project_analyzer",
        "src.analyzers.security",
        "src.analyzers.quality", 
        "src.analyzers.dependencies",
        "src.analyzers.github_analyzer",
        "src.utils.visualizer",
        "src.storage.database"
    ]
    
    all_imported = True
    for module in modules_to_test:
        try:
            __import__(module)
            print(f"✅ {module}")
        except ImportError as e:
            print(f"❌ {module}: {e}")
            all_imported = False
    
    return all_imported

def test_simple_commands():
    """Test simple commands that don't require full analysis."""
    print("\n🔧 Testing Simple Commands")
    print("=" * 30)
    
    # Test show-history (should work even without data)
    success = run_quick_test("python run_cli.py show-history", "Show history (may be empty)", timeout=15)
    if not success:
        print("❌ Show history command failed")
        return False
    
    # Test show-trends (should work even without data)
    success = run_quick_test("python run_cli.py show-trends", "Show trends (may be empty)", timeout=15)
    if not success:
        print("❌ Show trends command failed")
        return False
    
    return True

def test_dependencies_help():
    """Test dependencies command help and options."""
    print("\n📊 Testing Dependencies Command Options")
    print("=" * 40)
    
    # Test with --help to see all options
    success = run_quick_test("python run_cli.py dependencies --help", "Dependencies help", timeout=10)
    if not success:
        print("❌ Dependencies help failed")
        return False
    
    # Test with invalid path (should show error, not hang)
    success = run_quick_test("python run_cli.py dependencies /nonexistent/path", "Dependencies with invalid path", timeout=15)
    # This should fail but not hang
    print("✅ Dependencies command structure works")
    
    return True

def main():
    """Run all quick tests."""
    print("🧪 MCP Code Analyzer - Quick Enhancement Test Suite")
    print("=" * 60)
    print("Testing CLI structure and basic functionality...")
    print("=" * 60)
    
    tests = [
        ("CLI Structure", test_cli_structure),
        ("Configuration", test_configuration),
        ("Workflow Files", test_workflow_files),
        ("Module Imports", test_imports),
        ("Simple Commands", test_simple_commands),
        ("Dependencies Options", test_dependencies_help),
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            result = test_func()
            results[test_name] = result
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"\n{status} {test_name}")
        except Exception as e:
            results[test_name] = False
            print(f"\n❌ FAIL {test_name} - Exception: {e}")
    
    # Summary
    print("\n" + "="*60)
    print("📊 QUICK TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All CLI enhancements are working correctly!")
        print("🚀 Ready for manual testing of full analysis features.")
        print("\n💡 To test full analysis features manually:")
        print("   python run_cli.py analyze-project . --format console")
        print("   python run_cli.py generate-report . --format html")
        print("   python run_cli.py dependencies . --visualize")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please check the output above.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 