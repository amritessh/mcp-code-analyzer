#!/usr/bin/env python3
"""
Comprehensive test script for MCP Code Analyzer enhancements.
This script tests all the new features we've implemented.
"""

import asyncio
import subprocess
import sys
import os
import json
from pathlib import Path
from datetime import datetime

def run_command(cmd, description, check_output=False):
    """Run a CLI command and return the result."""
    print(f"\n{'='*60}")
    print(f"🧪 Testing: {description}")
    print(f"Command: {cmd}")
    print(f"{'='*60}")
    
    try:
        if check_output:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=os.getcwd())
            print(f"Exit Code: {result.returncode}")
            if result.stdout:
                print("Output:")
                print(result.stdout[:1000] + "..." if len(result.stdout) > 1000 else result.stdout)
            if result.stderr:
                print("Errors:")
                print(result.stderr[:500] + "..." if len(result.stderr) > 500 else result.stderr)
            return result.returncode == 0
        else:
            result = subprocess.run(cmd, shell=True, cwd=os.getcwd())
            return result.returncode == 0
    except Exception as e:
        print(f"❌ Error running command: {e}")
        return False

def test_basic_functionality():
    """Test basic CLI functionality."""
    print("\n🚀 Testing Basic Functionality")
    print("="*50)
    
    # Test help command
    success = run_command("python run_cli.py --help", "Help command", check_output=True)
    if not success:
        print("❌ Basic help command failed")
        return False
    
    # Test analyze-project command
    success = run_command("python run_cli.py analyze-project . --format console", "Project analysis")
    if not success:
        print("❌ Project analysis failed")
        return False
    
    return True

def test_enhanced_reporting():
    """Test enhanced reporting features."""
    print("\n📊 Testing Enhanced Reporting")
    print("="*50)
    
    # Test HTML report generation
    success = run_command("python run_cli.py generate-report . --format html --type detailed", "HTML report generation")
    if not success:
        print("❌ HTML report generation failed")
        return False
    
    # Test Markdown report generation
    success = run_command("python run_cli.py generate-report . --format markdown --type executive", "Markdown report generation")
    if not success:
        print("❌ Markdown report generation failed")
        return False
    
    # Test JSON report generation
    success = run_command("python run_cli.py generate-report . --format json --type detailed", "JSON report generation")
    if not success:
        print("❌ JSON report generation failed")
        return False
    
    # Check if reports were created
    reports = list(Path(".").glob("analysis_report_*"))
    if not reports:
        print("❌ No reports were generated")
        return False
    
    print(f"✅ Generated {len(reports)} reports:")
    for report in reports:
        print(f"  - {report.name}")
    
    return True

def test_visualization_features():
    """Test visualization and dependency analysis features."""
    print("\n📈 Testing Visualization Features")
    print("="*50)
    
    # Test dependency analysis with visualization
    success = run_command("python run_cli.py dependencies . --visualize --format text", "Dependency analysis with ASCII visualization")
    if not success:
        print("❌ Dependency analysis with visualization failed")
        return False
    
    # Test Mermaid export
    success = run_command("python run_cli.py dependencies . --format mermaid --export-graph deps.mmd", "Mermaid dependency graph export")
    if not success:
        print("❌ Mermaid export failed")
        return False
    
    # Test Graphviz export
    success = run_command("python run_cli.py dependencies . --format graphviz --export-graph deps.dot", "Graphviz dependency graph export")
    if not success:
        print("❌ Graphviz export failed")
        return False
    
    # Check if graph files were created
    graph_files = list(Path(".").glob("deps.*"))
    if not graph_files:
        print("❌ No graph files were generated")
        return False
    
    print(f"✅ Generated {len(graph_files)} graph files:")
    for graph in graph_files:
        print(f"  - {graph.name}")
    
    return True

def test_ci_cd_features():
    """Test CI/CD integration features."""
    print("\n🔧 Testing CI/CD Features")
    print("="*50)
    
    # Test quality gate with lenient settings
    success = run_command("python run_cli.py quality-gate . --min-health-score 0", "Quality gate check (lenient)")
    if not success:
        print("❌ Quality gate check failed")
        return False
    
    # Test badge generation
    success = run_command("python run_cli.py generate-badge . --metric overall_health --threshold 0 --output test_badge.md", "Badge generation")
    if not success:
        print("❌ Badge generation failed")
        return False
    
    # Check if badge file was created
    if not Path("test_badge.md").exists():
        print("❌ Badge file was not created")
        return False
    
    print("✅ Badge file created: test_badge.md")
    
    return True

def test_history_and_trends():
    """Test history and trends tracking."""
    print("\n📜 Testing History and Trends")
    print("="*50)
    
    # Test show-history command
    success = run_command("python run_cli.py show-history", "Show analysis history", check_output=True)
    if not success:
        print("❌ Show history command failed")
        return False
    
    # Test show-trends command
    success = run_command("python run_cli.py show-trends", "Show trending issues", check_output=True)
    if not success:
        print("❌ Show trends command failed")
        return False
    
    return True

def test_github_integration():
    """Test GitHub repository analysis."""
    print("\n🐙 Testing GitHub Integration")
    print("="*50)
    
    # Test GitHub analysis with export
    success = run_command("python run_cli.py analyze-github https://github.com/python/cpython --export markdown", "GitHub repository analysis")
    if not success:
        print("❌ GitHub analysis failed")
        return False
    
    # Check if GitHub report was created
    github_reports = list(Path(".").glob("report_cpython_*.md"))
    if not github_reports:
        print("❌ GitHub report was not created")
        return False
    
    print(f"✅ Generated GitHub report: {github_reports[0].name}")
    
    return True

def test_configuration():
    """Test configuration file functionality."""
    print("\n⚙️ Testing Configuration")
    print("="*50)
    
    # Check if config file exists
    if not Path(".analysis-config.json").exists():
        print("❌ Configuration file not found")
        return False
    
    # Test reading config
    try:
        with open(".analysis-config.json", 'r') as f:
            config = json.load(f)
        print("✅ Configuration file loaded successfully")
        print(f"  - Analysis patterns: {len(config.get('analysis', {}).get('include_patterns', []))}")
        print(f"  - Quality gates: {len(config.get('quality_gates', {}))}")
        print(f"  - CI settings: {len(config.get('ci', {}))}")
    except Exception as e:
        print(f"❌ Error reading configuration: {e}")
        return False
    
    return True

def test_workflow_files():
    """Test CI/CD workflow files."""
    print("\n🔄 Testing Workflow Files")
    print("="*50)
    
    # Check if GitHub Actions workflow exists
    workflow_path = Path(".github/workflows/code-analysis.yml")
    if not workflow_path.exists():
        print("❌ GitHub Actions workflow not found")
        return False
    
    # Check if CI/CD documentation exists
    docs_path = Path("docs/CI-CD.md")
    if not docs_path.exists():
        print("❌ CI/CD documentation not found")
        return False
    
    print("✅ Workflow files found:")
    print(f"  - {workflow_path}")
    print(f"  - {docs_path}")
    
    return True

def cleanup_test_files():
    """Clean up test files."""
    print("\n🧹 Cleaning up test files")
    print("="*50)
    
    test_files = [
        "test_badge.md",
        "deps.mmd",
        "deps.dot"
    ]
    
    # Add report files
    test_files.extend(list(Path(".").glob("analysis_report_*")))
    test_files.extend(list(Path(".").glob("report_cpython_*")))
    
    for file_path in test_files:
        if Path(file_path).exists():
            try:
                Path(file_path).unlink()
                print(f"  - Deleted: {file_path}")
            except Exception as e:
                print(f"  - Could not delete {file_path}: {e}")

def main():
    """Run all enhancement tests."""
    print("🧪 MCP Code Analyzer - Enhancement Test Suite")
    print("="*60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Working directory: {os.getcwd()}")
    
    test_results = {}
    
    # Run all tests
    tests = [
        ("Basic Functionality", test_basic_functionality),
        ("Enhanced Reporting", test_enhanced_reporting),
        ("Visualization Features", test_visualization_features),
        ("CI/CD Features", test_ci_cd_features),
        ("History and Trends", test_history_and_trends),
        ("GitHub Integration", test_github_integration),
        ("Configuration", test_configuration),
        ("Workflow Files", test_workflow_files),
    ]
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            test_results[test_name] = result
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"\n{status} {test_name}")
        except Exception as e:
            test_results[test_name] = False
            print(f"\n❌ FAIL {test_name} - Exception: {e}")
    
    # Summary
    print("\n" + "="*60)
    print("📊 TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for result in test_results.values() if result)
    total = len(test_results)
    
    for test_name, result in test_results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All enhancements are working correctly!")
        print("🚀 MCP Code Analyzer is ready for production use!")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please check the output above.")
    
    # Cleanup
    cleanup_test_files()
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 