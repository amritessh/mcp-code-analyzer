#!/usr/bin/env python3
"""
Build script for MCP Code Analyzer package distribution
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def run_command(cmd, description):
    """Run a command and handle errors"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"Error: {e.stderr}")
        return None

def clean_build():
    """Clean previous build artifacts"""
    print("🧹 Cleaning previous build artifacts...")
    dirs_to_clean = ["build", "dist", "*.egg-info"]
    for pattern in dirs_to_clean:
        for path in Path(".").glob(pattern):
            if path.is_dir():
                shutil.rmtree(path)
                print(f"   Removed {path}")
            elif path.is_file():
                path.unlink()
                print(f"   Removed {path}")

def check_dependencies():
    """Check if required build dependencies are installed"""
    print("🔍 Checking build dependencies...")
    required_packages = ["build", "wheel", "twine"]
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace("-", "_"))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing required packages: {', '.join(missing_packages)}")
        print("Installing missing packages...")
        run_command(f"pip install {' '.join(missing_packages)}", "Installing build dependencies")
    else:
        print("✅ All build dependencies are available")

def run_tests():
    """Run tests to ensure package quality"""
    print("🧪 Running tests...")
    if run_command("python -m pytest tests/ -v", "Running tests"):
        print("✅ All tests passed")
        return True
    else:
        print("❌ Tests failed. Please fix issues before building.")
        return False

def build_package():
    """Build the package"""
    print("🔨 Building package...")
    
    # Build using modern Python packaging
    if run_command("python -m build", "Building package with build"):
        print("✅ Package built successfully")
        return True
    else:
        print("❌ Package build failed")
        return False

def check_package():
    """Check the built package"""
    print("🔍 Checking built package...")
    if run_command("twine check dist/*", "Checking package with twine"):
        print("✅ Package check passed")
        return True
    else:
        print("❌ Package check failed")
        return False

def create_source_distribution():
    """Create source distribution"""
    print("📦 Creating source distribution...")
    if run_command("python setup.py sdist", "Creating source distribution"):
        print("✅ Source distribution created")
        return True
    else:
        print("❌ Source distribution failed")
        return False

def create_wheel():
    """Create wheel distribution"""
    print("⚙️ Creating wheel distribution...")
    if run_command("python setup.py bdist_wheel", "Creating wheel distribution"):
        print("✅ Wheel distribution created")
        return True
    else:
        print("❌ Wheel distribution failed")
        return False

def show_package_info():
    """Show information about the built package"""
    print("\n📋 Package Information:")
    print("=" * 50)
    
    # List built files
    dist_dir = Path("dist")
    if dist_dir.exists():
        print("Built files:")
        for file in dist_dir.glob("*"):
            size = file.stat().st_size / 1024  # Size in KB
            print(f"  📄 {file.name} ({size:.1f} KB)")
    
    # Show package metadata
    try:
        import pkg_resources
        dist = pkg_resources.get_distribution("mcp-code-analyzer")
        print(f"\nPackage: {dist.project_name}")
        print(f"Version: {dist.version}")
        print(f"Location: {dist.location}")
    except Exception as e:
        print(f"Could not get package info: {e}")

def main():
    """Main build process"""
    print("🚀 MCP Code Analyzer - Package Build Process")
    print("=" * 60)
    
    # Check if we're in the right directory
    if not Path("setup.py").exists():
        print("❌ setup.py not found. Please run this script from the project root.")
        sys.exit(1)
    
    # Clean previous builds
    clean_build()
    
    # Check dependencies
    check_dependencies()
    
    # Run tests
    if not run_tests():
        sys.exit(1)
    
    # Build package
    if not build_package():
        sys.exit(1)
    
    # Check package
    if not check_package():
        sys.exit(1)
    
    # Show results
    show_package_info()
    
    print("\n🎉 Package build completed successfully!")
    print("\nNext steps:")
    print("1. Test the package: pip install dist/mcp_code_analyzer-*.whl")
    print("2. Upload to PyPI: python -m twine upload dist/*")
    print("3. Upload to Test PyPI: python -m twine upload --repository testpypi dist/*")

if __name__ == "__main__":
    main() 