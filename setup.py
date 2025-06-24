#!/usr/bin/env python3
"""
Setup script for MCP Code Analyzer
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="mcp-code-analyzer",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="A comprehensive code analysis tool for security, quality, complexity, and dependencies",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/mcp-code-analyzer",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/mcp-code-analyzer/issues",
        "Source": "https://github.com/yourusername/mcp-code-analyzer",
        "Documentation": "https://github.com/yourusername/mcp-code-analyzer/tree/main/docs",
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.9",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
            "pre-commit>=2.20.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.0.0",
            "myst-parser>=0.18.0",
        ],
        "full": [
            "matplotlib>=3.5.0",
            "seaborn>=0.11.0",
            "plotly>=5.0.0",
            "graphviz>=0.20.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "mcp-code-analyzer=cli:cli",
            "mcp-analyzer=cli:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "": [
            "*.json",
            "*.yml",
            "*.yaml",
            "*.md",
        ],
    },
    keywords=[
        "code-analysis",
        "security",
        "quality",
        "complexity",
        "dependencies",
        "static-analysis",
        "code-review",
        "ci-cd",
        "github",
        "visualization",
        "reporting",
    ],
    zip_safe=False,
) 