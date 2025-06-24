# MCP Code Analyzer

A comprehensive code analysis tool that provides security scanning, quality checks, complexity analysis, and dependency visualization. Available as a Python MCP server, CLI tool, and VS Code extension.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10+-green)
![License](https://img.shields.io/badge/license-MIT-blue)

## 🚀 Features

### Security Analysis
- 🔒 **Vulnerability Detection**: Identifies security vulnerabilities including SQL injection, XSS, hardcoded secrets
- 🛡️ **Dependency Scanning**: Checks for known vulnerabilities in dependencies
- 🔑 **Secret Detection**: Finds exposed API keys, passwords, and tokens
- 📊 **Risk Scoring**: Provides overall security risk assessment

### Code Quality
- 📏 **Quality Metrics**: Measures code quality with actionable insights
- 🧹 **Dead Code Detection**: Identifies unused imports, variables, and functions
- 📝 **TODO/FIXME Tracking**: Manages technical debt and pending tasks
- 🎯 **Code Smell Detection**: Identifies problematic patterns

### Complexity Analysis
- 🧮 **Cyclomatic Complexity**: Measures code complexity at function level
- 📈 **Maintainability Index**: Calculates overall code maintainability
- 🔥 **Hotspot Detection**: Identifies complex areas needing refactoring
- 📊 **Halstead Metrics**: Provides detailed complexity measurements

### Dependency Analysis
- 🔗 **Dependency Mapping**: Visualizes module dependencies
- 🔄 **Circular Dependency Detection**: Finds and suggests fixes for circular imports
- 📦 **External Dependency Tracking**: Monitors third-party dependencies
- 🏗️ **Architecture Analysis**: Identifies architectural patterns and violations

### GitHub Integration
- 🐙 **Repository Analysis**: Analyze any public GitHub repository
- 🔍 **Quick Scanning**: Fast analysis without full clone
- 📊 **Repository Comparison**: Compare multiple repositories
- 🛡️ **Security Scanning**: Check for security advisories and vulnerabilities

### Multi-Language Support
- 🐍 Python (full support)
- 🟨 JavaScript/TypeScript (full support)
- 📄 Generic support for other languages

## 📦 Installation

### Python Package

```bash
# Clone the repository
git clone https://github.com/yourusername/mcp-code-analyzer.git
cd mcp-code-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .