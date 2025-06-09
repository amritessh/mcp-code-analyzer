# MCP Code Analyzer

A Model Context Protocol (MCP) server for comprehensive code analysis, providing complexity metrics, security scanning, and code quality insights.

## Features

- 📊 **Basic Metrics**: LOC, comments, functions, classes
- 🧮 **Complexity Analysis**: Cyclomatic complexity, maintainability index
- 🔍 **Code Quality**: Identify hotspots and technical debt
- 💾 **Smart Caching**: Fast repeated analysis
- 🎨 **Rich CLI**: Beautiful terminal output

## Installation

```bash
# Clone the repository
git clone https://github.com/amritessh/mcp-code-analyzer.git
cd mcp-code-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt