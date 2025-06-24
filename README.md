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

### Enhanced Reporting & Visualization
- 📊 **Interactive Dashboards**: HTML dashboards with charts and metrics
- 📈 **ASCII/Markdown Visualizations**: Dependency graphs and complexity heatmaps
- 📋 **Multiple Export Formats**: HTML, Markdown, JSON, and JUnit XML
- 🎨 **Professional Reports**: Executive summaries and detailed technical reports
- 📊 **Trend Analysis**: Track code quality improvements over time

### CI/CD Integration
- 🔄 **GitHub Actions**: Automated analysis on pull requests and pushes
- 🚦 **Quality Gates**: Configurable thresholds for build success/failure
- 🏷️ **Badge Generation**: Status badges for README and documentation
- 📊 **PR Comments**: Automatic analysis summaries on pull requests
- 🔧 **Multi-Platform Support**: GitLab CI, Jenkins, Azure DevOps

### Trends & History Tracking
- 📜 **Analysis History**: Track all analysis runs with timestamps
- 📈 **Trending Issues**: Identify recurring security and quality problems
- 📊 **Metrics Tracking**: Monitor code quality improvements over time
- 🔍 **Historical Comparison**: Compare current vs. previous analysis results

### Multi-Language Support
- 🐍 Python (full support)
- 🟨 JavaScript/TypeScript (full support)
- 📄 Generic support for other languages

## 📦 Installation

### Option 1: Install from Source (Recommended for Development)

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
```

### Option 2: Install as Python Package (Coming Soon)

```bash
# Install directly from PyPI (when published)
pip install mcp-code-analyzer

# Or install from GitHub
pip install git+https://github.com/yourusername/mcp-code-analyzer.git
```

### Option 3: Docker (Coming Soon)

```bash
# Pull and run with Docker
docker pull yourusername/mcp-code-analyzer
docker run -v $(pwd):/workspace mcp-code-analyzer analyze-project /workspace
```

## 🚀 Getting Started

### Quick Start (5 minutes)

1. **Install the tool** (see Installation section above)

2. **Analyze your first project:**
   ```bash
   # Basic analysis with console output
   python run_cli.py analyze-project /path/to/your/project
   
   # Or analyze the current directory
   python run_cli.py analyze-project .
   ```

3. **Generate your first report:**
   ```bash
   # HTML report
   python run_cli.py generate-report . --format html --type detailed
   
   # Markdown report
   python run_cli.py generate-report . --format markdown --type executive
   ```

4. **View dependency visualization:**
   ```bash
   # ASCII dependency graph
   python run_cli.py dependencies . --visualize --format text
   
   # Export Mermaid diagram
   python run_cli.py dependencies . --format mermaid --export-graph deps.mmd
   ```

### Step-by-Step Guide

#### 1. Initial Setup

```bash
# Clone and setup
git clone https://github.com/yourusername/mcp-code-analyzer.git
cd mcp-code-analyzer
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

#### 2. Configure Your Project

Create a configuration file in your project root:

```bash
# Copy the sample configuration
cp .analysis-config.json /path/to/your/project/

# Edit the configuration for your needs
nano /path/to/your/project/.analysis-config.json
```

Example configuration:
```json
{
  "analysis": {
    "include_patterns": ["src/**/*.py", "tests/**/*.py"],
    "exclude_patterns": ["**/__pycache__/**", "**/*.pyc"],
    "max_complexity": 15,
    "security_rules": ["all"]
  },
  "quality_gates": {
    "critical_issues": 0,
    "high_issues": 5,
    "overall_health_score": 80
  },
  "ci": {
    "fail_on_critical": true,
    "comment_on_pr": true
  }
}
```

#### 3. Run Your First Analysis

```bash
# Navigate to your project
cd /path/to/your/project

# Run comprehensive analysis
python /path/to/mcp-code-analyzer/run_cli.py analyze-project . --format console

# This will show:
# - Security issues found
# - Code quality metrics
# - Complexity analysis
# - Dependency information
# - Overall health score
```

#### 4. Generate Reports

```bash
# Generate detailed HTML report
python /path/to/mcp-code-analyzer/run_cli.py generate-report . \
  --format html \
  --type detailed \
  --output analysis_report.html

# Generate executive summary
python /path/to/mcp-code-analyzer/run_cli.py generate-report . \
  --format markdown \
  --type executive \
  --output executive_summary.md
```

#### 5. Visualize Dependencies

```bash
# View ASCII dependency graph
python /path/to/mcp-code-analyzer/run_cli.py dependencies . \
  --visualize \
  --format text

# Export Mermaid diagram for documentation
python /path/to/mcp-code-analyzer/run_cli.py dependencies . \
  --format mermaid \
  --export-graph docs/dependency-graph.mmd

# Export Graphviz for advanced visualization
python /path/to/mcp-code-analyzer/run_cli.py dependencies . \
  --format graphviz \
  --export-graph docs/dependency-graph.dot
```

#### 6. Set Up CI/CD Integration

Copy the GitHub Actions workflow to your repository:

```bash
# Create workflows directory
mkdir -p .github/workflows

# Copy the workflow file
cp /path/to/mcp-code-analyzer/.github/workflows/code-analysis.yml .github/workflows/
```

The workflow will automatically:
- Run analysis on every PR and push
- Generate reports and upload as artifacts
- Comment on PRs with analysis summary
- Fail builds if quality gates are not met

#### 7. Generate Status Badges

```bash
# Generate badge for overall health
python /path/to/mcp-code-analyzer/run_cli.py generate-badge . \
  --metric overall_health \
  --threshold 80 \
  --output badge.md

# Generate badge for security score
python /path/to/mcp-code-analyzer/run_cli.py generate-badge . \
  --metric security_score \
  --threshold 90 \
  --output security_badge.md
```

Add the badges to your README:
```markdown
![Code Quality](https://img.shields.io/badge/code%20quality-85%2F100-green)
![Security](https://img.shields.io/badge/security-92%2F100-green)
```

#### 8. Track Trends and History

```bash
# View analysis history
python /path/to/mcp-code-analyzer/run_cli.py show-history

# View trending issues
python /path/to/mcp-code-analyzer/run_cli.py show-trends
```

#### 9. Analyze GitHub Repositories

```bash
# Analyze any public repository
python /path/to/mcp-code-analyzer/run_cli.py analyze-github \
  https://github.com/python/cpython \
  --export markdown

# Full analysis with cloning (requires GitHub token)
python /path/to/mcp-code-analyzer/run_cli.py analyze-github \
  https://github.com/python/cpython \
  --token YOUR_GITHUB_TOKEN \
  --full \
  --export html
```

## 🛠️ Usage

### CLI Commands

```bash
# Analyze a project
python run_cli.py analyze-project /path/to/project

# Analyze dependencies with visualization
python run_cli.py dependencies /path/to/project --visualize --format mermaid

# Analyze GitHub repository
python run_cli.py analyze-github https://github.com/user/repo --export markdown

# Generate comprehensive report
python run_cli.py generate-report /path/to/project --format html --type detailed

# Run quality gate checks
python run_cli.py quality-gate /path/to/project --min-health-score 85

# Generate status badge
python run_cli.py generate-badge /path/to/project --metric security_score --threshold 90

# Show analysis history
python run_cli.py show-history

# Show trending issues
python run_cli.py show-trends
```

### CI/CD Integration

#### GitHub Actions

```yaml
# .github/workflows/code-analysis.yml
name: Code Analysis
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    - run: |
        pip install -r requirements.txt
        python run_cli.py analyze-project . --format markdown --output ./reports
    - uses: actions/upload-artifact@v3
      with:
        name: code-analysis-report
        path: ./reports/
```

#### Quality Gates

```bash
# Fail build if critical issues found
python run_cli.py quality-gate . --fail-on-critical --min-health-score 80

# Generate badges for documentation
python run_cli.py generate-badge . --metric overall_health --threshold 85 --output badge.md
```

### Configuration

Create `.analysis-config.json` in your project root:

```json
{
  "analysis": {
    "include_patterns": ["src/**/*.py", "tests/**/*.py"],
    "exclude_patterns": ["**/__pycache__/**", "**/*.pyc"],
    "max_complexity": 15,
    "security_rules": ["all"]
  },
  "quality_gates": {
    "critical_issues": 0,
    "high_issues": 5,
    "overall_health_score": 80
  },
  "ci": {
    "fail_on_critical": true,
    "comment_on_pr": true
  }
}
```

## 📊 Output Examples

### Console Output
```
🔍 Code Analysis Results
========================
📊 Overview
  • Files Analyzed: 45
  • Total Issues: 12
  • Average Complexity: 8.2
  • Overall Health: 85/100

🔒 Security Issues (3)
  1. HIGH Hardcoded API key in config.py:15
  2. MEDIUM SQL injection risk in user.py:42
  3. LOW Missing input validation in api.py:78

✨ Quality Issues (5)
  1. Function too long (50+ lines) in utils.py:120
  2. Missing docstring in helper.py:15
  3. Unused import 'datetime' in main.py:3
```

### HTML Dashboard
- Interactive charts and metrics
- Clickable file navigation
- Severity-based color coding
- Exportable visualizations

### Markdown Report
- Executive summary
- Detailed technical analysis
- Code snippets with line numbers
- Fix suggestions and references

### Dependency Graph (ASCII)
```
- src/
  - analyzers/
    - security.py
    - quality.py
    - dependencies.py
  - utils/
    - visualizer.py
    - logger.py
  - cli.py
```

## 🔧 Advanced Features

### Custom Analysis Rules
```json
{
  "custom_rules": {
    "max_function_length": 50,
    "require_docstrings": true,
    "naming_conventions": "snake_case"
  }
}
```

### Export Options
```bash
# Export dependency graph
python run_cli.py dependencies . --export-graph deps.mmd --format mermaid

# Generate JUnit XML for test runners
python run_cli.py analyze-project . --format junit --output test-results.xml

# Create executive summary
python run_cli.py generate-report . --type executive --format markdown
```

### Integration Examples
```bash
# Send results to external monitoring
python run_cli.py analyze-project . --format json | \
  curl -X POST https://api.monitoring.com/analysis \
  -H "Content-Type: application/json" -d @-

# Generate badges for multiple metrics
for metric in overall_health security_score quality_score; do
  python run_cli.py generate-badge . --metric $metric --threshold 80
done
```

## 📚 Documentation

- [API Documentation](docs/API.md)
- [CI/CD Integration Guide](docs/CI-CD.md)
- [Configuration Reference](docs/configuration.md)
- [Troubleshooting Guide](docs/troubleshooting.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the analysis: `python run_cli.py analyze-project .`
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Rich](https://github.com/Textualize/rich) for beautiful CLI output
- Uses [NetworkX](https://networkx.org/) for dependency analysis
- Integrates with [GitHub API](https://docs.github.com/en/rest) for repository analysis