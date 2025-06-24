# CI/CD Integration Guide

This guide explains how to integrate MCP Code Analyzer into your continuous integration and deployment pipelines.

## Overview

MCP Code Analyzer can be integrated into CI/CD pipelines to:
- Automatically analyze code quality on every commit
- Generate reports for pull requests
- Track code quality trends over time
- Enforce quality gates in deployment pipelines

## GitHub Actions Integration

### Basic Workflow

A sample GitHub Actions workflow is provided in `.github/workflows/code-analysis.yml`. This workflow:

1. **Triggers** on pushes to main/develop and pull requests
2. **Installs** Python and dependencies
3. **Runs** comprehensive code analysis
4. **Generates** Markdown reports
5. **Uploads** reports as artifacts
6. **Comments** on PRs with analysis summary

### Usage

1. Copy the workflow file to your repository:
   ```bash
   mkdir -p .github/workflows
   cp .github/workflows/code-analysis.yml .github/workflows/
   ```

2. Customize the workflow for your project:
   ```yaml
   # Modify branches to monitor
   on:
     push:
       branches: [ main, develop, feature/* ]
     pull_request:
       branches: [ main ]
   ```

3. Adjust analysis options:
   ```yaml
   - name: Run code analysis
     run: |
       python run_cli.py analyze-project . \
         --format markdown \
         --output ./reports \
         --config .analysis-config.json
   ```

### Configuration File

Create `.analysis-config.json` in your repository root:

```json
{
  "analysis": {
    "include_patterns": ["src/**/*.py", "tests/**/*.py"],
    "exclude_patterns": ["**/__pycache__/**", "**/*.pyc"],
    "max_complexity": 10,
    "security_rules": ["all"],
    "quality_threshold": 80
  },
  "reporting": {
    "format": "markdown",
    "include_visualizations": true,
    "export_graphs": true
  },
  "ci": {
    "fail_on_critical": true,
    "fail_on_high": false,
    "comment_on_pr": true
  }
}
```

## Other CI Platforms

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - analyze

code-analysis:
  stage: analyze
  image: python:3.9
  script:
    - pip install -r requirements.txt
    - python run_cli.py analyze-project . --format markdown --output ./reports
  artifacts:
    paths:
      - ./reports/
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
```

### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    stages {
        stage('Code Analysis') {
            steps {
                sh 'pip install -r requirements.txt'
                sh 'python run_cli.py analyze-project . --format html --output ./reports'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/**/*', fingerprint: true
                }
            }
        }
    }
}
```

### Azure DevOps

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
    - main
    - develop

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.9'

- script: |
    pip install -r requirements.txt
  displayName: 'Install dependencies'

- script: |
    python run_cli.py analyze-project . --format markdown --output ./reports
  displayName: 'Run code analysis'

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: 'reports'
    artifactName: 'code-analysis-report'
```

## Quality Gates

### Setting Up Quality Gates

Configure quality thresholds in your CI pipeline:

```bash
# Example: Fail if critical issues found
python run_cli.py analyze-project . --format json --output ./reports

# Check for critical issues
CRITICAL_ISSUES=$(python -c "
import json
with open('./reports/analysis_report_detailed_*.json') as f:
    data = json.load(f)
    issues = data.get('analysis', {}).get('issues', [])
    critical = sum(1 for i in issues if i.get('severity') == 'CRITICAL')
    print(critical)
")

if [ "$CRITICAL_ISSUES" -gt 0 ]; then
    echo "❌ Found $CRITICAL_ISSUES critical issues. Build failed."
    exit 1
fi
```

### Quality Gate Configuration

```json
{
  "quality_gates": {
    "critical_issues": 0,
    "high_issues": 5,
    "overall_health_score": 80,
    "complexity_threshold": 15,
    "security_score": 90
  }
}
```

## Badge Generation

Generate status badges for your README:

```bash
# Generate badge for overall health score
python run_cli.py generate-badge --metric overall_health --threshold 80

# Generate badge for security score
python run_cli.py generate-badge --metric security_score --threshold 90
```

This creates badges like:
- ![Code Quality](https://img.shields.io/badge/code%20quality-85%2F100-green)
- ![Security](https://img.shields.io/badge/security-92%2F100-green)

## Advanced Configuration

### Custom Analysis Rules

```json
{
  "custom_rules": {
    "max_function_length": 50,
    "max_file_length": 500,
    "require_docstrings": true,
    "naming_conventions": "snake_case"
  }
}
```

### Integration with External Tools

```bash
# Send results to external monitoring
python run_cli.py analyze-project . --format json | \
  curl -X POST https://api.monitoring.com/analysis \
  -H "Content-Type: application/json" \
  -d @-

# Generate JUnit XML for test runners
python run_cli.py analyze-project . --format junit --output test-results.xml
```

## Troubleshooting

### Common Issues

1. **Analysis fails in CI**: Check Python version and dependencies
2. **Reports not generated**: Verify output directory permissions
3. **Performance issues**: Use `--quick` mode for large repositories
4. **Memory issues**: Increase CI runner memory or use sampling

### Performance Optimization

```bash
# Quick analysis for CI
python run_cli.py analyze-project . --quick --format markdown

# Sample analysis for large repos
python run_cli.py analyze-project . --sample 100 --format markdown

# Parallel analysis
python run_cli.py analyze-project . --workers 4 --format markdown
```

## Best Practices

1. **Run analysis early**: Include in PR checks, not just main branch
2. **Set realistic thresholds**: Start with lenient gates and tighten over time
3. **Review trends**: Use `show-trends` command to track improvements
4. **Document findings**: Include analysis reports in project documentation
5. **Automate fixes**: Use analysis results to guide automated refactoring

## Support

For issues with CI/CD integration:
- Check the [troubleshooting section](#troubleshooting)
- Review [configuration examples](#configuration-file)
- Open an issue on the project repository 