# src/server.py (updated with Week 3 tools)
from .analyzers.dependencies import DependencyAnalyzer
from .analyzers.circular_dependencies import CircularDependencyDetector, DependencyRefactorer
from .analyzers.project_analyzer import ProjectAnalyzer, AnalysisReportGenerator
from .utils.visualizer import DependencyVisualizer
from .languages.language_manager import LanguageManager

# Initialize new components
dependency_analyzer = DependencyAnalyzer()
project_analyzer = ProjectAnalyzer()
report_generator = AnalysisReportGenerator()
visualizer = DependencyVisualizer()
language_manager = LanguageManager()

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools - updated with Week 3 tools."""
    return [
        # ... Week 1 & 2 tools ...
        
        # Week 3 tools
        Tool(
            name="analyze_dependencies",
            description="Analyze code dependencies and find circular dependencies",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File or directory path"
                    },
                    "depth": {
                        "type": "integer",
                        "description": "Dependency analysis depth",
                        "default": 3
                    },
                    "include_external": {
                        "type": "boolean",
                        "description": "Include external dependencies",
                        "default": True
                    }
                },
                "required": ["path"]
            }
        ),
        Tool(
            name="generate_dependency_graph",
            description="Generate visualization of dependencies",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Project path"
                    },
                    "format": {
                        "type": "string",
                        "enum": ["mermaid", "d3", "graphviz", "pyvis"],
                        "description": "Output format",
                        "default": "mermaid"
                    },
                    "layout": {
                        "type": "string",
                        "enum": ["hierarchical", "circular", "force"],
                        "description": "Graph layout",
                        "default": "hierarchical"
                    }
                },
                "required": ["path"]
            }
        ),
        Tool(
            name="analyze_project",
            description="Comprehensive project-wide analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Project root directory"
                    },
                    "config": {
                        "type": "object",
                        "description": "Analysis configuration",
                        "properties": {
                            "file_extensions": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "exclude_patterns": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "analyze_security": {"type": "boolean"},
                            "analyze_quality": {"type": "boolean"},
                            "analyze_complexity": {"type": "boolean"},
                            "analyze_dependencies": {"type": "boolean"},
                            "generate_visualizations": {"type": "boolean"}
                        }
                    }
                },
                "required": ["project_path"]
            }
        ),
        Tool(
            name="generate_report",
            description="Generate analysis report in various formats",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Project path"
                    },
                    "report_type": {
                        "type": "string",
                        "enum": ["executive", "detailed", "technical"],
                        "description": "Type of report",
                        "default": "detailed"
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["markdown", "html", "pdf"],
                        "description": "Output format",
                        "default": "markdown"
                    }
                },
                "required": ["project_path"]
            }
        ),
        Tool(
            name="find_circular_dependencies",
            description="Find and analyze circular dependencies",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Project path"
                    },
                    "suggest_fixes": {
                        "type": "boolean",
                        "description": "Generate fix suggestions",
                        "default": True
                    }
                },
                "required": ["project_path"]
            }
        )
    ]

# Week 3 tool handlers
async def analyze_dependencies_handler(
    path: str,
    depth: int,
    include_external: bool
) -> str:
    """Handle dependency analysis requests."""
    try:
        path_obj = Path(path)
        
        if not path_obj.exists():
            return f"❌ Path not found: {path}"
        
        # Run dependency analysis
        result = await dependency_analyzer.analyze_dependencies(
            path_obj,
            depth=depth,
            include_external=include_external
        )
        
        # Save to database
        await database.save_analysis(
            str(path_obj),
            "dependencies",
            result
        )
        
        # Format output
        return format_dependency_results(result)
        
    except Exception as e:
        logger.error(f"Error analyzing dependencies: {e}")
        return f"❌ Error during dependency analysis: {str(e)}"

async def generate_dependency_graph_handler(
    path: str,
    format: str,
    layout: str
) -> str:
    """Handle dependency graph generation."""
    try:
        path_obj = Path(path)
        
        # Get or generate dependency data
        dep_result = await dependency_analyzer.analyze_dependencies(path_obj)
        
        # Generate visualization
        viz_data = dep_result.get('visualization', {})
        
        if not viz_data:
            return "❌ No dependency data available for visualization"
        
        # Add circular dependencies for highlighting
        if dep_result.get('metrics', {}).get('circular_dependencies'):
            viz_data['cycles'] = dep_result['metrics']['circular_dependencies']
        
        graph = visualizer.generate_dependency_graph(
            viz_data,
            output_format=format,
            layout=layout
        )
        
        return graph
        
    except Exception as e:
        logger.error(f"Error generating dependency graph: {e}")
        return f"❌ Error generating graph: {str(e)}"

async def analyze_project_handler(
    project_path: str,
    config: Optional[Dict[str, Any]]
) -> str:
    """Handle comprehensive project analysis."""
    try:
        path_obj = Path(project_path)
        
        if not path_obj.exists() or not path_obj.is_dir():
            return f"❌ Invalid project directory: {project_path}"
        
        # Run comprehensive analysis
        def progress_callback(message: str, current: int, total: int):
            logger.info(f"Analysis progress: {message} ({current}/{total})")
        
        result = await project_analyzer.analyze_project(
            path_obj,
            config=config,
            progress_callback=progress_callback
        )
        
        # Format summary
        return format_project_analysis_summary(result)
        
    except Exception as e:
        logger.error(f"Error analyzing project: {e}")
        return f"❌ Error during project analysis: {str(e)}"

async def generate_report_handler(
    project_path: str,
    report_type: str,
    output_format: str
) -> str:
    """Handle report generation."""
    try:
        path_obj = Path(project_path)
        
        # Get latest analysis results
        # (In production, would retrieve from database)
        analysis_results = await project_analyzer.analyze_project(path_obj)
        
        # Generate report
        report = report_generator.generate_report(
            analysis_results,
            report_type=report_type,
            output_format=output_format
        )
        
        # Save report
        report_path = path_obj / f"analysis_report_{report_type}.{output_format}"
        with open(report_path, 'w') as f:
            f.write(report)
        
        return f"✅ Report generated: {report_path}\n\n{report[:500]}..."
        
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return f"❌ Error generating report: {str(e)}"

async def find_circular_dependencies_handler(
    project_path: str,
    suggest_fixes: bool
) -> str:
    """Handle circular dependency detection."""
    try:
        path_obj = Path(project_path)
        
        # First, analyze dependencies
        dep_result = await dependency_analyzer.analyze_dependencies(path_obj)
        
        # Create circular dependency detector
        detector = CircularDependencyDetector(dependency_analyzer.graph)
        cycles_analysis = detector.detect_cycles()
        
        output = format_circular_dependencies(cycles_analysis)
        
        # Add fix suggestions if requested
        if suggest_fixes and cycles_analysis['cycles']:
            refactorer = DependencyRefactorer(dependency_analyzer.graph)
            suggestions = refactorer.suggest_refactoring(
                cycles_analysis['cycles'],
                []  # No god modules for now
            )
            
            output += "\n\n" + format_refactoring_suggestions(suggestions)
        
        return output
        
    except Exception as e:
        logger.error(f"Error finding circular dependencies: {e}")
        return f"❌ Error: {str(e)}"

# Formatting functions
def format_dependency_results(result: Dict[str, Any]) -> str:
    """Format dependency analysis results."""
    metrics = result.get('metrics', {})
    patterns = result.get('patterns', {})
    
    output = f"""🔗 Dependency Analysis Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Path: {result['path']}

📊 Metrics:
  • Total Dependencies: {metrics.get('total_dependencies', 0)}
  • External Dependencies: {metrics.get('external_dependencies', 0)}
  • Internal Dependencies: {metrics.get('internal_dependencies', 0)}
  • Circular Dependencies: {len(metrics.get('circular_dependencies', []))}
  • Average Coupling: {metrics.get('coupling_score', 0):.1f}
  • Instability: {metrics.get('instability', 0):.2f}
"""
    
    # Circular dependencies
    circular = metrics.get('circular_dependencies', [])
    if circular:
        output += "\n🔄 Circular Dependencies:\n"
        for i, cycle in enumerate(circular[:5]):
            output += f"  {i+1}. {' → '.join(cycle[:4])}"
            if len(cycle) > 4:
                output += f" → ... ({len(cycle)} modules)"
            output += "\n"
    
    # Patterns
    if patterns.get('god_modules'):
        output += "\n⚠️ God Modules (high coupling):\n"
        for module in patterns['god_modules'][:5]:
            output += f"  • {module['module']}: {module['outgoing_dependencies']} dependencies\n"
    
    if patterns.get('hub_modules'):
        output += "\n🎯 Hub Modules (high fan-in):\n"
        for module in patterns['hub_modules'][:5]:
            output += f"  • {module['module']}: {module['incoming_dependencies']} incoming\n"
    
    # Recommendations
    if result.get('recommendations'):
        output += "\n💡 Recommendations:\n"
        for rec in result['recommendations'][:5]:
            output += f"  • {rec}\n"
    
    return output

def format_project_analysis_summary(result: Dict[str, Any]) -> str:
    """Format project analysis summary."""
    summary = result.get('summary', {})
    metrics = result.get('metrics', {})
    
    output = f"""📊 Project Analysis Complete
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Project: {Path(result['project_path']).name}
⏱️ Duration: {result.get('duration', 0):.1f}s

📈 Overview:
  • Files Analyzed: {summary.get('total_files', 0)}
  • Total LOC: {metrics.get('totals', {}).get('loc', 0):,}
  • Total Issues: {len(result.get('issues', []))}

🎯 Health Scores:
  • Overall Health: {summary.get('overall_health', 0):.1f}/100
  • Security Score: {summary.get('security_score', 0):.1f}/100
  • Quality Score: {summary.get('quality_score', 0):.1f}/100
  • Complexity Score: {summary.get('complexity_score', 0):.1f}/100

📊 Averages:
  • Complexity: {metrics.get('averages', {}).get('complexity', 0):.1f}
  • Quality: {metrics.get('averages', {}).get('quality', 0):.1f}
  • LOC per File: {metrics.get('averages', {}).get('loc_per_file', 0):.0f}
"""
    
    # Top issues
    issues = result.get('issues', [])
    if issues:
        severity_counts = {}
        for issue in issues:
            sev = issue.get('severity', 'UNKNOWN')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        output += "\n🚨 Issues by Severity:\n"
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if sev in severity_counts:
                output += f"  • {sev}: {severity_counts[sev]}\n"
    
    # Top recommendations
    if result.get('recommendations'):
        output += "\n💡 Top Recommendations:\n"
        for i, rec in enumerate(result['recommendations'][:3]):
            output += f"  {i+1}. {rec}\n"
    
    # Visualizations
    if result.get('visualizations'):
        output += "\n📊 Visualizations Generated:\n"
        for viz_name in result['visualizations'].keys():
            output += f"  • {viz_name}\n"
    
    return output

def format_circular_dependencies(analysis: Dict[str, Any]) -> str:
    """Format circular dependency analysis."""
    output = f"""🔄 Circular Dependency Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Cycles Found: {analysis['total_cycles']}
Overall Severity: {analysis.get('overall_severity', 0)}/10
Affected Modules: {len(analysis['affected_modules'])}
"""
    
    if analysis['cycles']:
        output += "\n🔗 Dependency Cycles:\n"
        for i, cycle in enumerate(analysis['cycles'][:10]):
            output += f"\n{i+1}. {cycle['description']}\n"
            output += f"   Severity: {cycle['severity']}/10 | "
            output += f"Type: {cycle['type']} | "
            output += f"Length: {cycle['length']}\n"
            output += f"   Path: {' → '.join(cycle['modules'][:5])}"
            if cycle['length'] > 5:
                output += " → ..."
            output += "\n"
    
    if analysis.get('breaking_points'):
        output += "\n✂️ Suggested Breaking Points:\n"
        for bp in analysis['breaking_points'][:5]:
            output += f"  • Break: {bp['source']} → {bp['target']}\n"
            output += f"    {bp['suggestion']}\n"
    
    return output

def format_refactoring_suggestions(suggestions: Dict[str, Any]) -> str:
    """Format refactoring suggestions."""
    output = "🔧 Refactoring Suggestions\n"
    output += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    
    if suggestions.get('patterns'):
        output += "\n📐 Design Patterns to Apply:\n"
        for pattern in suggestions['patterns'][:5]:
            output += f"\n**{pattern['pattern']} Pattern**\n"
            output += f"  {pattern['description']}\n"
            output += f"  Modules: {', '.join(pattern['modules'][:3])}\n"
            if pattern.get('implementation'):
                output += f"\n  Example:\n```python\n{pattern['implementation'][:200]}...\n```\n"
    
    if suggestions.get('new_modules'):
        output += "\n📦 Suggested New Modules:\n"
        for module in suggestions['new_modules'][:3]:
            output += f"  • {module['name']}: {module['purpose']}\n"
            output += f"    Reason: {module['reason']}\n"
    
    if suggestions.get('interfaces'):
        output += "\n🔌 Suggested Interfaces:\n"
        for interface in suggestions['interfaces'][:3]:
            output += f"  • {interface['interface_name']} for {interface['module']}\n"
            output += f"    Reason: {interface['reason']}\n"
    
    return output

# src/server.py (updated with GitHub tools)
from .analyzers.github_analyzer import GitHubAnalyzer, GitHubURLHandler
from .analyzers.github_security import GitHubSecurityScanner

# Initialize GitHub components
github_analyzer = GitHubAnalyzer()
github_security = GitHubSecurityScanner()

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools - updated with GitHub tools."""
    return [
        # ... existing tools ...
        
        # GitHub tools
        Tool(
            name="analyze_github_repo",
            description="Analyze a GitHub repository",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo_url": {
                        "type": "string",
                        "description": "GitHub repository URL"
                    },
                    "branch": {
                        "type": "string",
                        "description": "Branch to analyze",
                        "default": "main"
                    },
                    "analysis_mode": {
                        "type": "string",
                        "enum": ["full", "quick", "files_only"],
                        "description": "Analysis mode",
                        "default": "full"
                    },
                    "github_token": {
                        "type": "string",
                        "description": "GitHub personal access token (optional)"
                    }
                },
                "required": ["repo_url"]
            }
        ),
        Tool(
            name="github_security_scan",
            description="Scan GitHub repository for security issues",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo_url": {
                        "type": "string",
                        "description": "GitHub repository URL"
                    },
                    "github_token": {
                        "type": "string",
                        "description": "GitHub token (required for full scan)"
                    }
                },
                "required": ["repo_url"]
            }
        ),
        Tool(
            name="compare_github_repos",
            description="Compare multiple GitHub repositories",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo_urls": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of GitHub repository URLs"
                    },
                    "metrics": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Metrics to compare",
                        "default": ["quality", "security", "activity", "complexity"]
                    }
                },
                "required": ["repo_urls"]
            }
        ),
        Tool(
            name="analyze_github_pr",
            description="Analyze a GitHub pull request",
            inputSchema={
                "type": "object",
                "properties": {
                    "pr_url": {
                        "type": "string",
                        "description": "GitHub PR URL"
                    },
                    "checks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Checks to perform",
                        "default": ["security", "quality", "complexity"]
                    }
                },
                "required": ["pr_url"]
            }
        )
    ]

# GitHub tool handlers
async def analyze_github_repo_handler(
    repo_url: str,
    branch: str,
    analysis_mode: str,
    github_token: Optional[str]
) -> str:
    """Handle GitHub repository analysis."""
    try:
        # Set token if provided
        if github_token:
            analyzer = GitHubAnalyzer(github_token)
        else:
            analyzer = github_analyzer
        
        # Run analysis
        result = await analyzer.analyze_github_repo(
            repo_url,
            branch=branch,
            analysis_mode=analysis_mode
        )
        
        # Format output
        return format_github_analysis_results(result)
        
    except Exception as e:
        logger.error(f"Error analyzing GitHub repo: {e}")
        return f"❌ Error: {str(e)}"

async def github_security_scan_handler(
    repo_url: str,
    github_token: Optional[str]
) -> str:
    """Handle GitHub security scanning."""
    try:
        # Parse URL
        url_info = GitHubURLHandler.parse_url(repo_url)
        if url_info['type'] != 'repository':
            return "❌ Invalid repository URL"
        
        # Run security scan
        scanner = GitHubSecurityScanner(github_token)
        result = await scanner.scan_github_security(
            url_info['owner'],
            url_info['repo']
        )
        
        # Format output
        return format_github_security_results(result)
        
    except Exception as e:
        logger.error(f"Error scanning GitHub security: {e}")
        return f"❌ Error: {str(e)}"

async def compare_github_repos_handler(
    repo_urls: List[str],
    metrics: List[str]
) -> str:
    """Handle repository comparison."""
    try:
        results = {}
        
        # Analyze each repository
        for repo_url in repo_urls[:5]:  # Limit to 5 repos
            result = await github_analyzer.analyze_github_repo(
                repo_url,
                analysis_mode='quick'
            )
            results[repo_url] = result
        
        # Generate comparison
        comparison = generate_repo_comparison(results, metrics)
        
        return format_repo_comparison(comparison)
        
    except Exception as e:
        logger.error(f"Error comparing repos: {e}")
        return f"❌ Error: {str(e)}"

# Formatting functions
def format_github_analysis_results(result: Dict[str, Any]) -> str:
    """Format GitHub analysis results."""
    repo = result.get('repository', {})
    metadata = result.get('metadata', {})
    analysis = result.get('analysis', {})
    insights = result.get('insights', {})
    
    output = f"""🐙 GitHub Repository Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📦 Repository: {repo.get('owner')}/{repo.get('name')}
🌿 Branch: {repo.get('branch')}
📊 Mode: {repo.get('analysis_mode')}

📈 Repository Info:
  • Stars: ⭐ {metadata.get('stars', 0)}
  • Forks: 🍴 {metadata.get('forks', 0)}
  • Size: 💾 {metadata.get('size_kb', 0):,} KB
  • Language: 🔤 {metadata.get('primary_language', 'Unknown')}
  • Contributors: 👥 {metadata.get('contributors', 0)}
  • License: 📄 {metadata.get('license', 'None')}
"""
    
    # Add badges
    if insights.get('badges'):
        output += f"\n🏅 Badges: {' '.join(insights['badges'])}\n"
    
    # Add analysis results based on mode
    if analysis.get('mode') == 'quick':
        output += f"""
📁 File Summary:
  • Total Files: {analysis.get('file_summary', {}).get('total_files', 0)}
  • Supported Files: {analysis.get('file_summary', {}).get('supported_files', 0)}
  • Has Tests: {'✅' if analysis.get('structure', {}).get('has_tests') else '❌'}
  • Has CI/CD: {'✅' if analysis.get('structure', {}).get('has_ci') else '❌'}
"""
    elif analysis.get('summary'):
        # Full analysis results
        summary = analysis.get('summary', {})
        output += f"""
🎯 Health Scores:
  • Overall: {summary.get('overall_health', 0):.1f}/100
  • Security: {summary.get('security_score', 0):.1f}/100
  • Quality: {summary.get('quality_score', 0):.1f}/100
  • Complexity: {summary.get('complexity_score', 0):.1f}/100

📊 Metrics:
  • Files Analyzed: {summary.get('total_files', 0)}
  • Total Issues: {len(analysis.get('issues', []))}
  • Average Complexity: {analysis.get('metrics', {}).get('averages', {}).get('complexity', 0):.1f}
"""
    
    # Add insights
    if insights.get('recommendations'):
        output += "\n💡 Recommendations:\n"
        for rec in insights['recommendations'][:5]:
            output += f"  • {rec}\n"
    
    return output

def format_github_security_results(result: Dict[str, Any]) -> str:
    """Format GitHub security scan results."""
    output = f"""🔒 GitHub Security Scan Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ Security Score: {result.get('security_score', 0):.1f}/100

📊 Vulnerability Summary:
  • Security Advisories: {len(result.get('security_advisories', []))}
  • Dependabot Alerts: {len(result.get('dependabot_alerts', []))}
  • Secret Scanning: {len(result.get('secret_scanning', []))}
"""
    
    # Details on vulnerabilities
    if result.get('security_advisories'):
        output += "\n🚨 Security Advisories:\n"
        for adv in result['security_advisories'][:5]:
            output += f"  • [{adv.get('severity', 'UNKNOWN')}] {adv.get('package', 'Unknown package')}\n"
            output += f"    {adv.get('summary', 'No summary')}\n"
    
    if result.get('dependabot_alerts'):
        output += "\n🤖 Dependabot Alerts:\n"
        for alert in result['dependabot_alerts'][:5]:
            output += f"  • [{alert.get('severity', 'unknown')}] {alert.get('package', 'Unknown')}\n"
            output += f"    Vulnerable: {alert.get('vulnerable_version', 'Unknown version')}\n"
    
    # Security file status
    security_files = result.get('security_files', {})
    output += "\n📁 Security Files:\n"
    output += f"  • SECURITY.md: {'✅' if security_files.get('SECURITY.md') or security_files.get('.github/SECURITY.md') else '❌'}\n"
    output += f"  • Dependabot: {'✅' if security_files.get('.github/dependabot.yml') else '❌'}\n"
    output += f"  • CodeQL: {'✅' if security_files.get('.github/workflows/codeql-analysis.yml') else '❌'}\n"
    
    # Recommendations
    if result.get('recommendations'):
        output += "\n💡 Security Recommendations:\n"
        for rec in result['recommendations']:
            output += f"  {rec}\n"
    
    return output

def generate_repo_comparison(
    results: Dict[str, Dict[str, Any]],
    metrics: List[str]
) -> Dict[str, Any]:
    """Generate repository comparison data."""
    comparison = {
        'repositories': [],
        'metrics': {}
    }
    
    for repo_url, result in results.items():
        repo_data = {
            'url': repo_url,
            'name': result.get('repository', {}).get('name', 'Unknown'),
            'metadata': result.get('metadata', {}),
            'scores': {}
        }
        
        # Extract scores
        if 'analysis' in result and 'summary' in result['analysis']:
            summary = result['analysis']['summary']
            repo_data['scores'] = {
                'overall': summary.get('overall_health', 0),
                'security': summary.get('security_score', 0),
                'quality': summary.get('quality_score', 0),
                'complexity': summary.get('complexity_score', 0)
            }
        elif 'insights' in result:
            repo_data['scores']['overall'] = result['insights'].get('overall_health_score', 0)
        
        comparison['repositories'].append(repo_data)
    
    # Calculate metric comparisons
    for metric in metrics:
        if metric == 'activity':
            comparison['metrics']['activity'] = [
                {
                    'repo': r['name'],
                    'commits': r['metadata'].get('recent_commits', 0),
                    'contributors': r['metadata'].get('contributors', 0)
                }
                for r in comparison['repositories']
            ]
        elif metric == 'popularity':
            comparison['metrics']['popularity'] = [
                {
                    'repo': r['name'],
                    'stars': r['metadata'].get('stars', 0),
                    'forks': r['metadata'].get('forks', 0)
                }
                for r in comparison['repositories']
            ]
    
    return comparison

def format_repo_comparison(comparison: Dict[str, Any]) -> str:
    """Format repository comparison results."""
    output = "📊 Repository Comparison\n"
    output += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
    
    # Create comparison table
    repos = comparison['repositories']
    
    # Header
    output += "| Repository | Overall | Security | Quality | Stars | Forks |\n"
    output += "|------------|---------|----------|---------|-------|-------|\n"
    
    # Data rows
    for repo in repos:
        output += f"| {repo['name'][:20]} "
        output += f"| {repo['scores'].get('overall', 0):.0f} "
        output += f"| {repo['scores'].get('security', 0):.0f} "
        output += f"| {repo['scores'].get('quality', 0):.0f} "
        output += f"| {repo['metadata'].get('stars', 0)} "
        output += f"| {repo['metadata'].get('forks', 0)} |\n"
    
    # Best in each category
    if repos:
        output += "\n🏆 Best in Category:\n"
        
        # Find best scores
        best_overall = max(repos, key=lambda r: r['scores'].get('overall', 0))
        best_security = max(repos, key=lambda r: r['scores'].get('security', 0))
        best_quality = max(repos, key=lambda r: r['scores'].get('quality', 0))
        most_popular = max(repos, key=lambda r: r['metadata'].get('stars', 0))
        
        output += f"  • Best Overall: {best_overall['name']}\n"
        output += f"  • Most Secure: {best_security['name']}\n"
        output += f"  • Best Quality: {best_quality['name']}\n"
        output += f"  • Most Popular: {most_popular['name']}\n"
    
    return output