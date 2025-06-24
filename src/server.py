# src/server.py
"""
MCP Code Analyzer Server
Comprehensive code analysis with security, quality, complexity, and dependency scanning
"""

import asyncio
from typing import Dict, Any, List, Optional
from pathlib import Path
import json
import os
from datetime import datetime

from mcp import Server
from mcp.server import stdio
from mcp.types import Tool, TextContent, ImageContent, EmbeddedResource

# Import all analyzers
from .config import settings
from .utils.logger import logger, setup_logger
from .storage.cache import FileCache
from .storage.database import AnalysisDatabase

# Week 1: Basic and Complexity Analysis
from .analyzers.basic import BasicAnalyzer
from .analyzers.complexity import ComplexityAnalyzer

# Week 2: Security and Quality
from .analyzers.security import SecurityAnalyzer
from .analyzers.quality import QualityAnalyzer
from .analyzers.todo_tracker import TodoTracker
from .analyzers.dead_code import DeadCodeDetector
from .analyzers.dependency_security import DependencyScanner

# Week 3: Dependencies and Project Analysis
from .analyzers.dependencies import DependencyAnalyzer
from .analyzers.circular_dependencies import CircularDependencyDetector, DependencyRefactorer
from .analyzers.project_analyzer import ProjectAnalyzer, AnalysisReportGenerator
from .utils.visualizer import DependencyVisualizer, TreemapVisualizer
from .languages.language_manager import LanguageManager

# Week 4: GitHub Integration
from .analyzers.github_analyzer import GitHubAnalyzer, GitHubURLHandler
from .analyzers.github_security import GitHubSecurityScanner

# Initialize server
server = Server(settings.server_name)
logger.info(f"Initializing {settings.server_name} MCP server")

# Initialize all analyzers
basic_analyzer = BasicAnalyzer()
complexity_analyzer = ComplexityAnalyzer()
security_analyzer = SecurityAnalyzer()
quality_analyzer = QualityAnalyzer()
todo_tracker = TodoTracker()
dead_code_detector = DeadCodeDetector()
dependency_scanner = DependencyScanner()
dependency_analyzer = DependencyAnalyzer()
project_analyzer = ProjectAnalyzer()
report_generator = AnalysisReportGenerator()
visualizer = DependencyVisualizer()
treemap_viz = TreemapVisualizer()
language_manager = LanguageManager()
github_analyzer = GitHubAnalyzer()
github_security = GitHubSecurityScanner()

# Initialize storage
cache = FileCache()
database = AnalysisDatabase()

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List all available analysis tools."""
    return [
        # Week 1: Basic Analysis Tools
        Tool(
            name="analyze_file",
            description="Analyze a single file for basic metrics (LOC, functions, classes)",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to analyze"
                    }
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="get_complexity",
            description="Get complexity metrics for a code file",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file"
                    },
                    "include_details": {
                        "type": "boolean",
                        "description": "Include detailed breakdown",
                        "default": False
                    }
                },
                "required": ["file_path"]
            }
        ),
        
        # Week 2: Security and Quality Tools
        Tool(
            name="scan_security",
            description="Scan file or directory for security vulnerabilities",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File or directory path to scan"
                    },
                    "rules": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific security rules to apply"
                    },
                    "include_info": {
                        "type": "boolean",
                        "description": "Include informational findings",
                        "default": False
                    }
                },
                "required": ["path"]
            }
        ),
        Tool(
            name="check_quality",
            description="Check code quality and detect code smells",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to check"
                    },
                    "standards": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Quality standards to apply"
                    }
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="find_todos",
            description="Find TODO, FIXME, and other code comments",
            inputSchema={
                "type": "object",
                "properties": {
                    "directory": {
                        "type": "string",
                        "description": "Directory to search"
                    },
                    "include_patterns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Patterns to include (TODO, FIXME, HACK, etc.)"
                    }
                },
                "required": ["directory"]
            }
        ),
        Tool(
            name="detect_dead_code",
            description="Find unused code, imports, and variables",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "File to analyze"
                    }
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="scan_dependencies",
            description="Scan project dependencies for known vulnerabilities",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Project root directory"
                    }
                },
                "required": ["project_path"]
            }
        ),
        
        # Week 3: Dependency and Project Analysis Tools
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
                        "enum": ["markdown", "html", "json"],
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
        ),
        
        # Week 4: GitHub Integration Tools
        Tool(
            name="analyze_github_repo",
            description="Analyze a GitHub repository without cloning",
            inputSchema={
                "type": "object",
                "properties": {
                    "repo_url": {
                        "type": "string",
                        "description": "GitHub repository URL (e.g., https://github.com/owner/repo)"
                    },
                    "branch": {
                        "type": "string",
                        "description": "Branch to analyze",
                        "default": "main"
                    },
                    "analysis_mode": {
                        "type": "string",
                        "enum": ["full", "quick", "files_only"],
                        "description": "Analysis mode - full (clone), quick (API only), files_only (selective)",
                        "default": "quick"
                    },
                    "github_token": {
                        "type": "string",
                        "description": "GitHub personal access token for API rate limits (optional)"
                    }
                },
                "required": ["repo_url"]
            }
        ),
        Tool(
            name="github_security_scan",
            description="Scan GitHub repository for security issues and advisories",
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
                        "description": "List of GitHub repository URLs to compare"
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
        
        # Utility Tools
        Tool(
            name="get_analysis_history",
            description="Get historical analysis data for trends",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Project path"
                    },
                    "days": {
                        "type": "integer",
                        "description": "Number of days to look back",
                        "default": 30
                    }
                },
                "required": ["project_path"]
            }
        ),
        Tool(
            name="clear_cache",
            description="Clear analysis cache",
            inputSchema={
                "type": "object",
                "properties": {
                    "older_than_days": {
                        "type": "integer",
                        "description": "Clear cache older than specified days",
                        "default": 7
                    }
                }
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls and route to appropriate handlers."""
    try:
        logger.info(f"Tool called: {name} with args: {json.dumps(arguments, indent=2)}")
        
        # Route to appropriate handler
        handlers = {
            # Week 1 handlers
            "analyze_file": analyze_file_handler,
            "get_complexity": get_complexity_handler,
            
            # Week 2 handlers
            "scan_security": scan_security_handler,
            "check_quality": check_quality_handler,
            "find_todos": find_todos_handler,
            "detect_dead_code": detect_dead_code_handler,
            "scan_dependencies": scan_dependencies_handler,
            
            # Week 3 handlers
            "analyze_dependencies": analyze_dependencies_handler,
            "generate_dependency_graph": generate_dependency_graph_handler,
            "analyze_project": analyze_project_handler,
            "generate_report": generate_report_handler,
            "find_circular_dependencies": find_circular_dependencies_handler,
            
            # Week 4 handlers
            "analyze_github_repo": analyze_github_repo_handler,
            "github_security_scan": github_security_scan_handler,
            "compare_github_repos": compare_github_repos_handler,
            
            # Utility handlers
            "get_analysis_history": get_analysis_history_handler,
            "clear_cache": clear_cache_handler
        }
        
        handler = handlers.get(name)
        if not handler:
            result = f"❌ Unknown tool: {name}"
        else:
            result = await handler(**arguments)
        
        return [TextContent(type="text", text=result)]
        
    except Exception as e:
        logger.error(f"Error in tool {name}: {str(e)}", exc_info=True)
        return [TextContent(
            type="text", 
            text=f"❌ Error: {str(e)}\n\nPlease check the logs for more details."
        )]

# ==================== Week 1 Handlers ====================

async def analyze_file_handler(file_path: str) -> str:
    """Handle basic file analysis requests."""
    try:
        path = Path(file_path)
        
        if not path.exists():
            return f"❌ File not found: {file_path}"
        
        if not path.is_file():
            return f"❌ Not a file: {file_path}"
        
        # Check cache
        cached = await cache.get(path, "basic")
        if cached:
            logger.info(f"Using cached basic analysis for {file_path}")
            return format_basic_analysis(cached)
        
        # Check file size
        file_size = path.stat().st_size
        if file_size > settings.max_file_size:
            return f"❌ File too large: {file_size} bytes (max: {settings.max_file_size})"
        
        # Use language manager for multi-language support
        result = await language_manager.analyze_file(path, ["basic"])
        
        # Cache result
        await cache.set(path, "basic", result.get("basic", {}))
        
        # Save to database
        await database.save_analysis(
            str(path),
            "basic",
            result.get("basic", {})
        )
        
        return format_basic_analysis(result.get("basic", {}))
        
    except Exception as e:
        logger.error(f"Error analyzing {file_path}: {e}")
        return f"❌ Error analyzing file: {str(e)}"

async def get_complexity_handler(file_path: str, include_details: bool) -> str:
    """Handle complexity analysis requests."""
    try:
        path = Path(file_path)
        
        if not path.exists():
            return f"❌ File not found: {file_path}"
        
        # Check if file is supported for complexity analysis
        if path.suffix not in ['.py', '.js', '.ts', '.jsx', '.tsx']:
            return f"❌ Complexity analysis not supported for {path.suffix} files"
        
        # Check cache
        cache_key = f"complexity_{'detailed' if include_details else 'simple'}"
        cached = await cache.get(path, cache_key)
        if cached:
            logger.info(f"Using cached complexity analysis for {file_path}")
            return format_complexity_analysis(cached)
        
        # Get complexity
        if path.suffix == '.py':
            result = await complexity_analyzer.analyze_complexity(path, include_details)
        else:
            # Use language manager for other languages
            analysis = await language_manager.analyze_file(path, ["complexity"])
            result = analysis.get("complexity", {})
        
        if not result:
            return f"❌ Could not analyze complexity for {file_path}"
        
        # Cache result
        await cache.set(path, cache_key, result)
        
        # Save metrics to database
        await database.save_quality_metrics(
            str(path),
            {
                'complexity_average': result.get('average_complexity', 0),
                'complexity_max': result.get('max_complexity', 0),
                'maintainability_index': result.get('maintainability_index', 0)
            }
        )
        
        return format_complexity_analysis(result)
        
    except Exception as e:
        logger.error(f"Error getting complexity for {file_path}: {e}")
        return f"❌ Error analyzing complexity: {str(e)}"

# ==================== Week 2 Handlers ====================

async def scan_security_handler(path: str, rules: Optional[List[str]], include_info: bool) -> str:
    """Handle security scanning requests."""
    try:
        path_obj = Path(path)
        
        if not path_obj.exists():
            return f"❌ Path not found: {path}"
        
        # Handle directory scanning
        if path_obj.is_dir():
            # Scan all supported files in directory
            python_files = list(path_obj.rglob("*.py"))
            js_files = list(path_obj.rglob("*.js")) + list(path_obj.rglob("*.ts"))
            
            all_files = python_files + js_files
            if not all_files:
                return "❌ No supported files found in directory"
            
            total_issues = 0
            critical_count = 0
            high_count = 0
            results_summary = []
            
            for file_path in all_files[:50]:  # Limit to 50 files
                result = await security_analyzer.scan_security(
                    file_path, 
                    rules, 
                    include_info
                )
                
                if result.get('total_issues', 0) > 0:
                    total_issues += result['total_issues']
                    critical_count += result['severity_counts'].get('critical', 0)
                    high_count += result['severity_counts'].get('high', 0)
                    
                    results_summary.append({
                        'file': str(file_path.relative_to(path_obj)),
                        'issues': result['total_issues'],
                        'risk_score': result['risk_score']
                    })
            
            # Format directory scan results
            output = f"""🔒 Security Scan Results (Directory)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Path: {path}
📊 Files Scanned: {len(all_files)}
⚠️  Total Issues: {total_issues}

🎯 Severity Summary:
  • Critical: {critical_count}
  • High: {high_count}
"""
            
            if results_summary:
                output += "\n🔥 Files with Issues:\n"
                for summary in sorted(results_summary, key=lambda x: x['risk_score'], reverse=True)[:10]:
                    output += f"  • {summary['file']}: {summary['issues']} issues (Risk: {summary['risk_score']}/100)\n"
            
            return output
        
        else:
            # Single file scan
            result = await security_analyzer.scan_security(
                path_obj, 
                rules, 
                include_info
            )
            
            # Save to database
            if result['issues']:
                await database.save_security_issues(result['issues'])
            
            return format_security_results(result)
        
    except Exception as e:
        logger.error(f"Error scanning security: {e}")
        return f"❌ Error during security scan: {str(e)}"

async def check_quality_handler(file_path: str, standards: Optional[List[str]]) -> str:
    """Handle quality check requests."""
    try:
        path = Path(file_path)
        
        if not path.exists():
            return f"❌ File not found: {file_path}"
        
        # Run quality check
        result = await quality_analyzer.check_quality(path, standards)
        
        # Save metrics to database
        if result.get('metrics'):
            await database.save_quality_metrics(
                str(path), 
                result['metrics']
            )
        
        return format_quality_results(result)
        
    except Exception as e:
        logger.error(f"Error checking quality: {e}")
        return f"❌ Error during quality check: {str(e)}"

async def find_todos_handler(directory: str, include_patterns: Optional[List[str]]) -> str:
    """Handle TODO finding requests."""
    try:
        path = Path(directory)
        
        if not path.exists():
            return f"❌ Directory not found: {directory}"
        
        # Find TODOs
        result = await todo_tracker.find_todos(
            path,
            include_patterns,
            recursive=True
        )
        
        # Save to database
        if result['items']:
            await database.save_todo_items(result['items'])
        
        return format_todo_results(result)
        
    except Exception as e:
        logger.error(f"Error finding TODOs: {e}")
        return f"❌ Error during TODO search: {str(e)}"

async def detect_dead_code_handler(file_path: str) -> str:
    """Handle dead code detection requests."""
    try:
        path = Path(file_path)
        
        if not path.exists():
            return f"❌ File not found: {file_path}"
        
        # Detect dead code
        result = await dead_code_detector.detect_dead_code(path)
        
        return format_dead_code_results(result)
        
    except Exception as e:
        logger.error(f"Error detecting dead code: {e}")
        return f"❌ Error during dead code detection: {str(e)}"

async def scan_dependencies_handler(project_path: str) -> str:
    """Handle dependency vulnerability scanning."""
    try:
        path = Path(project_path)
        
        if not path.exists() or not path.is_dir():
            return f"❌ Invalid project directory: {project_path}"
        
        # Scan dependencies
        result = await dependency_scanner.scan_dependencies(path)
        
        # Format output
        output = f"""🔐 Dependency Security Scan
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Project: {project_path}

📊 Vulnerabilities Found:
"""
        
        total_vulns = 0
        for lang, lang_result in result.items():
            if isinstance(lang_result, dict) and 'vulnerabilities' in lang_result:
                vulns = lang_result['vulnerabilities']
                if vulns:
                    output += f"\n{lang_result.get('language', lang)}:\n"
                    for vuln in vulns[:5]:
                        output += f"  • [{vuln.severity}] {vuln.message}\n"
                    total_vulns += len(vulns)
        
        if total_vulns == 0:
            output += "  ✅ No known vulnerabilities found!"
        else:
            output += f"\n⚠️  Total vulnerabilities: {total_vulns}"
        
        return output
        
    except Exception as e:
        logger.error(f"Error scanning dependencies: {e}")
        return f"❌ Error: {str(e)}"

# ==================== Week 3 Handlers ====================

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
        
        # Get latest analysis results (in production, would retrieve from database)
        analysis_results = await project_analyzer.analyze_project(path_obj)
        
        # Generate report
        report = report_generator.generate_report(
            analysis_results,
            report_type=report_type,
            output_format=output_format
        )
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"analysis_report_{report_type}_{timestamp}.{output_format}"
        report_path = path_obj / report_filename
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report)
        
        # Return summary and first part of report
        summary = f"✅ Report generated: {report_path}\n\n"
        summary += "="*50 + "\n"
        summary += report[:1000]  # First 1000 characters
        if len(report) > 1000:
            summary += "\n\n... (truncated, see full report in file)"
        
        return summary
        
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
                [c['modules'] for c in cycles_analysis['cycles']],
                dep_result.get('patterns', {}).get('god_modules', [])
            )
            
            output += "\n\n" + format_refactoring_suggestions(suggestions)
        
        return output
        
    except Exception as e:
        logger.error(f"Error finding circular dependencies: {e}")
        return f"❌ Error: {str(e)}"

# ==================== Week 4 Handlers ====================

async def analyze_github_repo_handler(
    repo_url: str,
    branch: str,
    analysis_mode: str,
    github_token: Optional[str] = None
) -> str:
    """Handle GitHub repository analysis."""
    try:
        # Set token if provided
        if github_token:
            analyzer = GitHubAnalyzer(github_token)
        else:
            analyzer = github_analyzer
        
        # Parse and validate URL
        url_info = GitHubURLHandler.parse_url(repo_url)
        if url_info['type'] != 'repository':
            return f"❌ Invalid GitHub repository URL: {repo_url}"
        
        # Run analysis
        result = await analyzer.analyze_github_repo(
            repo_url,
            branch=branch,
            analysis_mode=analysis_mode
        )
        
        return format_github_analysis_results(result)
        
    except Exception as e:
        logger.error(f"Error analyzing GitHub repo: {e}")
        return f"❌ Error: {str(e)}"

async def github_security_scan_handler(
    repo_url: str,
    github_token: Optional[str] = None
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
        if len(repo_urls) < 2:
            return "❌ Please provide at least 2 repositories to compare"
        
        if len(repo_urls) > 5:
            return "❌ Maximum 5 repositories can be compared at once"
        
        results = {}
        
        # Analyze each repository
        for repo_url in repo_urls:
            try:
                result = await github_analyzer.analyze_github_repo(
                    repo_url,
                    analysis_mode='quick'
                )
                results[repo_url] = result
            except Exception as e:
                logger.error(f"Error analyzing {repo_url}: {e}")
                results[repo_url] = {'error': str(e)}
        
        # Generate comparison
        comparison = generate_repo_comparison(results, metrics)
        
        return format_repo_comparison(comparison)
        
    except Exception as e:
        logger.error(f"Error comparing repos: {e}")
        return f"❌ Error: {str(e)}"

# ==================== Utility Handlers ====================

async def get_analysis_history_handler(project_path: str, days: int) -> str:
    """Get historical analysis data."""
    try:
        history = await database.get_project_history(project_path, limit=50)
        trends = await database.get_trending_issues(days)
        
        output = f"""📊 Analysis History & Trends
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Project: {project_path}
📅 Period: Last {days} days

📈 Recent Analyses:
"""
        
        for entry in history[:10]:
            output += f"  • {entry['completed_at']}: "
            output += f"{entry['total_files']} files, "
            output += f"{entry['total_issues']} issues found\n"
        
        if trends['security_trends']:
            output += "\n🔒 Top Security Issues:\n"
            for trend in trends['security_trends'][:5]:
                output += f"  • {trend['rule_id']} ({trend['severity']}): "
                output += f"{trend['count']} occurrences\n"
        
        if trends['quality_trends']:
            output += "\n📏 Quality Metrics Trends:\n"
            for trend in trends['quality_trends']:
                output += f"  • {trend['metric_name']}: "
                output += f"avg {trend['avg_value']:.2f}\n"
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting history: {e}")
        return f"❌ Error: {str(e)}"

async def clear_cache_handler(older_than_days: int = 7) -> str:
    """Clear old cache entries."""
    try:
        # Clear file cache
        cleared_files = await cache.clear_old(older_than_days)
        
        # Clear old database entries
        cleared_db = await database.cleanup_old_data(older_than_days)
        
        return f"""🧹 Cache Cleanup Complete
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Cache files removed: {cleared_files}
📊 Database records cleaned: {cleared_db}
✅ All cache entries older than {older_than_days} days have been removed.
"""
        
    except Exception as e:
        logger.error(f"Error clearing cache: {e}")
        return f"❌ Error: {str(e)}"

# ==================== Formatting Functions ====================

def format_basic_analysis(result: Dict[str, Any]) -> str:
    """Format basic analysis results."""
    if 'error' in result:
        return f"❌ Error: {result['error']}"
    
    return f"""📊 File Analysis Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 File: {result.get('file_path', 'Unknown')}
📏 Size: {result.get('size_bytes', 0):,} bytes
🔤 Language: {result.get('language', 'Unknown')}

📈 Basic Metrics:
  • Lines of Code: {result.get('metrics', {}).get('loc', 0)}
  • Total Lines: {result.get('metrics', {}).get('total_lines', 0)}
  • Blank Lines: {result.get('metrics', {}).get('blank_lines', 0)}
  • Comment Lines: {result.get('metrics', {}).get('comment_lines', 0)}
  
📋 Code Elements:
  • Functions: {result.get('metrics', {}).get('functions', 'N/A')}
  • Classes: {result.get('metrics', {}).get('classes', 'N/A')}
  • Imports: {result.get('metrics', {}).get('imports', 'N/A')}
"""

def format_complexity_analysis(result: Dict[str, Any]) -> str:
    """Format complexity analysis results."""
    output = f"""🧮 Complexity Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 File: {result.get('file_path', 'Unknown')}

📊 Overall Metrics:
  • Average Complexity: {result.get('average_complexity', 0):.2f}
  • Max Complexity: {result.get('max_complexity', 0)}
  • Total Complexity: {result.get('total_complexity', 0)}
  • Risk Level: {result.get('risk_level', 'Unknown')}
  • Maintainability Index: {result.get('maintainability_index', 0):.1f}/100
"""
    
    if result.get('details'):
        output += "\n🔍 Detailed Breakdown:\n"
        for item in result['details'][:10]:  # Top 10
            output += f"  • {item['name']}: {item['complexity']} "
            output += f"({item['type']}) - {item['risk_level']}\n"
        
        if len(result['details']) > 10:
            output += f"  ... and {len(result['details']) - 10} more\n"
    
    if result.get('hotspots'):
        output += "\n🔥 Complexity Hotspots:\n"
        for hotspot in result['hotspots']:
            output += f"  • {hotspot['name']} ({hotspot['location']})\n"
            output += f"    Complexity: {hotspot['complexity']}\n"
            output += f"    💡 {hotspot['recommendation']}\n"
    
    return output

def format_security_results(result: Dict[str, Any]) -> str:
    """Format security scan results."""
    output = f"""🔒 Security Scan Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 File: {result.get('file_path', 'Unknown')}
📊 Total Issues: {result.get('total_issues', 0)}
⚠️  Risk Score: {result.get('risk_score', 0)}/100

🎯 Severity Breakdown:
  • Critical: {result.get('severity_counts', {}).get('critical', 0)}
  • High: {result.get('severity_counts', {}).get('high', 0)}
  • Medium: {result.get('severity_counts', {}).get('medium', 0)}
  • Low: {result.get('severity_counts', {}).get('low', 0)}
"""
    
    if result.get('issues'):
        output += "\n🚨 Top Security Issues:\n"
        for issue in result['issues'][:5]:
            output += f"\n  [{issue['severity']}] {issue['rule_id']}\n"
            output += f"  📍 Line {issue['location']['line']}: {issue['message']}\n"
            if issue.get('cwe'):
                output += f"  🔗 CWE: {issue['cwe']}\n"
            if issue.get('code_snippet'):
                snippet = issue['code_snippet'].strip().split('\n')[0][:60]
                output += f"  📝 Code: {snippet}...\n"
    else:
        output += "\n✅ No security issues found!"
    
    return output

def format_quality_results(result: Dict[str, Any]) -> str:
    """Format quality check results."""
    output = f"""📏 Code Quality Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 File: {result.get('file_path', 'Unknown')}
🏆 Quality Score: {result.get('quality_score', 0)}/100
📊 Total Issues: {result.get('total_issues', 0)}

📈 Issue Severity:
  • High: {result.get('issues_by_severity', {}).get('high', 0)}
  • Medium: {result.get('issues_by_severity', {}).get('medium', 0)}
  • Low: {result.get('issues_by_severity', {}).get('low', 0)}
"""
    
    if result.get('metrics'):
        output += "\n📊 Code Metrics:\n"
        metrics = result['metrics']
        if 'max_function_length' in metrics:
            output += f"  • Longest Function: {metrics['max_function_length']} lines\n"
        if 'max_class_length' in metrics:
            output += f"  • Largest Class: {metrics['max_class_length']} lines\n"
        if 'max_nesting_depth' in metrics:
            output += f"  • Max Nesting: {metrics['max_nesting_depth']} levels\n"
        if 'docstring_coverage' in metrics:
            output += f"  • Documentation: {metrics['docstring_coverage']*100:.0f}%\n"
    
    if result.get('issues'):
        output += "\n🔍 Top Quality Issues:\n"
        for issue in result['issues'][:5]:
            output += f"  • {issue['type']}: {issue['message']} (Line {issue['location']['line']})\n"
            if issue.get('suggestion'):
                output += f"    💡 {issue['suggestion']}\n"
    
    return output

def format_todo_results(result: Dict[str, Any]) -> str:
    """Format TODO findings."""
    output = f"""📝 TODO/FIXME Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Total Items: {result.get('total_todos', 0)}

📌 By Type:
"""
    for todo_type, count in result.get('by_type', {}).items():
        output += f"  • {todo_type}: {count}\n"
    
    output += "\n⚡ By Priority:\n"
    for priority, count in result.get('by_priority', {}).items():
        output += f"  • {priority}: {count}\n"
    
    summary = result.get('summary', {})
    if summary.get('high_priority_count', 0) > 0:
        output += f"\n🚨 High Priority Items: {summary['high_priority_count']}\n"
    
    if summary.get('old_todos_count', 0) > 0:
        output += f"\n⏰ Old TODOs (>3 months): {summary['old_todos_count']}\n"
    
    if summary.get('files_with_most_todos'):
        output += "\n📁 Files with Most TODOs:\n"
        for file_path, count in summary['files_with_most_todos'][:5]:
            output += f"  • {Path(file_path).name}: {count} items\n"
    
    if summary.get('recommendations'):
        output += "\n💡 Recommendations:\n"
        for rec in summary['recommendations']:
            output += f"  • {rec}\n"
    
    return output

def format_dead_code_results(result: Dict[str, Any]) -> str:
    """Format dead code detection results."""
    output = f"""🧹 Dead Code Detection
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 File: {result.get('file_path', 'Unknown')}
🗑️  Total Dead Code: {result.get('total_dead_code', 0)}

📊 By Type:
"""
    for code_type, count in result.get('by_type', {}).items():
        output += f"  • {code_type}: {count}\n"
    
    if result.get('items'):
        output += "\n🔍 Dead Code Items:\n"
        for item in result['items'][:10]:
            output += f"  • Line {item['line']}: {item['message']}\n"
            if item.get('name'):
                output += f"    Name: {item['name']}\n"
        
        if len(result['items']) > 10:
            output += f"\n  ... and {len(result['items']) - 10} more items\n"
    
    if result.get('total_dead_code', 0) == 0:
        output += "\n✅ No dead code found!"
    else:
        output += "\n💡 Consider removing unused code to improve maintainability."
    
    return output

def format_dependency_results(result: Dict[str, Any]) -> str:
    """Format dependency analysis results."""
    metrics = result.get('metrics', {})
    patterns = result.get('patterns', {})
    
    output = f"""🔗 Dependency Analysis Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 Path: {result.get('path', 'Unknown')}

📊 Metrics:
  • Total Dependencies: {metrics.get('total_dependencies', 0)}
  • External Dependencies: {metrics.get('external_dependencies', 0)}
  • Internal Dependencies: {metrics.get('internal_dependencies', 0)}
  • Circular Dependencies: {len(metrics.get('circular_dependencies', []))}
  • Average Coupling: {metrics.get('coupling_score', 0):.1f}
  • Cohesion Score: {metrics.get('cohesion_score', 0):.2f}
  • Instability: {metrics.get('instability', 0):.2f}
  • Abstractness: {metrics.get('abstractness', 0):.2f}
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
        
        if len(circular) > 5:
            output += f"\n  ... and {len(circular) - 5} more cycles\n"
    
    # Patterns
    if patterns.get('god_modules'):
        output += "\n⚠️ God Modules (high coupling):\n"
        for module in patterns['god_modules'][:5]:
            output += f"  • {module['module']}: {module['outgoing_dependencies']} dependencies\n"
    
    if patterns.get('hub_modules'):
        output += "\n🎯 Hub Modules (high fan-in):\n"
        for module in patterns['hub_modules'][:5]:
            output += f"  • {module['module']}: {module['incoming_dependencies']} incoming\n"
    
    if patterns.get('isolated_modules'):
        output += f"\n🏝️ Isolated Modules: {len(patterns['isolated_modules'])}\n"
    
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
📁 Project: {Path(result.get('project_path', 'Unknown')).name}
⏱️ Duration: {result.get('duration', 0):.1f}s

📈 Overview:
  • Files Analyzed: {summary.get('total_files', 0)}
  • Total LOC: {metrics.get('totals', {}).get('loc', 0):,}
  • Total Issues: {len(result.get('issues', []))}
  • Functions: {metrics.get('totals', {}).get('functions', 0)}
  • Classes: {metrics.get('totals', {}).get('classes', 0)}

🎯 Health Scores:
  • Overall Health: {summary.get('overall_health', 0):.1f}/100
  • Security Score: {summary.get('security_score', 0):.1f}/100
  • Quality Score: {summary.get('quality_score', 0):.1f}/100
  • Complexity Score: {summary.get('complexity_score', 0):.1f}/100
  • Maintainability: {summary.get('maintainability_score', 0):.1f}/100

📊 Averages:
  • Complexity: {metrics.get('averages', {}).get('complexity', 0):.1f}
  • Quality: {metrics.get('averages', {}).get('quality', 0):.1f}
  • LOC per File: {metrics.get('averages', {}).get('loc_per_file', 0):.0f}
"""
    
    # Language distribution
    if metrics.get('by_language'):
        output += "\n🔤 Language Distribution:\n"
        for lang, lang_metrics in metrics['by_language'].items():
            output += f"  • {lang}: {lang_metrics['files']} files, {lang_metrics['loc']:,} LOC\n"
    
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
        for i, rec in enumerate(result['recommendations'][:5]):
            output += f"  {i+1}. {rec}\n"
    
    # Visualizations
    if result.get('visualizations'):
        output += "\n📊 Generated Visualizations:\n"
        for viz_name in result['visualizations'].keys():
            output += f"  • {viz_name}\n"
    
    return output

def format_circular_dependencies(analysis: Dict[str, Any]) -> str:
    """Format circular dependency analysis."""
    output = f"""🔄 Circular Dependency Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Cycles Found: {analysis.get('total_cycles', 0)}
Overall Severity: {analysis.get('overall_severity', 0)}/10
Affected Modules: {len(analysis.get('affected_modules', []))}
"""
    
    if analysis.get('cycles'):
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
        
        if len(analysis['cycles']) > 10:
            output += f"\n... and {len(analysis['cycles']) - 10} more cycles\n"
    
    if analysis.get('breaking_points'):
        output += "\n✂️ Suggested Breaking Points:\n"
        for bp in analysis['breaking_points'][:5]:
            output += f"  • Break: {bp['source']} → {bp['target']}\n"
            output += f"    Impact Score: {bp['impact_score']:.1f}\n"
            output += f"    💡 {bp['suggestion']}\n"
    
    if analysis.get('recommendations'):
        output += "\n💡 Resolution Recommendations:\n"
        for rec in analysis['recommendations']:
            output += f"  • {rec}\n"
    
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
                # Show first few lines of implementation
                impl_lines = pattern['implementation'].strip().split('\n')[:5]
                output += f"\n  Example:\n```python\n"
                output += '\n'.join(impl_lines)
                output += "\n  ...\n```\n"
    
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
            if interface.get('methods'):
                output += "    Methods:\n"
                for method in interface['methods'][:3]:
                    output += f"      - {method}\n"
    
    if suggestions.get('specific_changes'):
        output += "\n📝 Specific Code Changes:\n"
        for change in suggestions['specific_changes'][:5]:
            output += f"  • File: {change['file']}\n"
            output += f"    Current: {change['current']}\n"
            output += f"    Suggested: {change['suggested']}\n"
            output += f"    Reason: {change['reason']}\n"
    
    return output

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
  • Stars: ⭐ {metadata.get('stars', 0):,}
  • Forks: 🍴 {metadata.get('forks', 0):,}
  • Open Issues: 🐛 {metadata.get('open_issues', 0)}
  • Size: 💾 {metadata.get('size_kb', 0):,} KB
  • Language: 🔤 {metadata.get('primary_language', 'Unknown')}
  • Contributors: 👥 {metadata.get('contributors', 0)}
  • License: 📄 {metadata.get('license', 'None')}
  • Created: 📅 {metadata.get('created_at', 'Unknown')[:10]}
  • Updated: 🔄 {metadata.get('updated_at', 'Unknown')[:10]}
"""
    
    # Language breakdown
    if metadata.get('languages'):
        output += "\n💻 Languages:\n"
        total_bytes = sum(metadata['languages'].values())
        for lang, bytes_count in sorted(metadata['languages'].items(), 
                                      key=lambda x: x[1], reverse=True)[:5]:
            percentage = (bytes_count / total_bytes * 100) if total_bytes > 0 else 0
            output += f"  • {lang}: {percentage:.1f}%\n"
    
    # Add badges
    if insights.get('badges'):
        output += f"\n🏅 Badges: {' '.join(insights['badges'])}\n"
    
    # Add analysis results based on mode
    if analysis.get('mode') == 'quick':
        output += f"""
📁 File Summary:
  • Total Files: {analysis.get('file_summary', {}).get('total_files', 0):,}
  • Supported Files: {analysis.get('file_summary', {}).get('supported_files', 0)}
  • Total Size: {analysis.get('file_summary', {}).get('total_size_bytes', 0):,} bytes

🏗️ Structure:
  • Directories: {analysis.get('structure', {}).get('total_directories', 0)}
  • Max Depth: {analysis.get('structure', {}).get('max_depth', 0)}
  • Has Tests: {'✅' if analysis.get('structure', {}).get('has_tests') else '❌'}
  • Has Docs: {'✅' if analysis.get('structure', {}).get('has_docs') else '❌'}
  • Has CI/CD: {'✅' if analysis.get('structure', {}).get('has_ci') else '❌'}
"""
        
        # Sample analysis
        if analysis.get('sample_analysis'):
            sample = analysis['sample_analysis']
            output += f"""
📊 Sample Analysis ({sample.get('files_analyzed', 0)} files):
  • Total LOC: {sample.get('total_loc', 0):,}
  • Issues Found: {sample.get('issues_found', 0)}
"""
            if sample.get('complexity_samples'):
                output += "  • Complexity Samples:\n"
                for comp in sample['complexity_samples'][:3]:
                    output += f"    - {Path(comp['file']).name}: {comp['complexity']}\n"
    
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
    
    # Git info
    if analysis.get('git_info'):
        git_info = analysis['git_info']
        output += f"""
📝 Git Activity:
  • Recent Commits: {git_info.get('recent_commits', 0)}
  • Active Contributors: {git_info.get('active_contributors', 0)}
  • Commit Frequency: {git_info.get('commit_frequency_per_day', 0):.2f}/day
  • Branches: {len(git_info.get('branches', []))}
  • Tags: {len(git_info.get('tags', []))}
"""
    
    # Health indicators
    if insights.get('health_indicators'):
        health = insights['health_indicators']
        output += "\n🏥 Health Indicators:\n"
        for indicator, value in health.items():
            icon = '✅' if value in ['active', 'high', 'healthy', 'present', 'configured'] else '⚠️'
            output += f"  • {indicator.replace('_', ' ').title()}: {icon} {value}\n"
    
    # Insights and recommendations
    if insights.get('overall_health_score'):
        output += f"\n🎯 Overall Repository Health: {insights['overall_health_score']:.1f}/100\n"
    
    if insights.get('recommendations'):
        output += "\n💡 Recommendations:\n"
        for rec in insights['recommendations'][:5]:
            output += f"  • {rec}\n"
    
    return output

def format_github_security_results(result: Dict[str, Any]) -> str:
    """Format GitHub security scan results."""
    output = f"""🔒 GitHub Security Scan Results
━━━━━━━━━━━━━━━━
🛡️ Security Score: {result.get('security_score', 0):.1f}/100

📊 Vulnerability Summary:
 • Security Advisories: {len(result.get('security_advisories', []))}
 • Dependabot Alerts: {len(result.get('dependabot_alerts', []))}
 • Secret Scanning Alerts: {len(result.get('secret_scanning', []))}
"""
    
    # Details on vulnerabilities
    if result.get('security_advisories'):
        output += "\n🚨 Security Advisories:\n"
        for adv in result['security_advisories'][:5]:
            severity = adv.get('severity', 'UNKNOWN')
            severity_icon = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MODERATE': '🟡',
                'LOW': '🟢'
            }.get(severity, '⚪')
            
            output += f"  • {severity_icon} [{severity}] {adv.get('package', 'Unknown package')}\n"
            output += f"    {adv.get('summary', 'No summary')}\n"
            if adv.get('score'):
                output += f"    CVSS Score: {adv['score']}\n"
        
        if len(result['security_advisories']) > 5:
            output += f"\n  ... and {len(result['security_advisories']) - 5} more advisories\n"
    
    if result.get('dependabot_alerts'):
        output += "\n🤖 Dependabot Alerts:\n"
        for alert in result['dependabot_alerts'][:5]:
            severity = alert.get('severity', 'unknown')
            severity_icon = {
                'critical': '🔴',
                'high': '🟠',
                'moderate': '🟡',
                'low': '🟢'
            }.get(severity, '⚪')
            
            output += f"  • {severity_icon} [{severity}] {alert.get('package', 'Unknown')}\n"
            output += f"    Vulnerable: {alert.get('vulnerable_version', 'Unknown version')}\n"
            if alert.get('cve_id'):
                output += f"    CVE: {alert['cve_id']}\n"
            output += f"    {alert.get('description', '')[:100]}...\n"
        
        if len(result['dependabot_alerts']) > 5:
            output += f"\n  ... and {len(result['dependabot_alerts']) - 5} more alerts\n"
    
    if result.get('secret_scanning'):
        output += "\n🔑 Secret Scanning Alerts:\n"
        output += "  ⚠️  CRITICAL: Exposed secrets detected!\n"
        for secret in result['secret_scanning'][:3]:
            output += f"  • {secret.get('secret_type', 'Unknown type')}\n"
            output += f"    Created: {secret.get('created_at', 'Unknown')[:10]}\n"
    
    # Security file status
    security_files = result.get('security_files', {})
    output += "\n📁 Security Configuration:\n"
    
    security_file_checks = [
        ('SECURITY.md', security_files.get('SECURITY.md') or security_files.get('.github/SECURITY.md'), 
         'Security policy'),
        ('Dependabot', security_files.get('.github/dependabot.yml'), 
         'Automated dependency updates'),
        ('CodeQL', security_files.get('.github/workflows/codeql-analysis.yml'), 
         'Code security analysis'),
        ('.gitignore', security_files.get('.gitignore'), 
         'Prevent sensitive file commits')
    ]
    
    for name, present, description in security_file_checks:
        icon = '✅' if present else '❌'
        output += f"  • {name}: {icon} {description}\n"
    
    # Recommendations
    if result.get('recommendations'):
        output += "\n💡 Security Recommendations:\n"
        for rec in result['recommendations']:
            output += f"  {rec}\n"
    
    # Risk assessment
    score = result.get('security_score', 100)
    if score >= 90:
        risk_level = "🟢 Low Risk"
        risk_message = "Repository has good security practices"
    elif score >= 70:
        risk_level = "🟡 Medium Risk"
        risk_message = "Some security improvements recommended"
    elif score >= 50:
        risk_level = "🟠 High Risk"
        risk_message = "Significant security issues need attention"
    else:
        risk_level = "🔴 Critical Risk"
        risk_message = "Immediate security action required"
    
    output += f"\n⚠️  Risk Assessment: {risk_level}\n   {risk_message}\n"
    
    return output

def generate_repo_comparison(
   results: Dict[str, Dict[str, Any]],
   metrics: List[str]
) -> Dict[str, Any]:
   """Generate repository comparison data."""
   comparison = {
       'repositories': [],
       'metrics': {},
       'rankings': {}
   }
   
   for repo_url, result in results.items():
       if 'error' in result:
           continue
           
       repo_data = {
           'url': repo_url,
           'name': result.get('repository', {}).get('name', 'Unknown'),
           'owner': result.get('repository', {}).get('owner', 'Unknown'),
           'metadata': result.get('metadata', {}),
           'scores': {},
           'metrics': {}
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
       
       # Extract metrics
       if 'analysis' in result:
           analysis = result['analysis']
           if 'metrics' in analysis:
               repo_data['metrics'] = {
                   'loc': analysis['metrics'].get('totals', {}).get('loc', 0),
                   'files': analysis.get('summary', {}).get('total_files', 0),
                   'avg_complexity': analysis['metrics'].get('averages', {}).get('complexity', 0)
               }
           elif 'file_summary' in analysis:
               repo_data['metrics'] = {
                   'files': analysis['file_summary'].get('total_files', 0),
                   'size_kb': result['metadata'].get('size_kb', 0)
               }
       
       comparison['repositories'].append(repo_data)
   
   # Calculate metric comparisons
   for metric in metrics:
       if metric == 'activity':
           comparison['metrics']['activity'] = [
               {
                   'repo': r['name'],
                   'stars': r['metadata'].get('stars', 0),
                   'forks': r['metadata'].get('forks', 0),
                   'commits': r['metadata'].get('recent_commits', 0),
                   'contributors': r['metadata'].get('contributors', 0),
                   'last_updated': r['metadata'].get('updated_at', 'Unknown')[:10]
               }
               for r in comparison['repositories']
           ]
       elif metric == 'popularity':
           comparison['metrics']['popularity'] = [
               {
                   'repo': r['name'],
                   'stars': r['metadata'].get('stars', 0),
                   'forks': r['metadata'].get('forks', 0),
                   'watchers': r['metadata'].get('watchers', 0)
               }
               for r in comparison['repositories']
           ]
       elif metric == 'quality':
           comparison['metrics']['quality'] = [
               {
                   'repo': r['name'],
                   'quality_score': r['scores'].get('quality', 0),
                   'has_tests': any('test' in lang.lower() for lang in r['metadata'].get('languages', {})),
                   'has_ci': r.get('analysis', {}).get('structure', {}).get('has_ci', False),
                   'documentation': 'README' in str(r.get('analysis', {}).get('key_files', []))
               }
               for r in comparison['repositories']
           ]
       elif metric == 'security':
           comparison['metrics']['security'] = [
               {
                   'repo': r['name'],
                   'security_score': r['scores'].get('security', 0),
                   'open_issues': r['metadata'].get('open_issues', 0)
               }
               for r in comparison['repositories']
           ]
       elif metric == 'complexity':
           comparison['metrics']['complexity'] = [
               {
                   'repo': r['name'],
                   'complexity_score': r['scores'].get('complexity', 0),
                   'avg_complexity': r['metrics'].get('avg_complexity', 0),
                   'loc': r['metrics'].get('loc', 0),
                   'files': r['metrics'].get('files', 0)
               }
               for r in comparison['repositories']
           ]
   
   # Generate rankings
   if comparison['repositories']:
       # Overall ranking
       comparison['rankings']['overall'] = sorted(
           comparison['repositories'],
           key=lambda r: r['scores'].get('overall', 0),
           reverse=True
       )
       
       # Category rankings
       for category in ['security', 'quality', 'complexity']:
           comparison['rankings'][category] = sorted(
               comparison['repositories'],
               key=lambda r: r['scores'].get(category, 0),
               reverse=True
           )
       
       comparison['rankings']['popularity'] = sorted(
           comparison['repositories'],
           key=lambda r: r['metadata'].get('stars', 0),
           reverse=True
       )
   
   return comparison

def format_repo_comparison(comparison: Dict[str, Any]) -> str:
   """Format repository comparison results."""
   output = "📊 Repository Comparison\n"
   output += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
   
   repos = comparison['repositories']
   
   if not repos:
       return output + "❌ No valid repositories to compare"
   
   # Summary table
   output += "📈 Overview:\n"
   output += "```\n"
   output += f"{'Repository':<25} {'Stars':>8} {'Overall':>8} {'Security':>8} {'Quality':>8}\n"
   output += "-" * 65 + "\n"
   
   for repo in repos[:5]:
       name = f"{repo['owner']}/{repo['name']}"[:24]
       stars = repo['metadata'].get('stars', 0)
       overall = repo['scores'].get('overall', 0)
       security = repo['scores'].get('security', 0)
       quality = repo['scores'].get('quality', 0)
       
       output += f"{name:<25} {stars:>8,} {overall:>8.1f} {security:>8.1f} {quality:>8.1f}\n"
   
   output += "```\n"
   
   # Best in each category
   rankings = comparison.get('rankings', {})
   if rankings:
       output += "\n🏆 Category Winners:\n"
       
       categories = [
           ('overall', '🥇 Best Overall', 'overall'),
           ('security', '🔒 Most Secure', 'security'),
           ('quality', '📏 Best Quality', 'quality'),
           ('popularity', '⭐ Most Popular', 'stars')
       ]
       
       for rank_key, label, score_key in categories:
           if rank_key in rankings and rankings[rank_key]:
               winner = rankings[rank_key][0]
               score = winner['scores'].get(score_key, 0) if score_key != 'stars' else winner['metadata'].get('stars', 0)
               output += f"  {label}: {winner['owner']}/{winner['name']}"
               
               if isinstance(score, (int, float)):
                   if score_key == 'stars':
                       output += f" ({score:,} stars)"
                   else:
                       output += f" (Score: {score:.1f})"
               output += "\n"
   
   # Detailed metrics comparison
   metrics = comparison.get('metrics', {})
   
   if 'activity' in metrics:
       output += "\n📊 Activity Comparison:\n"
       activity_data = sorted(metrics['activity'], key=lambda x: x['stars'], reverse=True)
       
       for data in activity_data[:5]:
           output += f"\n  **{data['repo']}**\n"
           output += f"    • Stars: {data['stars']:,}\n"
           output += f"    • Forks: {data['forks']:,}\n"
           output += f"    • Contributors: {data['contributors']}\n"
           output += f"    • Last Updated: {data['last_updated']}\n"
   
   if 'complexity' in metrics:
       output += "\n🧮 Complexity Analysis:\n"
       complexity_data = sorted(metrics['complexity'], 
                              key=lambda x: x.get('avg_complexity', 0))
       
       for data in complexity_data:
           output += f"  • {data['repo']}: "
           output += f"Avg {data.get('avg_complexity', 0):.1f}, "
           output += f"{data.get('loc', 0):,} LOC, "
           output += f"{data.get('files', 0)} files\n"
   
   # Insights
   output += "\n💡 Key Insights:\n"
   
   # Find outliers and interesting patterns
   if repos:
       # Highest stars but lowest quality
       popular_but_poor = max(
           repos, 
           key=lambda r: r['metadata'].get('stars', 0) - r['scores'].get('quality', 0) * 100
       )
       
       if popular_but_poor['metadata'].get('stars', 0) > 100 and popular_but_poor['scores'].get('quality', 100) < 70:
           output += f"  • {popular_but_poor['name']} is popular but has quality issues\n"
       
       # Best overall but least popular
       underrated = min(
           [r for r in repos if r['scores'].get('overall', 0) > 70],
           key=lambda r: r['metadata'].get('stars', 0),
           default=None
       )
       
       if underrated and underrated['metadata'].get('stars', 0) < 1000:
           output += f"  • {underrated['name']} is high quality but underrated\n"
       
       # Security concerns
       security_risks = [r for r in repos if r['scores'].get('security', 100) < 60]
       if security_risks:
           output += f"  • {len(security_risks)} repositories have security concerns\n"
   
   return output

# ==================== Main Entry Point ====================

async def main():
   """Main entry point for the MCP server."""
   logger.info("Starting MCP Code Analyzer Server")
   
   # Initialize database migrations
   from .storage.migrations import MigrationManager
   migration_manager = MigrationManager(database.db_path)
   migration_manager.run_migrations()
   
   # Start server
   async with stdio.stdio_server() as (read_stream, write_stream):
       await server.run(read_stream, write_stream)

if __name__ == "__main__":
   # Setup logging
   setup_logger("mcp-analyzer", "INFO")
   
   # Print startup banner
   print("""
╔═══════════════════════════════════════════════════════════════╗
║                   MCP Code Analyzer Server                    ║
║                        Version 1.0.0                          ║
║                                                               ║
║  Comprehensive code analysis with:                            ║
║  • Security scanning & vulnerability detection                ║
║  • Code quality & complexity analysis                         ║
║  • Dependency mapping & circular dependency detection         ║
║  • Multi-language support (Python, JavaScript, and more)      ║
║  • GitHub repository analysis                                 ║
║  • Professional reporting & visualizations                    ║
╚═══════════════════════════════════════════════════════════════╝

Starting server...
   """)
   
   # Run the server
   asyncio.run(main())