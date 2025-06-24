# src/cli.py (updated with Week 2 commands)
import asyncio
import click
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
import json
from pprint import pprint

from analyzers.security import SecurityAnalyzer
from analyzers.quality import QualityAnalyzer
from analyzers.dependencies import DependencyAnalyzer
from analyzers.project_analyzer import ProjectAnalyzer, AnalysisReportGenerator
from analyzers.github_analyzer import GitHubAnalyzer
from utils.visualizer import DependencyVisualizer
from storage.database import AnalysisDatabase

# Initialize components
console = Console()
security_analyzer = SecurityAnalyzer()
quality_analyzer = QualityAnalyzer()
dependency_analyzer = DependencyAnalyzer()
project_analyzer = ProjectAnalyzer()
github_analyzer = GitHubAnalyzer()
visualizer = DependencyVisualizer()
report_generator = AnalysisReportGenerator()
database = AnalysisDatabase()

@click.group()
def cli():
    """Code Analysis CLI Tool"""
    pass

# src/cli.py (updated with Week 3 commands)
@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--depth', default=3, help='Dependency analysis depth')
@click.option('--format', 'output_format', 
              type=click.Choice(['text', 'mermaid', 'd3', 'graphviz']),
              default='text', help='Output format')
@click.option('--show-external', is_flag=True, help='Show external dependencies')
@click.option('--visualize', is_flag=True, help='Show dependency graph visualization (ASCII/Markdown if text)')
@click.option('--export-graph', type=click.Path(), help='Export dependency graph to file (format based on --format)')
def dependencies(path: str, depth: int, output_format: str, show_external: bool, visualize: bool, export_graph: str):
    """Analyze code dependencies."""
    asyncio.run(_analyze_dependencies(Path(path), depth, output_format, show_external, visualize, export_graph))

async def _analyze_dependencies(
    path: Path, 
    depth: int, 
    output_format: str,
    show_external: bool,
    visualize: bool = False,
    export_graph: str = None
):
    """Async dependency analysis."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Analyzing dependencies...", total=None)
        
        result = await dependency_analyzer.analyze_dependencies(
            path,
            depth=depth,
            include_external=show_external
        )
        
        if output_format == 'text':
            console.print("\n[bold cyan]Dependency Analysis[/bold cyan]")
            _display_dependency_results(result)
            if visualize:
                viz_data = result.get('visualization', {})
                ascii_graph = _generate_ascii_dependency_graph(viz_data)
                console.print("\n[bold]Dependency Graph (ASCII):[/bold]\n")
                console.print(ascii_graph)
        elif output_format in ['mermaid', 'd3', 'graphviz']:
            viz_data = result.get('visualization', {})
            graph = visualizer.generate_dependency_graph(
                viz_data,
                output_format=output_format
            )
            console.print(graph)
            if export_graph:
                with open(export_graph, 'w') as f:
                    f.write(graph)
                console.print(f"[green]Graph exported to {export_graph}[/green]")
        elif export_graph:
            # Export text/ASCII graph
            viz_data = result.get('visualization', {})
            ascii_graph = _generate_ascii_dependency_graph(viz_data)
            with open(export_graph, 'w') as f:
                f.write(ascii_graph)
            console.print(f"[green]ASCII graph exported to {export_graph}[/green]")

def _generate_ascii_dependency_graph(viz_data: dict) -> str:
    """Generate a simple ASCII dependency graph (tree-like)."""
    if not viz_data or 'nodes' not in viz_data or 'edges' not in viz_data:
        return "[No graph data available]"
    # Build adjacency list
    from collections import defaultdict
    adj = defaultdict(list)
    for edge in viz_data['edges']:
        adj[edge['source']].append(edge['target'])
    # Find roots (nodes not appearing as targets)
    all_nodes = {n['id'] for n in viz_data['nodes']}
    targets = {e['target'] for e in viz_data['edges']}
    roots = list(all_nodes - targets)
    # Node labels
    labels = {n['id']: n['label'] for n in viz_data['nodes']}
    # DFS print
    lines = []
    def dfs(node, prefix=""):
        lines.append(f"{prefix}- {labels.get(node, node)}")
        for child in adj.get(node, []):
            dfs(child, prefix + "  ")
    for root in roots:
        dfs(root)
    return "\n".join(lines) if lines else "[No graph structure]"

def _display_dependency_results(result: Dict[str, Any]):
    """Display dependency analysis results."""
    metrics = result.get('metrics', {})
    
    # Summary table
    summary_table = Table(title="Dependency Metrics")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="green")
    
    summary_table.add_row("Total Dependencies", str(metrics.get('total_dependencies', 0)))
    summary_table.add_row("External Dependencies", str(metrics.get('external_dependencies', 0)))
    summary_table.add_row("Circular Dependencies", str(len(metrics.get('circular_dependencies', []))))
    summary_table.add_row("Average Coupling", f"{metrics.get('coupling_score', 0):.1f}")
    summary_table.add_row("Instability", f"{metrics.get('instability', 0):.2f}")
    
    console.print(summary_table)
    
    # Circular dependencies
    circular = metrics.get('circular_dependencies', [])
    if circular:
        console.print("\n[red]Circular Dependencies Found:[/red]")
        for i, cycle in enumerate(circular[:5]):
            console.print(f"  {i+1}. {' → '.join(cycle)}")

@cli.command()
@click.argument('project_path', type=click.Path(exists=True))
@click.option('--config', type=click.Path(exists=True), 
              help='Configuration file (JSON)')
@click.option('--output', type=click.Path(), 
              help='Output directory for reports')
@click.option('--format', 'report_format',
              type=click.Choice(['console', 'markdown', 'html']),
              default='console', help='Report format')
def analyze_project(project_path: str, config: str, output: str, report_format: str):
    """Perform comprehensive project analysis."""
    asyncio.run(_analyze_project(
        Path(project_path), 
        Path(config) if config else None,
        Path(output) if output else None,
        report_format
    ))

async def _analyze_project(
    project_path: Path,
    config_path: Optional[Path],
    output_path: Optional[Path],
    report_format: str
):
    """Async project analysis."""
    # Load config if provided
    config = None
    if config_path:
        with open(config_path, 'r') as f:
            config = json.load(f)
    
    # Progress display
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        
        def progress_callback(message: str, current: int, total: int):
            if not hasattr(progress_callback, 'task'):
                progress_callback.task = progress.add_task(
                    "Analyzing project...", 
                    total=total
                )
            progress.update(progress_callback.task, description=message, completed=current)
        
        # Run analysis
        result = await project_analyzer.analyze_project(
            project_path,
            config=config,
            progress_callback=progress_callback
        )
    
    # Display or save results
    if report_format == 'console':
        _display_project_results(result)
    else:
        # Generate report
        report = report_generator.generate_report(
            result,
            report_type='detailed',
            output_format='markdown' if report_format == 'markdown' else 'html'
        )
        
        # Save report
        if not output_path:
            output_path = project_path
        
        report_file = output_path / f"analysis_report.{report_format}"
        with open(report_file, 'w') as f:
            f.write(report)
        
        console.print(f"[green]Report saved to: {report_file}[/green]")

def _display_project_results(result: Dict[str, Any]):
    """Display project analysis results."""
    summary = result.get('summary', {})
    
    # Health scores
    health_table = Table(title="Project Health Scores")
    health_table.add_column("Metric", style="cyan")
    health_table.add_column("Score", style="bold")
    health_table.add_column("Grade", style="bold")
    
    for metric, score in summary.items():
        if 'score' in metric:
            grade = _get_grade(score)
            color = _get_grade_color(grade)
            health_table.add_row(
                metric.replace('_', ' ').title(),
                f"{score:.1f}/100",
                f"[{color}]{grade}[/{color}]"
            )
    
    console.print(health_table)
    
    # Issues summary
    issues = result.get('issues', [])
    if issues:
        issue_counts = {}
        for issue in issues:
            sev = issue.get('severity', 'UNKNOWN')
            issue_counts[sev] = issue_counts.get(sev, 0) + 1
        
        issue_table = Table(title="Issues by Severity")
        issue_table.add_column("Severity", style="bold")
        issue_table.add_column("Count", style="bold")
        
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if sev in issue_counts:
                color = {
                    'CRITICAL': 'red',
                    'HIGH': 'bright_red',
                    'MEDIUM': 'yellow',
                    'LOW': 'green'
                }.get(sev, 'white')
                issue_table.add_row(
                    f"[{color}]{sev}[/{color}]",
                    str(issue_counts[sev])
                )
        
        console.print("\n")
        console.print(issue_table)
    
    # Recommendations
    if result.get('recommendations'):
        console.print("\n[bold yellow]Top Recommendations:[/bold yellow]")
        for i, rec in enumerate(result['recommendations'][:5]):
            console.print(f"  {i+1}. {rec}")

    # Per-file/module summaries
    if 'analysis' in result and 'files' in result['analysis']:
        files = result['analysis']['files']
        console.print(f"\n[bold]📂 Per-File/Module Summary:[/bold]")
        for i, (file_path, file_data) in enumerate(list(files.items())[:10]):  # Show first 10 files
            if 'error' in file_data:
                continue
            analyses = file_data.get('analyses', {})
            console.print(f"\n[bold]{i+1}. {file_path}[/bold]")
            # Complexity
            if 'complexity' in analyses:
                comp = analyses['complexity']
                avg = comp.get('average_complexity', 0)
                maxc = comp.get('max_complexity', 0)
                mi = comp.get('maintainability_index', 0)
                console.print(f"   [cyan]Complexity:[/cyan] avg={avg:.1f}, max={maxc}, MI={mi}")
            # Quality
            if 'quality' in analyses:
                qual = analyses['quality']
                score = qual.get('quality_score', 0)
                total = qual.get('total_issues', 0)
                console.print(f"   [green]Quality:[/green] score={score}, issues={total}")
                for issue in qual.get('issues', [])[:2]:
                    console.print(f"     - {issue.get('message', '')}")
                    if 'code_snippet' in issue and issue['code_snippet']:
                        console.print(f"       [dim]Code:[/dim] {issue['code_snippet']}")
                    if 'reference' in issue and issue['reference']:
                        console.print(f"       [dim]Reference:[/dim] {issue['reference']}")
                    if 'fix_suggestion' in issue and issue['fix_suggestion']:
                        console.print(f"       [dim]Fix:[/dim] {issue['fix_suggestion']}")
            # Security
            if 'security' in analyses:
                sec = analyses['security']
                total = sec.get('total_issues', 0)
                console.print(f"   [red]Security:[/red] issues={total}")
                for issue in sec.get('issues', [])[:2]:
                    console.print(f"     - {issue.get('message', '')}")
                    if 'code_snippet' in issue and issue['code_snippet']:
                        console.print(f"       [dim]Code:[/dim] {issue['code_snippet']}")
                    if 'cwe' in issue and issue['cwe']:
                        console.print(f"       [dim]CWE:[/dim] {issue['cwe']}")
                    if 'owasp' in issue and issue['owasp']:
                        console.print(f"       [dim]OWASP:[/dim] {issue['owasp']}")
                    if 'fix_suggestion' in issue and issue['fix_suggestion']:
                        console.print(f"       [dim]Fix:[/dim] {issue['fix_suggestion']}")
        if len(files) > 10:
            console.print(f"\n... and {len(files) - 10} more files")

    # Dependency Graph Visualization
    if 'dependencies' in result and 'visualization' in result['dependencies']:
        viz = result['dependencies']['visualization']
        if viz.get('format') == 'network' and viz.get('nodes') and viz.get('edges'):
            console.print(f"\n[bold]🕸️ Dependency Graph (ASCII/Markdown):[/bold]")
            # Simple ASCII/Markdown graph: show top 10 nodes and their edges
            nodes = viz['nodes'][:10]
            node_ids = {n['id'] for n in nodes}
            edges = [e for e in viz['edges'] if e['source'] in node_ids and e['target'] in node_ids]
            for node in nodes:
                out_edges = [e for e in edges if e['source'] == node['id']]
                if out_edges:
                    targets = ', '.join(e['target'] for e in out_edges)
                    console.print(f"  [bold]{node['id']}[/bold] → {targets}")
                else:
                    console.print(f"  [bold]{node['id']}[/bold]")
            if len(viz['nodes']) > 10:
                console.print(f"  ... and {len(viz['nodes']) - 10} more nodes")

    # Complexity Heatmap Visualization
    if 'analysis' in result and 'files' in result['analysis']:
        files = result['analysis']['files']
        heatmap = []
        for file_path, file_data in files.items():
            analyses = file_data.get('analyses', {})
            if 'complexity' in analyses:
                avg = analyses['complexity'].get('average_complexity', 0)
                heatmap.append((file_path, avg))
        if heatmap:
            heatmap = sorted(heatmap, key=lambda x: -x[1])[:10]  # Top 10 by complexity
            console.print(f"\n[bold]🌡️ Complexity Heatmap (Top 10 by avg complexity):[/bold]")
            for file_path, avg in heatmap:
                color = 'red' if avg > 15 else 'yellow' if avg > 7 else 'green'
                console.print(f"  [{color}]{file_path}[/] : {avg:.1f}")

def _get_grade(score: float) -> str:
    """Get letter grade from score."""
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"

def _get_grade_color(grade: str) -> str:
    """Get color for grade."""
    return {
        "A": "green",
        "B": "bright_green",
        "C": "yellow",
        "D": "bright_red",
        "F": "red"
    }.get(grade, "white")

@cli.command()
@click.argument('project_path', type=click.Path(exists=True))
@click.option('--fix', is_flag=True, help='Show fix suggestions')
@click.option('--visualize', is_flag=True, help='Generate visualization')
def circular_deps(project_path: str, fix: bool, visualize: bool):
    """Find circular dependencies."""
    asyncio.run(_find_circular_deps(Path(project_path), fix, visualize))

async def _find_circular_deps(project_path: Path, show_fixes: bool, visualize: bool):
    """Find and display circular dependencies."""
    # First analyze dependencies
    dep_result = await dependency_analyzer.analyze_dependencies(project_path)
    
    # Detect cycles
    detector = CircularDependencyDetector(dependency_analyzer.graph)
    cycles_analysis = detector.detect_cycles()
    
    if cycles_analysis['total_cycles'] == 0:
        console.print("[green]✅ No circular dependencies found![/green]")
        return
    
    # Display results
    console.print(f"\n[red]Found {cycles_analysis['total_cycles']} circular dependencies[/red]")
    
    for i, cycle in enumerate(cycles_analysis['cycles'][:10]):
        console.print(f"\n[bold]{i+1}. {cycle['description']}[/bold]")
        console.print(f"   Severity: {cycle['severity']}/10")
        console.print(f"   Modules: {' → '.join(cycle['modules'])}")
    
    # Show fixes if requested
    if show_fixes:
        refactorer = DependencyRefactorer(dependency_analyzer.graph)
        suggestions = refactorer.suggest_refactoring(
            [c['modules'] for c in cycles_analysis['cycles']],
            []
        )
        
        console.print("\n[yellow]Suggested Fixes:[/yellow]")
        for pattern in suggestions['patterns'][:3]:
            console.print(f"\n• Apply {pattern['pattern']} pattern:")
            console.print(f"  {pattern['description']}")
    
    # Generate visualization if requested
    if visualize:
        viz_data = dep_result['visualization']
        viz_data['cycles'] = [c['modules'] for c in cycles_analysis['cycles']]
        
        graph = visualizer.generate_dependency_graph(
            viz_data,
            output_format='mermaid',
            highlight_cycles=True
        )
        
        console.print("\n[cyan]Dependency Graph with Cycles:[/cyan]")
        console.print(graph)

@cli.command()
@click.option('--format', type=click.Choice(['summary', 'detailed']),
              default='summary', help='Report format')
def report(format: str):
    """Generate analysis report for last analyzed project."""
    asyncio.run(_generate_report(format))

async def _generate_report(format: str):
    """Generate and display report."""
    # Get latest analysis from database
    history = await database.get_project_history(".", limit=1)
    
    if not history:
        console.print("[red]No analysis history found. Run 'analyze-project' first.[/red]")
        return
    
    # Generate report
    # (In production, would load full results from database)
    console.print("[yellow]Report generation from history not yet implemented.[/yellow]")
    console.print("Run 'analyze-project' with --format option to generate reports.")

@cli.command()
@click.argument('repo_url')
@click.option('--token', help='GitHub personal access token')
@click.option('--branch', default='main', help='Branch to analyze')
@click.option('--full', is_flag=True, help='Perform full analysis with cloning')
@click.option('--export', type=click.Choice(['html', 'markdown', 'json']), help='Export report to file in the chosen format')
def analyze_github(repo_url: str, token: str, branch: str, full: bool, export: str):
    """Analyze a GitHub repository."""
    asyncio.run(_analyze_github(repo_url, token, branch, full, export))

async def _analyze_github(repo_url: str, token: str, branch: str, full: bool, export: str = None):
    """Async GitHub analysis."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Analyzing GitHub repository...", total=None)
        
        # Use token if provided
        if token:
            analyzer = GitHubAnalyzer(token)
        else:
            analyzer = github_analyzer
        
        try:
            mode = "full" if full else "quick"
            result = await analyzer.analyze_github_repo(repo_url, branch=branch, analysis_mode=mode)
            _display_github_results(result)
            if export:
                _export_report(result, export, repo_url)
        except Exception as e:
            console.print(f"[red]Error analyzing GitHub repository: {e}[/red]")

def _display_github_results(result: Dict[str, Any]):
    """Display GitHub analysis results."""
    console.print("\n[bold cyan]🐙 GitHub Repository Analysis[/bold cyan]")
    console.print("=" * 60)
    
    # Repository Information
    if 'repository' in result:
        repo = result['repository']
        console.print(f"\n[bold]📦 Repository:[/bold] {repo.get('owner', 'N/A')}/{repo.get('name', 'N/A')}")
        console.print(f"[bold]🌿 Branch:[/bold] {repo.get('branch', 'N/A')}")
        console.print(f"[bold]📊 Mode:[/bold] {repo.get('analysis_mode', 'N/A')}")
    
    # Metadata (GitHub API info)
    if 'metadata' in result:
        meta = result['metadata']
        console.print(f"\n[bold]📈 Repository Info:[/bold]")
        console.print(f"  • Stars: ⭐ {meta.get('stars', 0)}")
        console.print(f"  • Forks: 🍴 {meta.get('forks', 0)}")
        console.print(f"  • Open Issues: 🐛 {meta.get('open_issues', 0)}")
        console.print(f"  • Size: 💾 {meta.get('size_kb', 0)} KB")
        console.print(f"  • Language: 🔤 {meta.get('primary_language', 'N/A')}")
        console.print(f"  • Contributors: 👥 {meta.get('contributors', 0)}")
        console.print(f"  • License: 📄 {meta.get('license', 'N/A')}")
        console.print(f"  • Created: 📅 {meta.get('created_at', 'N/A')[:10] if meta.get('created_at') else 'N/A'}")
        console.print(f"  • Updated: 🔄 {meta.get('updated_at', 'N/A')[:10] if meta.get('updated_at') else 'N/A'}")
        
        # Languages breakdown
        if meta.get('languages'):
            console.print(f"\n[bold]💻 Languages:[/bold]")
            for lang, bytes_count in meta['languages'].items():
                console.print(f"  • {lang}: {bytes_count:,} bytes")
    
    # Analysis Results
    if 'analysis' in result:
        analysis = result['analysis']
        console.print(f"\n[bold]📊 Analysis Results:[/bold]")
        
        # Summary
        if 'summary' in analysis:
            summary = analysis['summary']
            console.print(f"  • Files Analyzed: {summary.get('total_files', 0)}")
            console.print(f"  • Total Issues: {summary.get('total_issues', 0)}")
            console.print(f"  • Average Complexity: {summary.get('avg_complexity', 0):.1f}")
            
            # Health scores
            console.print(f"\n[bold]🎯 Health Scores:[/bold]")
            for key, value in summary.items():
                if 'score' in key and isinstance(value, (int, float)):
                    console.print(f"  • {key.replace('_', ' ').title()}: {value:.1f}/100")
        
        # Project-wide Issues
        if 'issues' in analysis:
            issues = analysis['issues']
            if issues:
                console.print(f"\n[bold]🚨 Project Issues ({len(issues)}):[/bold]")
                
                # Group by category
                by_category = {}
                for issue in issues:
                    category = issue.get('category', 'unknown')
                    if category not in by_category:
                        by_category[category] = []
                    by_category[category].append(issue)
                
                for category, category_issues in by_category.items():
                    console.print(f"\n  [bold]{category.title()} Issues ({len(category_issues)}):[/bold]")
                    for i, issue in enumerate(category_issues[:3]):  # Show first 3 per category
                        severity = issue.get('severity', 'UNKNOWN')
                        color = {'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'green'}.get(severity, 'white')
                        file_path = issue.get('file', 'N/A')
                        if isinstance(file_path, str) and len(file_path) > 50:
                            file_path = "..." + file_path[-47:]
                        console.print(f"    {i+1}. [{color}]{severity}[/{color}] {issue.get('message', 'N/A')}")
                        console.print(f"       File: {file_path}")
                    if len(category_issues) > 3:
                        console.print(f"       ... and {len(category_issues) - 3} more {category} issues")
        
        # File-level Security Issues
        if 'files' in analysis:
            files = analysis['files']
            security_issues = []
            quality_issues = []
            
            for file_path, file_data in files.items():
                if 'error' in file_data:
                    continue
                
                analyses = file_data.get('analyses', {})
                
                # Collect security issues
                if 'security' in analyses and analyses['security'].get('issues'):
                    for issue in analyses['security']['issues']:
                        issue['file'] = file_path
                        security_issues.append(issue)
                
                # Collect quality issues
                if 'quality' in analyses and analyses['quality'].get('issues'):
                    for issue in analyses['quality']['issues']:
                        issue['file'] = file_path
                        quality_issues.append(issue)
            
            # Display security issues
            if security_issues:
                console.print(f"\n[bold]🔒 Security Issues ({len(security_issues)}):[/bold]")
                for i, issue in enumerate(security_issues[:5]):  # Show first 5
                    severity = issue.get('severity', 'UNKNOWN')
                    color = {'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'green'}.get(severity, 'white')
                    file_path = issue.get('file', 'N/A')
                    if isinstance(file_path, str) and len(file_path) > 50:
                        file_path = "..." + file_path[-47:]
                    console.print(f"  {i+1}. [{color}]{severity}[/{color}] {issue.get('message', 'N/A')}")
                    console.print(f"     File: {file_path}")
                if len(security_issues) > 5:
                    console.print(f"  ... and {len(security_issues) - 5} more security issues")
            
            # Display quality issues
            if quality_issues:
                console.print(f"\n[bold]✨ Quality Issues ({len(quality_issues)}):[/bold]")
                for i, issue in enumerate(quality_issues[:5]):  # Show first 5
                    file_path = issue.get('file', 'N/A')
                    if isinstance(file_path, str) and len(file_path) > 50:
                        file_path = "..." + file_path[-47:]
                    console.print(f"  {i+1}. {issue.get('message', 'N/A')}")
                    console.print(f"     File: {file_path}")
                    if 'code_snippet' in issue and issue['code_snippet']:
                        console.print(f"     [dim]Code:[/dim] {issue['code_snippet']}")
                    if 'reference' in issue and issue['reference']:
                        console.print(f"     [dim]Reference:[/dim] {issue['reference']}")
                    if 'fix_suggestion' in issue and issue['fix_suggestion']:
                        console.print(f"     [dim]Fix:[/dim] {issue['fix_suggestion']}")
                if len(quality_issues) > 5:
                    console.print(f"  ... and {len(quality_issues) - 5} more quality issues")
        
        # Dependencies
        if 'dependencies' in analysis:
            deps = analysis['dependencies']
            if 'metrics' in deps:
                metrics = deps['metrics']
                console.print(f"\n[bold]📦 Dependencies:[/bold]")
                console.print(f"  • Total: {metrics.get('total_dependencies', 0)}")
                console.print(f"  • External: {metrics.get('external_dependencies', 0)}")
                console.print(f"  • Internal: {metrics.get('internal_dependencies', 0)}")
                console.print(f"  • Circular: {metrics.get('circular_dependencies', 0)}")
                console.print(f"  • Coupling Score: {metrics.get('coupling_score', 0):.1f}")
                console.print(f"  • Cohesion Score: {metrics.get('cohesion_score', 0):.1f}")
            
            # Show circular dependencies
            if 'circular_dependencies' in deps.get('metrics', {}):
                circular = deps['metrics']['circular_dependencies']
                if circular:
                    console.print(f"\n[bold]🔄 Circular Dependencies ({len(circular)}):[/bold]")
                    for i, cycle in enumerate(circular[:3]):  # Show first 3
                        console.print(f"  {i+1}. {' → '.join(cycle)}")
                    if len(circular) > 3:
                        console.print(f"  ... and {len(circular) - 3} more cycles")
        
        # Git Info
        if 'git_info' in analysis:
            git = analysis['git_info']
            console.print(f"\n[bold]📝 Git Activity:[/bold]")
            console.print(f"  • Recent Commits: {git.get('recent_commits', 0)}")
            console.print(f"  • Active Contributors: {git.get('active_contributors', 0)}")
            console.print(f"  • Commit Frequency: {git.get('commit_frequency_per_day', 0):.2f}/day")
            console.print(f"  • Branches: {len(git.get('branches', []))}")
            console.print(f"  • Tags: {len(git.get('tags', []))}")
        
        # Dependency Issues
        if 'dependencies' in analysis and 'patterns' in analysis['dependencies']:
            dep_patterns = analysis['dependencies']['patterns']
            if 'issues' in dep_patterns and dep_patterns['issues']:
                console.print(f"\n[bold]🔗 Dependency Issues ({len(dep_patterns['issues'])}):[/bold]")
                for i, issue in enumerate(dep_patterns['issues'][:5]):
                    file_path = issue.get('file_path', 'N/A')
                    line = issue.get('line_number', 'N/A')
                    console.print(f"  {i+1}. {issue.get('message', 'N/A')} at {file_path}:{line}")
                    if 'code_snippet' in issue and issue['code_snippet']:
                        console.print(f"     [dim]Code:[/dim] {issue['code_snippet']}")
                    if 'reference' in issue and issue['reference']:
                        console.print(f"     [dim]Reference:[/dim] {issue['reference']}")
                    if 'fix_suggestion' in issue and issue['fix_suggestion']:
                        console.print(f"     [dim]Fix:[/dim] {issue['fix_suggestion']}")
                if len(dep_patterns['issues']) > 5:
                    console.print(f"  ... and {len(dep_patterns['issues']) - 5} more dependency issues")
    
    # Complexity Hotspots
    if 'details' in analysis and 'hotspots' in analysis:
        hotspots = analysis['hotspots']
        if hotspots:
            console.print(f"\n[bold]🔥 Complexity Hotspots ({len(hotspots)}):[/bold]")
            for i, issue in enumerate(hotspots):
                name = issue.get('name', 'N/A')
                risk = issue.get('risk_level', 'N/A')
                file_path = issue.get('file_path', 'N/A')
                line = issue.get('line_number', 'N/A')
                console.print(f"  {i+1}. {name} (Risk: {risk}) at {file_path}:{line}")
                if 'code_snippet' in issue and issue['code_snippet']:
                    console.print(f"     [dim]Code:[/dim] {issue['code_snippet']}")
                if 'reference' in issue and issue['reference']:
                    console.print(f"     [dim]Reference:[/dim] {issue['reference']}")
                if 'fix_suggestion' in issue and issue['fix_suggestion']:
                    console.print(f"     [dim]Fix:[/dim] {issue['fix_suggestion']}")
    
    # Insights
    if 'insights' in result:
        insights = result['insights']
        console.print(f"\n[bold]💡 Insights:[/bold]")
        
        # Badges
        if 'badges' in insights:
            console.print(f"  🏅 Badges: {' '.join(insights['badges'])}")
        
        # Health indicators
        if 'health_indicators' in insights:
            health = insights['health_indicators']
            console.print(f"\n[bold]🏥 Health Indicators:[/bold]")
            for indicator, status in health.items():
                status_icon = "✅" if status in ['active', 'high', 'healthy', 'present', 'configured'] else "❌"
                console.print(f"  • {indicator.replace('_', ' ').title()}: {status_icon} {status}")
        
        # Overall health score
        if 'overall_health_score' in insights:
            score = insights['overall_health_score']
            console.print(f"\n[bold]🎯 Overall Repository Health:[/bold] {score:.1f}/100")
        
        # Recommendations
        if 'recommendations' in insights:
            recs = insights['recommendations']
            if recs:
                console.print(f"\n[bold]💡 Recommendations:[/bold]")
                for i, rec in enumerate(recs[:5]):  # Show first 5
                    console.print(f"  {i+1}. {rec}")
                if len(recs) > 5:
                    console.print(f"  ... and {len(recs) - 5} more recommendations")
    
    # Project recommendations
    if 'analysis' in result and 'recommendations' in result['analysis']:
        recs = result['analysis']['recommendations']
        if recs:
            console.print(f"\n[bold]🎯 Project Recommendations:[/bold]")
            for i, rec in enumerate(recs[:5]):  # Show first 5
                console.print(f"  {i+1}. {rec}")
            if len(recs) > 5:
                console.print(f"  ... and {len(recs) - 5} more recommendations")
    
    # Error handling
    if 'error' in result:
        console.print(f"\n[red]❌ Error: {result['error']}[/red]")
    
    console.print("\n" + "=" * 60)

def _export_report(result: Dict[str, Any], export: str, repo_url: str):
    """Export the analysis report to a file in the chosen format."""
    import json
    import datetime
    from pathlib import Path
    
    repo_name = repo_url.split('/')[-1].replace('.git', '')
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"report_{repo_name}_{timestamp}.{export}"
    
    if export == 'json':
        with open(filename, 'w') as f:
            json.dump(result, f, indent=2)
        console.print(f"[green]JSON report saved to {filename}[/green]")
    
    elif export == 'markdown':
        # Enhanced Markdown export using AnalysisReportGenerator
        try:
            from analyzers.project_analyzer import AnalysisReportGenerator
            report_gen = AnalysisReportGenerator()
            
            # Prepare data for report generator
            report_data = {
                'project_path': repo_url,
                'completed_at': timestamp,
                'summary': result.get('analysis', {}).get('summary', {}),
                'metrics': result.get('analysis', {}).get('metrics', {}),
                'issues': result.get('analysis', {}).get('issues', []),
                'files': result.get('analysis', {}).get('files', {}),
                'dependencies': result.get('analysis', {}).get('dependencies', {}),
                'recommendations': result.get('analysis', {}).get('recommendations', []),
                'visualizations': result.get('visualizations', {})
            }
            
            markdown_report = report_gen.generate_report(
                report_data,
                report_type='detailed',
                output_format='markdown'
            )
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(markdown_report)
            console.print(f"[green]Enhanced Markdown report saved to {filename}[/green]")
            
        except ImportError:
            # Fallback to simple markdown
            md = f"""# GitHub Repository Analysis

## Repository Information
- **Repository:** {repo_url}
- **Analysis Date:** {timestamp}
- **Analysis Mode:** {result.get('repository', {}).get('analysis_mode', 'N/A')}

## Summary
```json
{json.dumps(result.get('analysis', {}), indent=2)}
```

## Metadata
```json
{json.dumps(result.get('metadata', {}), indent=2)}
```
"""
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(md)
            console.print(f"[green]Markdown report saved to {filename}[/green]")
    
    elif export == 'html':
        # Enhanced HTML export using AnalysisReportGenerator
        try:
            from analyzers.project_analyzer import AnalysisReportGenerator
            report_gen = AnalysisReportGenerator()
            
            # Prepare data for report generator
            report_data = {
                'project_path': repo_url,
                'completed_at': timestamp,
                'summary': result.get('analysis', {}).get('summary', {}),
                'metrics': result.get('analysis', {}).get('metrics', {}),
                'issues': result.get('analysis', {}).get('issues', []),
                'files': result.get('analysis', {}).get('files', {}),
                'dependencies': result.get('analysis', {}).get('dependencies', {}),
                'recommendations': result.get('analysis', {}).get('recommendations', []),
                'visualizations': result.get('visualizations', {})
            }
            
            html_report = report_gen.generate_report(
                report_data,
                report_type='detailed',
                output_format='html'
            )
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_report)
            console.print(f"[green]Enhanced HTML report saved to {filename}[/green]")
            
        except ImportError:
            # Fallback to simple HTML
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>GitHub Repository Analysis</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #f8f9fa; padding: 20px; border-radius: 8px; }}
        .section {{ margin: 20px 0; }}
        pre {{ background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>GitHub Repository Analysis</h1>
        <p><strong>Repository:</strong> {repo_url}</p>
        <p><strong>Date:</strong> {timestamp}</p>
    </div>
    
    <div class="section">
        <h2>Analysis Results</h2>
        <pre>{json.dumps(result.get('analysis', {}), indent=2)}</pre>
    </div>
    
    <div class="section">
        <h2>Repository Metadata</h2>
        <pre>{json.dumps(result.get('metadata', {}), indent=2)}</pre>
    </div>
</body>
</html>"""
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html)
            console.print(f"[green]HTML report saved to {filename}[/green]")

@cli.command()
@click.argument('project_path', type=click.Path(exists=True))
@click.option('--metric', type=click.Choice(['overall_health', 'security_score', 'quality_score', 'complexity_score']), 
              default='overall_health', help='Metric to generate badge for')
@click.option('--threshold', type=int, default=80, help='Threshold for pass/fail')
@click.option('--output', type=click.Path(), help='Output file for badge')
def generate_badge(project_path: str, metric: str, threshold: int, output: str):
    """Generate a status badge for CI/CD integration."""
    asyncio.run(_generate_badge(Path(project_path), metric, threshold, output))

async def _generate_badge(project_path: Path, metric: str, threshold: int, output: str):
    """Generate a status badge."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Generating badge...", total=None)
        
        try:
            # Run analysis
            result = await project_analyzer.analyze_project(project_path)
            
            # Get metric value
            summary = result.get('summary', {})
            metric_value = summary.get(metric, 0)
            
            # Determine badge color
            if metric_value >= threshold:
                color = "green"
                status = "passing"
            else:
                color = "red"
                status = "failing"
            
            # Generate badge URL
            badge_url = f"https://img.shields.io/badge/{metric.replace('_', '%20')}-{metric_value}%2F100-{color}"
            
            # Generate markdown
            badge_markdown = f"![{metric.replace('_', ' ').title()}]({badge_url})"
            
            # Output
            if output:
                with open(output, 'w') as f:
                    f.write(badge_markdown)
                console.print(f"[green]Badge saved to {output}[/green]")
            else:
                console.print(f"\n[bold]Badge for {metric}:[/bold]")
                console.print(badge_markdown)
                console.print(f"\n[bold]Status:[/bold] {status} ({metric_value}/{threshold})")
            
            # For CI, exit with appropriate code
            if metric_value < threshold:
                console.print(f"[red]❌ Quality gate failed: {metric} = {metric_value} < {threshold}[/red]")
                exit(1)
            else:
                console.print(f"[green]✅ Quality gate passed: {metric} = {metric_value} >= {threshold}[/green]")
                
        except Exception as e:
            console.print(f"[red]❌ Error generating badge: {e}[/red]")
            exit(1)

@cli.command()
@click.argument('project_path', type=click.Path(exists=True))
@click.option('--config', type=click.Path(exists=True), help='Quality gate configuration file')
@click.option('--fail-on-critical', is_flag=True, default=True, help='Fail if critical issues found')
@click.option('--fail-on-high', is_flag=True, default=False, help='Fail if high severity issues found')
@click.option('--min-health-score', type=int, default=80, help='Minimum overall health score')
def quality_gate(project_path: str, config: str, fail_on_critical: bool, fail_on_high: bool, min_health_score: int):
    """Run quality gate checks for CI/CD integration."""
    asyncio.run(_run_quality_gate(Path(project_path), config, fail_on_critical, fail_on_high, min_health_score))

async def _run_quality_gate(project_path: Path, config: str, fail_on_critical: bool, fail_on_high: bool, min_health_score: int):
    """Run quality gate checks."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Running quality gate...", total=None)
        
        try:
            # Load config if provided
            quality_config = {}
            if config:
                with open(config, 'r') as f:
                    quality_config = json.load(f)
            
            # Run analysis
            result = await project_analyzer.analyze_project(project_path)
            
            # Get metrics
            summary = result.get('summary', {})
            issues = result.get('issues', [])
            
            overall_health = summary.get('overall_health', 0)
            critical_issues = sum(1 for i in issues if i.get('severity') == 'CRITICAL')
            high_issues = sum(1 for i in issues if i.get('severity') == 'HIGH')
            
            # Check quality gates
            failed_gates = []
            
            if fail_on_critical and critical_issues > 0:
                failed_gates.append(f"Critical issues: {critical_issues}")
            
            if fail_on_high and high_issues > 0:
                failed_gates.append(f"High severity issues: {high_issues}")
            
            if overall_health < min_health_score:
                failed_gates.append(f"Health score: {overall_health} < {min_health_score}")
            
            # Check custom gates from config
            if 'quality_gates' in quality_config:
                gates = quality_config['quality_gates']
                
                if 'critical_issues' in gates and critical_issues > gates['critical_issues']:
                    failed_gates.append(f"Critical issues: {critical_issues} > {gates['critical_issues']}")
                
                if 'high_issues' in gates and high_issues > gates['high_issues']:
                    failed_gates.append(f"High issues: {high_issues} > {gates['high_issues']}")
                
                if 'overall_health_score' in gates and overall_health < gates['overall_health_score']:
                    failed_gates.append(f"Health score: {overall_health} < {gates['overall_health_score']}")
            
            # Display results
            console.print(f"\n[bold cyan]Quality Gate Results[/bold cyan]")
            console.print("=" * 40)
            console.print(f"Overall Health Score: {overall_health:.1f}/100")
            console.print(f"Critical Issues: {critical_issues}")
            console.print(f"High Issues: {high_issues}")
            console.print(f"Total Issues: {len(issues)}")
            
            if failed_gates:
                console.print(f"\n[red]❌ Quality gates failed:[/red]")
                for gate in failed_gates:
                    console.print(f"  • {gate}")
                exit(1)
            else:
                console.print(f"\n[green]✅ All quality gates passed![/green]")
                
        except Exception as e:
            console.print(f"[red]❌ Error running quality gate: {e}[/red]")
            exit(1)

@cli.command()
@click.argument('project_path', type=click.Path(exists=True))
@click.option('--format', type=click.Choice(['html', 'markdown', 'json']), default='html', help='Report format')
@click.option('--type', 'report_type', type=click.Choice(['executive', 'detailed']), default='detailed', help='Report type')
@click.option('--output', type=click.Path(), help='Output file path')
def generate_report(project_path: str, format: str, report_type: str, output: str):
    """Generate a comprehensive analysis report."""
    asyncio.run(_generate_standalone_report(Path(project_path), format, report_type, output))

async def _generate_standalone_report(project_path: Path, format: str, report_type: str, output: str):
    """Generate a standalone analysis report."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Generating report...", total=None)
        
        try:
            # Run analysis
            result = await project_analyzer.analyze_project(project_path)
            
            # Generate report
            from analyzers.project_analyzer import AnalysisReportGenerator
            report_gen = AnalysisReportGenerator()
            
            report_content = report_gen.generate_report(
                result,
                report_type=report_type,
                output_format=format
            )
            
            # Determine output file
            if not output:
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                output = project_path / f"analysis_report_{report_type}_{timestamp}.{format}"
            else:
                output = Path(output)
            
            # Save report
            with open(output, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            console.print(f"[green]✅ Report generated successfully![/green]")
            console.print(f"[bold]File:[/bold] {output}")
            console.print(f"[bold]Type:[/bold] {report_type.title()}")
            console.print(f"[bold]Format:[/bold] {format.upper()}")
            
            # Show preview for console
            if format == 'markdown':
                console.print(f"\n[bold]Preview:[/bold]")
                console.print("=" * 50)
                console.print(report_content[:500] + "..." if len(report_content) > 500 else report_content)
            
        except Exception as e:
            console.print(f"[red]❌ Error generating report: {e}[/red]")

@cli.command()
def show_history():
    """Show recent analysis history for the current project."""
    import os
    import asyncio
    project_path = os.path.abspath('.')
    async def _show():
        # Create a new database instance to avoid threading issues
        from storage.database import AnalysisDatabase
        db = AnalysisDatabase()
        history = await db.get_project_history(project_path, limit=10)
        if not history:
            console.print("[red]No analysis history found.[/red]")
            return
        console.print("\n[bold cyan]📜 Recent Analysis History[/bold cyan]")
        for entry in history:
            console.print(f"- [bold]{entry.get('completed_at', 'N/A')}[/bold]: {entry.get('analysis_type', 'N/A')} | Files: {entry.get('total_files', 'N/A')} | Issues: {entry.get('total_issues', 'N/A')} | Duration: {entry.get('duration_seconds', 'N/A')}s")
            if entry.get('summary'):
                console.print(f"    [dim]{entry['summary']}[/dim]")
    asyncio.run(_show())

@cli.command()
def show_trends():
    """Show trending security and quality issues for the last 7 days."""
    import asyncio
    async def _show():
        # Create a new database instance to avoid threading issues
        from storage.database import AnalysisDatabase
        db = AnalysisDatabase()
        trends = await db.get_trending_issues(days=7)
        console.print("\n[bold cyan]📈 Trending Issues (Last 7 Days)[/bold cyan]")
        if trends['security_trends']:
            console.print("\n[bold]🔒 Security Issues:[/bold]")
            for t in trends['security_trends']:
                console.print(f"- Rule: {t['rule_id']} | Severity: {t['severity']} | Count: {t['count']}")
        else:
            console.print("No trending security issues.")
        if trends['quality_trends']:
            console.print("\n[bold]✨ Quality Metrics:[/bold]")
            for t in trends['quality_trends']:
                console.print(f"- {t['metric_name']}: Avg Value = {t['avg_value']:.2f}")
        else:
            console.print("No trending quality metrics.")
    asyncio.run(_show())

if __name__ == '__main__':
    cli()