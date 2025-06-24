# src/cli.py (updated with Week 2 commands)
import asyncio
import click
from pathlib import Path
from typing import Dict, Any, List
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .analyzers.security import SecurityAnalyzer
from .analyzers.quality import QualityAnalyzer
from .analyzers.dependencies import DependencyAnalyzer
from .storage.database import AnalysisDatabase

# Initialize components
console = Console()
security_analyzer = SecurityAnalyzer()
quality_analyzer = QualityAnalyzer()
dependency_analyzer = DependencyAnalyzer()
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
def dependencies(path: str, depth: int, output_format: str, show_external: bool):
    """Analyze code dependencies."""
    asyncio.run(_analyze_dependencies(Path(path), depth, output_format, show_external))

async def _analyze_dependencies(
    path: Path, 
    depth: int, 
    output_format: str,
    show_external: bool
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
        elif output_format in ['mermaid', 'd3', 'graphviz']:
            viz_data = result.get('visualization', {})
            graph = visualizer.generate_dependency_graph(
                viz_data,
                output_format=output_format
            )
            console.print(graph)

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