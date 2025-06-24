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
from .storage.database import AnalysisDatabase

# Initialize components
console = Console()
security_analyzer = SecurityAnalyzer()
quality_analyzer = QualityAnalyzer()
database = AnalysisDatabase()

@click.group()
def cli():
    """Code Analysis CLI Tool"""
    pass

@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--rules', multiple=True, help='Specific security rules')
@click.option('--include-info', is_flag=True, help='Include info level issues')
def security(file_path: str, rules: tuple, include_info: bool):
    """Run security scan on a file."""
    asyncio.run(_security_scan(Path(file_path), list(rules), include_info))

async def _security_scan(file_path: Path, rules: List[str], include_info: bool):
    """Async security scanning."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Scanning for vulnerabilities...", total=None)
        
        result = await security_analyzer.scan_security(
            file_path, 
            rules if rules else None,
            include_info
        )
        
        # Display results
        console.print("\n[bold red]Security Scan Results[/bold red]")
        _display_security_results(result)

def _display_security_results(result: Dict[str, Any]):
    """Display security results in a table."""
    if not result['issues']:
        console.print("[green]✅ No security issues found![/green]")
        return
    
    table = Table(title=f"Security Issues - Risk Score: {result['risk_score']}/100")
    table.add_column("Severity", style="red")
    table.add_column("Rule", style="cyan")
    table.add_column("Line", style="yellow")
    table.add_column("Message", style="white")
    
    for issue in result['issues'][:20]:  # Show top 20
        severity_color = {
            'CRITICAL': 'red',
            'HIGH': 'bright_red',
            'MEDIUM': 'yellow',
            'LOW': 'bright_yellow',
            'INFO': 'blue'
        }.get(issue['severity'], 'white')
        
        table.add_row(
            f"[{severity_color}]{issue['severity']}[/{severity_color}]",
            issue['rule_id'],
            str(issue['location']['line']),
            issue['message'][:60] + "..." if len(issue['message']) > 60 else issue['message']
        )
    
    console.print(table)
    
    if len(result['issues']) > 20:
        console.print(f"\n... and {len(result['issues']) - 20} more issues")

@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--standards', multiple=True, help='Quality standards to apply')
def quality(file_path: str, standards: tuple):
    """Check code quality."""
    asyncio.run(_quality_check(Path(file_path), list(standards)))

async def _quality_check(file_path: Path, standards: List[str]):
    """Async quality checking."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Checking code quality...", total=None)
        
        result = await quality_analyzer.check_quality(
            file_path,
            standards if standards else None
        )
        
        # Display results
        console.print("\n[bold blue]Code Quality Results[/bold blue]")
        _display_quality_results(result)

@cli.command()
@click.argument('directory', type=click.Path(exists=True))
@click.option('--type', 'todo_types', multiple=True, 
              help='Types to find (TODO, FIXME, etc.)')
@click.option('--output', type=click.Choice(['table', 'list', 'json']), 
              default='table', help='Output format')
def todos(directory: str, todo_types: tuple, output: str):
    """Find TODO and FIXME comments."""
    asyncio.run(_find_todos(Path(directory), list(todo_types), output))

@cli.command()
@click.option('--days', default=7, help='Number of days to analyze')
def trends(days: int):
    """Show trending issues and metrics."""
    asyncio.run(_show_trends(days))

async def _show_trends(days: int):
    """Display trending analysis data."""
    trends = await database.get_trending_issues(days)
    
    console.print(f"\n[bold]Trending Issues (Last {days} Days)[/bold]")
    
    # Security trends
    if trends['security_trends']:
        console.print("\n[red]Top Security Issues:[/red]")
        for item in trends['security_trends'][:5]:
            console.print(f"  • {item['rule_id']} ({item['severity']}): "
                         f"{item['count']} occurrences")
    
    # Quality trends
    if trends['quality_trends']:
        console.print("\n[blue]Average Quality Metrics:[/blue]")
        for item in trends['quality_trends']:
            console.print(f"  • {item['metric_name']}: "
                         f"{item['avg_value']:.2f}")