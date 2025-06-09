# src/cli.py
import click
import asyncio
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .analyzers.basic import BasicAnalyzer
from .analyzers.complexity import ComplexityAnalyzer
from .storage.cache import FileCache
from .utils.logger import logger

console = Console()

@click.group()
def cli():
    """MCP Code Analyzer CLI."""
    pass

@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--no-cache', is_flag=True, help='Disable cache')
def analyze(file_path: str, no_cache: bool):
    """Analyze a single file."""
    asyncio.run(_analyze_file(Path(file_path), not no_cache))

async def _analyze_file(file_path: Path, use_cache: bool):
    """Async file analysis."""
    analyzer = BasicAnalyzer()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Analyzing file...", total=None)
        
        # Basic analysis
        result = await analyzer.analyze_basic(file_path)
        
        # Display results
        console.print("\n[bold green]Basic Analysis Results[/bold green]")
        _display_basic_results(result)
        
        # Complexity analysis for Python files
        if file_path.suffix == '.py':
            progress.update(task, description="Analyzing complexity...")
            complexity = await analyzer.analyze_complexity(file_path, True)
            console.print("\n[bold blue]Complexity Analysis[/bold blue]")
            _display_complexity_results(complexity)

def _display_basic_results(result: Dict[str, Any]):
    """Display basic analysis results."""
    table = Table(title="File Metrics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("File", result['file_path'])
    table.add_row("Language", result['language'])
    table.add_row("Size", f"{result['size_bytes']:,} bytes")
    table.add_row("Lines of Code", str(result['metrics']['loc']))
    table.add_row("Total Lines", str(result['metrics']['total_lines']))
    table.add_row("Comments", str(result['metrics']['comment_lines']))
    
    if 'functions' in result['metrics']:
        table.add_row("Functions", str(result['metrics']['functions']))
        table.add_row("Classes", str(result['metrics']['classes']))
    
    console.print(table)

def _display_complexity_results(result: Dict[str, Any]):
    """Display complexity analysis results."""
    # Summary
    console.print(f"Average Complexity: [yellow]{result['average_complexity']:.2f}[/yellow]")
    console.print(f"Max Complexity: [red]{result['max_complexity']}[/red]")
    console.print(f"Risk Level: {result['risk_level']}")
    console.print(f"Maintainability Index: [cyan]{result['maintainability_index']}[/cyan]")
    
    # Hotspots
    if result.get('hotspots'):
        console.print("\n[bold]Complexity Hotspots:[/bold]")
        for hotspot in result['hotspots']:
            console.print(f"  • {hotspot['name']}: "
                         f"[red]{hotspot['complexity']}[/red] - "
                         f"{hotspot['recommendation']}")

@cli.command()
@click.argument('directory', type=click.Path(exists=True))
@click.option('--ext', multiple=True, default=['.py'], 
              help='File extensions to analyze')
def scan(directory: str, ext: tuple):
    """Scan directory for files to analyze."""
    asyncio.run(_scan_directory(Path(directory), ext))

async def _scan_directory(directory: Path, extensions: tuple):
    """Scan and analyze directory."""
    files = []
    for extension in extensions:
        files.extend(directory.rglob(f"*{extension}"))
    
    console.print(f"Found [cyan]{len(files)}[/cyan] files to analyze")
    
    # TODO: Implement batch analysis for Week 3

@cli.command()
def cache_stats():
    """Show cache statistics."""
    asyncio.run(_show_cache_stats())

async def _show_cache_stats():
    """Display cache statistics."""
    cache = FileCache()
    stats = await cache.get_stats()
    
    console.print("[bold]Cache Statistics:[/bold]")
    console.print(f"Files: {stats['cache_files']}")
    console.print(f"Size: {stats['total_size_mb']} MB")
    console.print(f"Location: {stats['cache_dir']}")

@cli.command()
def clear_cache():
    """Clear all cached results."""
    asyncio.run(_clear_cache())

async def _clear_cache():
    """Clear cache."""
    cache = FileCache()
    count = await cache.clear()
    console.print(f"[green]Cleared {count} cache files[/green]")

if __name__ == "__main__":
    cli()