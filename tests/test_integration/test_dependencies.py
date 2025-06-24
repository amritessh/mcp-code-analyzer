# tests/test_integration/test_dependencies.py
import pytest
from pathlib import Path
import tempfile
import shutil
from src.analyzers.dependencies import DependencyAnalyzer
from src.analyzers.circular_dependencies import CircularDependencyDetector

@pytest.fixture
def sample_project(tmp_path):
    """Create a sample project with dependencies."""
    # Create project structure
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "__init__.py").write_text("")
    
    # Module A imports B
    (tmp_path / "src" / "module_a.py").write_text("""
from .module_b import function_b
import external_lib

def function_a():
    return function_b() + 1
""")
    
    # Module B imports C
    (tmp_path / "src" / "module_b.py").write_text("""
from .module_c import function_c

def function_b():
    return function_c() * 2
""")
    
    # Module C imports A (circular dependency)
    (tmp_path / "src" / "module_c.py").write_text("""
from .module_a import function_a

def function_c():
    return 42
    
def circular_call():
    return function_a()
""")
    
    return tmp_path

@pytest.mark.asyncio
async def test_dependency_analysis(sample_project):
    """Test basic dependency analysis."""
    analyzer = DependencyAnalyzer()
    result = await analyzer.analyze_dependencies(sample_project)
    
    assert result['metrics']['total_dependencies'] > 0
    assert result['metrics']['internal_dependencies'] > 0
    assert result['metrics']['external_dependencies'] >= 1  # external_lib
    
    # Check visualization data
    assert 'visualization' in result
    assert len(result['visualization']['nodes']) > 0
    assert len(result['visualization']['edges']) > 0

@pytest.mark.asyncio
async def test_circular_dependency_detection(sample_project):
    """Test circular dependency detection."""
    analyzer = DependencyAnalyzer()
    await analyzer.analyze_dependencies(sample_project)
    
    detector = CircularDependencyDetector(analyzer.graph)
    cycles = detector.detect_cycles()
    
    assert cycles['total_cycles'] > 0
    assert len(cycles['cycles']) > 0
    
    # Check that module_a, module_b, module_c form a cycle
    cycle_modules = set()
    for cycle in cycles['cycles']:
        cycle_modules.update(cycle['modules'])
    
    assert any('module_a' in m for m in cycle_modules)
    assert any('module_b' in m for m in cycle_modules)
    assert any('module_c' in m for m in cycle_modules)

@pytest.mark.asyncio
async def test_project_analyzer(sample_project):
    """Test comprehensive project analysis."""
    from src.analyzers.project_analyzer import ProjectAnalyzer
    
    analyzer = ProjectAnalyzer()
    result = await analyzer.analyze_project(sample_project)
    
    assert 'summary' in result
    assert 'files' in result
    assert 'metrics' in result
    assert 'issues' in result
    assert 'recommendations' in result
    
    # Check that files were analyzed
    assert len(result['files']) >= 3  # At least our 3 modules
    
    # Check metrics
    assert result['metrics']['totals']['files'] >= 3
    assert result['metrics']['totals']['loc'] > 0