# tests/test_analyzers/test_basic.py
import pytest
from pathlib import Path
from src.analyzers.basic import BasicAnalyzer

@pytest.mark.asyncio
async def test_analyze_basic_python(sample_python_file):
    """Test basic analysis of Python file."""
    analyzer = BasicAnalyzer()
    result = await analyzer.analyze_basic(sample_python_file)
    
    assert result['file_path'] == str(sample_python_file)
    assert result['language'] == 'Python'
    assert result['metrics']['loc'] > 0
    assert result['metrics']['functions'] == 2
    assert result['metrics']['classes'] == 1
    assert 'simple_function' in result['metrics']['function_names']

@pytest.mark.asyncio
async def test_analyze_basic_javascript(sample_javascript_file):
    """Test basic analysis of JavaScript file."""
    analyzer = BasicAnalyzer()
    result = await analyzer.analyze_basic(sample_javascript_file)
    
    assert result['language'] == 'JavaScript'
    assert result['metrics']['loc'] > 0
    assert result['metrics']['total_lines'] > result['metrics']['loc']

@pytest.mark.asyncio
async def test_file_not_found():
    """Test handling of non-existent file."""
    analyzer = BasicAnalyzer()
    
    with pytest.raises(FileNotFoundError):
        await analyzer.analyze_basic(Path("nonexistent.py"))