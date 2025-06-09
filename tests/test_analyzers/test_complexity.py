# tests/test_analyzers/test_complexity.py
import pytest
from pathlib import Path
from src.analyzers.complexity import ComplexityAnalyzer

@pytest.mark.asyncio
async def test_complexity_analysis(sample_python_file):
    """Test complexity analysis."""
    analyzer = ComplexityAnalyzer()
    result = await analyzer.analyze_complexity(sample_python_file, True)
    
    assert 'average_complexity' in result
    assert 'max_complexity' in result
    assert result['max_complexity'] > 5  # complex_function should be complex
    assert 'details' in result
    assert len(result['details']) > 0
    
    # Check that complex_function is identified
    complex_items = [d for d in result['details'] 
                     if d['name'] == 'complex_function']
    assert len(complex_items) == 1
    assert complex_items[0]['complexity'] > 10

@pytest.mark.asyncio
async def test_maintainability_index(sample_python_file):
    """Test maintainability index calculation."""
    analyzer = ComplexityAnalyzer()
    result = await analyzer.analyze_complexity(sample_python_file)
    
    assert 'maintainability_index' in result
    assert 0 <= result['maintainability_index'] <= 100

@pytest.mark.asyncio
async def test_hotspot_identification(sample_python_file):
    """Test hotspot identification."""
    analyzer = ComplexityAnalyzer()
    result = await analyzer.analyze_complexity(sample_python_file, True)
    
    assert 'hotspots' in result
    # complex_function should be identified as a hotspot
    hotspot_names = [h['name'] for h in result['hotspots']]
    assert 'complex_function' in hotspot_names