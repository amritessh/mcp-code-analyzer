# tests/test_integration/test_quality.py
import pytest
from pathlib import Path
from src.analyzers.quality import QualityAnalyzer

@pytest.fixture
def poor_quality_code(temp_dir):
    """Create file with quality issues."""
    file_path = temp_dir / "poor_quality.py"
    content = '''
def very_long_function_with_too_many_responsibilities(a, b, c, d, e, f, g):
    """This function is way too long and complex."""
    result = 0
    
    # Deeply nested code
    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    if e > 0:
                        result = a + b + c + d + e
    
    # Magic numbers everywhere
    threshold = 42
    max_value = 9999
    
    # Very long line that exceeds the recommended character limit and makes the code hard to read on standard displays
    
    # Duplicate code block 1
    for i in range(10):
        if i % 2 == 0:
            result += i * 2
    
    # More code...
    for x in range(50):
        result += x
    
    # Duplicate code block 2 (same as block 1)
    for i in range(10):
        if i % 2 == 0:
            result += i * 2
    
    return result

class VeryLargeClassWithTooManyResponsibilities:
    """This class is doing too much."""
    
    def method1(self): pass
    def method2(self): pass
    def method3(self): pass
    # ... imagine 50 more methods
    '''
    
    file_path.write_text(content)
    return file_path

@pytest.mark.asyncio
async def test_quality_analyzer(poor_quality_code):
    """Test quality analysis."""
    analyzer = QualityAnalyzer()
    result = await analyzer.check_quality(poor_quality_code)
    
    assert result['quality_score'] < 80  # Poor quality
    assert result['total_issues'] > 0
    
    # Check specific issues detected
    assert 'long_function' in result['issues_by_type']
    assert 'too_many_parameters' in result['issues_by_type']
    assert 'long_line' in result['issues_by_type']