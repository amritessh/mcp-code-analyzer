# tests/test_integration/test_security.py
import pytest
from pathlib import Path
from src.analyzers.security import SecurityAnalyzer

@pytest.fixture
def vulnerable_code(temp_dir):
    """Create file with security vulnerabilities."""
    file_path = temp_dir / "vulnerable.py"
    content = '''
import os
import hashlib

# Hardcoded password
PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

def execute_command(user_input):
    # Command injection vulnerability
    os.system("echo " + user_input)
    
def hash_password(password):
    # Weak hash algorithm
    return hashlib.md5(password.encode()).hexdigest()

def query_database(user_id):
    # SQL injection
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    
# Debug mode enabled
DEBUG = True
    '''
    file_path.write_text(content)
    return file_path

@pytest.mark.asyncio
async def test_security_scanner(vulnerable_code):
    """Test security vulnerability detection."""
    analyzer = SecurityAnalyzer()
    result = await analyzer.scan_security(vulnerable_code)
    
    assert result['total_issues'] > 0
    assert result['risk_score'] > 50
    
    # Check specific vulnerabilities detected
    issue_types = [issue['rule_id'] for issue in result['issues']]
    assert 'SEC001' in issue_types  # Hardcoded password
    assert 'SEC002' in issue_types  # API key
    assert 'SEC006' in issue_types  # Command injection
    assert 'SEC008' in issue_types  # Weak hash

@pytest.mark.asyncio
async def test_security_severity_filtering(vulnerable_code):
    """Test filtering by severity."""
    analyzer = SecurityAnalyzer()
    
    # Include all severities
    result_all = await analyzer.scan_security(vulnerable_code, include_info=True)
    
    # Exclude info level
    result_filtered = await analyzer.scan_security(vulnerable_code, include_info=False)
    
    assert result_all['total_issues'] >= result_filtered['total_issues']