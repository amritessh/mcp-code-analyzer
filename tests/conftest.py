# tests/conftest.py
import pytest
from pathlib import Path
import tempfile
import shutil

@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir)

@pytest.fixture
def sample_python_file(temp_dir):
    """Create a sample Python file for testing."""
    file_path = temp_dir / "sample.py"
    content = '''
def simple_function():
    """A simple function."""
    return 42

def complex_function(x, y, z):
    """A more complex function."""
    if x > 0:
        if y > 0:
            if z > 0:
                return x + y + z
            else:
                return x + y
        else:
            if z > 0:
                return x + z
            else:
                return x
    else:
        if y > 0:
            if z > 0:
                return y + z
            else:
                return y
        else:
            return z

class SampleClass:
    def __init__(self):
        self.value = 0
    
    def method_one(self):
        for i in range(10):
            if i % 2 == 0:
                self.value += i
    '''
    
    file_path.write_text(content)
    return file_path

@pytest.fixture
def sample_javascript_file(temp_dir):
    """Create a sample JavaScript file."""
    file_path = temp_dir / "sample.js"
    content = '''
// Sample JavaScript file
function calculateTotal(items) {
    let total = 0;
    for (let item of items) {
        if (item.price > 0) {
            total += item.price * item.quantity;
        }
    }
    return total;
}

class ShoppingCart {
    constructor() {
        this.items = [];
    }
    
    addItem(item) {
        this.items.push(item);
    }
}
    '''
    file_path.write_text(content)
    return file_path