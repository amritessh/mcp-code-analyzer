# src/analyzers/basic.py
import ast
from pathlib import Path
from typing import Dict, Any, List, Optional
import re

from ..utils.logger import logger
from ..config import settings

class BasicAnalyzer:
    """Basic file analyzer for code metrics."""
    
    def __init__(self):
        self.language_mapping = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.go': 'Go',
            '.rs': 'Rust',
            '.cpp': 'C++',
            '.c': 'C',
        }
        
        self.comment_patterns = {
            'Python': (r'#.*$', r'"""[\s\S]*?"""', r"'''[\s\S]*?'''"),
            'JavaScript': (r'//.*$', r'/\*[\s\S]*?\*/'),
            'Java': (r'//.*$', r'/\*[\s\S]*?\*/'),
            'C': (r'//.*$', r'/\*[\s\S]*?\*/'),
        }
    
    async def analyze_basic(self, file_path: Path) -> Dict[str, Any]:
        """Perform basic analysis on a file."""
        logger.debug(f"Analyzing file: {file_path}")
        
        # Read file content
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
        
        lines = content.split('\n')
        language = self.detect_language(file_path)
        
        # Basic metrics
        metrics = {
            'total_lines': len(lines),
            'blank_lines': sum(1 for line in lines if not line.strip()),
            'loc': sum(1 for line in lines if line.strip()),
            'comment_lines': self.count_comment_lines(lines, language),
        }
        
        # Language-specific analysis
        if language == 'Python' and file_path.suffix == '.py':
            python_metrics = self.analyze_python_structure(content)
            metrics.update(python_metrics)
        
        return {
            'file_path': str(file_path),
            'size_bytes': file_path.stat().st_size,
            'language': language,
            'metrics': metrics
        }
    
    def detect_language(self, file_path: Path) -> str:
        """Detect programming language from file extension."""
        return self.language_mapping.get(file_path.suffix, 'Unknown')
    
    def count_comment_lines(self, lines: List[str], language: str) -> int:
        """Count comment lines based on language."""
        if language not in self.comment_patterns:
            return 0
        
        count = 0
        patterns = self.comment_patterns[language]
        
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
                
            # Check single-line comments
            if any(re.match(pattern, stripped) for pattern in patterns 
                   if not pattern.startswith(r'/\*')):
                count += 1
        
        return count
    
    def analyze_python_structure(self, content: str) -> Dict[str, int]:
        """Analyze Python-specific code structure."""
        try:
            tree = ast.parse(content)
            
            functions = []
            classes = []
            imports = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    functions.append(node.name)
                elif isinstance(node, ast.ClassDef):
                    classes.append(node.name)
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    imports.append(node)
            
            return {
                'functions': len(functions),
                'classes': len(classes),
                'imports': len(imports),
                'function_names': functions[:10],  # Store first 10
                'class_names': classes[:10]
            }
            
        except SyntaxError as e:
            logger.warning(f"Syntax error in Python file: {e}")
            return {
                'functions': 0,
                'classes': 0,
                'imports': 0,
                'syntax_error': str(e)
            }