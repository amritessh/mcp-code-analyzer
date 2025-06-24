# src/languages/python.py
import ast
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from .base import LanguageAdapter
from utils.logger import logger

class PythonAdapter(LanguageAdapter):
    """Python-specific language adapter."""
    
    def __init__(self):
        self.comment_patterns = {
            '#': r'#.*$',
            '"""': r'""".*?"""',
            "'''": r"'''.*?'''"
        }
    
    def can_handle(self, file_path: Path) -> bool:
        """Check if this adapter can handle the file."""
        return file_path.suffix == '.py'
    
    async def analyze_basic(self, file_path: Path) -> Dict[str, Any]:
        """Basic analysis for Python files."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            # Count lines
            lines = content.split('\n')
            total_lines = len(lines)
            blank_lines = sum(1 for line in lines if not line.strip())
            comment_lines = self._count_comments(lines)
            loc = total_lines - blank_lines - comment_lines
            
            # Count functions and classes
            functions = len([node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)])
            classes = len([node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)])
            imports = len([node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))])
            
            return {
                'file_path': str(file_path),
                'language': 'Python',
                'size_bytes': file_path.stat().st_size,
                'metrics': {
                    'total_lines': total_lines,
                    'blank_lines': blank_lines,
                    'comment_lines': comment_lines,
                    'loc': loc,
                    'functions': functions,
                    'classes': classes,
                    'imports': imports
                }
            }
            
        except Exception as e:
            logger.error(f"Error analyzing Python file {file_path}: {e}")
            return {'error': str(e)}
    
    async def analyze_complexity(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Complexity analysis for Python files."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            # Calculate cyclomatic complexity
            complexity = 1  # Base complexity
            details = []
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                    complexity += 1
                    details.append({
                        'name': self._get_node_name(node),
                        'complexity': 1,
                        'type': type(node).__name__,
                        'line': node.lineno,
                        'risk_level': 'LOW'
                    })
                elif isinstance(node, ast.BoolOp):
                    complexity += 1
                elif isinstance(node, ast.ExceptHandler):
                    complexity += 1
                elif isinstance(node, ast.FunctionDef):
                    func_complexity = self._calculate_function_complexity(node)
                    details.append({
                        'name': node.name,
                        'complexity': func_complexity,
                        'type': 'function',
                        'line': node.lineno,
                        'risk_level': self._get_risk_level(func_complexity)
                    })
            
            # Calculate maintainability index
            loc = len(content.split('\n'))
            maintainability_index = max(0, 171 - 5.2 * complexity - 0.23 * loc - 16.2 * len(details))
            
            return {
                'file_path': str(file_path),
                'average_complexity': complexity,
                'max_complexity': max([d['complexity'] for d in details]) if details else complexity,
                'total_complexity': complexity,
                'risk_level': self._get_risk_level(complexity),
                'maintainability_index': maintainability_index,
                'details': details,
                'hotspots': [d for d in details if d['complexity'] > 10]
            }
            
        except Exception as e:
            logger.error(f"Error analyzing Python complexity: {e}")
            return None
    
    async def analyze_dependencies(self, file_path: Path) -> List[Dict[str, Any]]:
        """Extract dependencies from Python files."""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        dependencies.append({
                            'source': str(file_path),
                            'target': alias.name,
                            'type': 'import',
                            'line': node.lineno
                        })
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ''
                    for alias in node.names:
                        full_name = f"{module}.{alias.name}" if module else alias.name
                        dependencies.append({
                            'source': str(file_path),
                            'target': full_name,
                            'type': 'from_import',
                            'line': node.lineno
                        })
            
        except Exception as e:
            logger.error(f"Error extracting Python dependencies: {e}")
        
        return dependencies
    
    def _count_comments(self, lines: List[str]) -> int:
        """Count comment lines in Python code."""
        comment_count = 0
        in_multiline = False
        
        for line in lines:
            stripped = line.strip()
            
            # Skip empty lines
            if not stripped:
                continue
            
            # Check for multiline comments
            if '"""' in stripped or "'''" in stripped:
                in_multiline = not in_multiline
                comment_count += 1
                continue
            
            # Count single-line comments
            if stripped.startswith('#'):
                comment_count += 1
            elif in_multiline:
                comment_count += 1
        
        return comment_count
    
    def _get_node_name(self, node) -> str:
        """Get a readable name for an AST node."""
        if hasattr(node, 'name'):
            return node.name
        elif hasattr(node, 'id'):
            return node.id
        else:
            return type(node).__name__
    
    def _calculate_function_complexity(self, node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity for a function."""
        complexity = 1  # Base complexity
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
        
        return complexity
    
    def _get_risk_level(self, complexity: int) -> str:
        """Get risk level based on complexity."""
        if complexity <= 5:
            return 'LOW'
        elif complexity <= 10:
            return 'MEDIUM'
        elif complexity <= 20:
            return 'HIGH'
        else:
            return 'VERY_HIGH'
    
    def get_comment_patterns(self) -> Dict[str, str]:
        """Get comment patterns for Python."""
        return self.comment_patterns 