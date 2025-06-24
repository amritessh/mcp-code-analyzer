# src/languages/javascript.py
import re
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import esprima

from .base import LanguageAdapter
from utils.logger import logger

class JavaScriptAdapter(LanguageAdapter):
    """JavaScript/TypeScript language adapter."""
    
    def __init__(self):
        self.extensions = {'.js', '.jsx', '.ts', '.tsx', '.mjs'}
        
    def can_handle(self, file_path: Path) -> bool:
        return file_path.suffix in self.extensions
    
    async def analyze_basic(self, file_path: Path) -> Dict[str, Any]:
        """Analyze JavaScript/TypeScript file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.split('\n')
            
            # Basic metrics
            metrics = {
                'total_lines': len(lines),
                'blank_lines': sum(1 for line in lines if not line.strip()),
                'comment_lines': self._count_comments(lines),
                'loc': sum(1 for line in lines if line.strip() and not self._is_comment(line))
            }
            
            # Parse JavaScript
            if file_path.suffix in {'.js', '.jsx', '.mjs'}:
                js_metrics = self._analyze_javascript(content)
                metrics.update(js_metrics)
            
            return {
                'language': 'JavaScript' if file_path.suffix.startswith('.js') else 'TypeScript',
                'metrics': metrics
            }
            
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
            return {'error': str(e)}
    
    def _analyze_javascript(self, content: str) -> Dict[str, Any]:
        """Parse JavaScript using esprima."""
        try:
            # Parse the JavaScript code
            tree = esprima.parseScript(content, {'loc': True, 'range': True})
            
            # Count functions and classes
            function_count = 0
            class_count = 0
            max_depth = 0
            
            def walk_node(node, depth=0):
                nonlocal function_count, class_count, max_depth
                
                max_depth = max(max_depth, depth)
                
                if node.type == 'FunctionDeclaration' or node.type == 'FunctionExpression':
                    function_count += 1
                elif node.type == 'ClassDeclaration':
                    class_count += 1
                
                # Walk children
                for key, value in node.__dict__.items():
                    if isinstance(value, list):
                        for item in value:
                            if hasattr(item, 'type'):
                                walk_node(item, depth + 1)
                    elif hasattr(value, 'type'):
                        walk_node(value, depth + 1)
            
            walk_node(tree)
            
            return {
                'functions': function_count,
                'classes': class_count,
                'max_nesting_depth': max_depth
            }
            
        except Exception as e:
            logger.warning(f"Failed to parse JavaScript: {e}")
            return {}
    
    async def analyze_complexity(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Analyze JavaScript complexity."""
        # Simplified complexity calculation
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Count complexity indicators
            complexity_patterns = {
                'if': r'\bif\s*\(',
                'else': r'\belse\b',
                'for': r'\bfor\s*\(',
                'while': r'\bwhile\s*\(',
                'case': r'\bcase\s+',
                'catch': r'\bcatch\s*\(',
                '&&': r'&&',
                '||': r'\|\|',
                '?': r'\?(?!\.)'  # Ternary operator
            }
            
            total_complexity = 1  # Base complexity
            
            for pattern_name, pattern in complexity_patterns.items():
                matches = len(re.findall(pattern, content))
                total_complexity += matches
            
            # Estimate average (divide by estimated function count)
            function_count = len(re.findall(r'function\s*\w*\s*\(', content)) or 1
            avg_complexity = total_complexity / function_count
            
            return {
                'average_complexity': avg_complexity,
                'total_complexity': total_complexity,
                'max_complexity': int(avg_complexity * 1.5),  # Estimate
                'risk_level': self._get_risk_level(avg_complexity)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing complexity: {e}")
            return None
    
    async def analyze_dependencies(self, file_path: Path) -> List[Dict[str, Any]]:
        """Extract JavaScript imports."""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # ES6 imports
            es6_import_pattern = r'import\s+(?:(?:\*\s+as\s+\w+)|(?:\{[^}]+\})|(?:\w+))?\s*(?:,\s*(?:\{[^}]+\}|\w+))?\s*from\s*[\'"]([^\'"]+)[\'"]'
            for match in re.finditer(es6_import_pattern, content):
                dependencies.append({
                    'source': str(file_path),
                    'target': match.group(1),
                    'type': 'es6_import',
                    'line': content[:match.start()].count('\n') + 1
                })
            
            # CommonJS requires
            require_pattern = r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)'
            for match in re.finditer(require_pattern, content):
                dependencies.append({
                    'source': str(file_path),
                    'target': match.group(1),
                    'type': 'commonjs_require',
                    'line': content[:match.start()].count('\n') + 1
                })
            
            # Dynamic imports
            dynamic_pattern = r'import\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)'
            for match in re.finditer(dynamic_pattern, content):
                dependencies.append({
                    'source': str(file_path),
                    'target': match.group(1),
                    'type': 'dynamic_import',
                    'line': content[:match.start()].count('\n') + 1
                })
            
        except Exception as e:
            logger.error(f"Error extracting dependencies: {e}")
        
        return dependencies
    
    def get_comment_patterns(self) -> Dict[str, str]:
        return {
            'single_line': r'//.*$',
            'multi_line': r'/\*[\s\S]*?\*/',
            'jsdoc': r'/\*\*[\s\S]*?\*/'
        }
    
    def _count_comments(self, lines: List[str]) -> int:
        """Count comment lines."""
        comment_count = 0
        in_multiline = False
        
        for line in lines:
            stripped = line.strip()
            
            if in_multiline:
                comment_count += 1
                if '*/' in line:
                    in_multiline = False
            elif stripped.startswith('//'):
                comment_count += 1
            elif stripped.startswith('/*'):
                comment_count += 1
                if '*/' not in line:
                    in_multiline = True
        
        return comment_count
    
    def _is_comment(self, line: str) -> bool:
        """Check if line is a comment."""
        stripped = line.strip()
        return (stripped.startswith('//') or 
                stripped.startswith('/*') or 
                stripped.startswith('*'))
    
    def _get_risk_level(self, complexity: float) -> str:
        """Get risk level based on complexity."""
        if complexity > 20:
            return "🔴 Very High Risk"
        elif complexity > 10:
            return "🟠 High Risk"
        elif complexity > 5:
            return "🟡 Medium Risk"
        else:
            return "🟢 Low Risk"