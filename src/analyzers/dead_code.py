# src/analyzers/dead_code.py
import ast
import os
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
import subprocess

from utils.logger import logger

class DeadCodeDetector:
    """Detect unused code, imports, and variables."""
    
    def __init__(self):
        self.vulture_available = self._check_vulture()
    
    def _check_vulture(self) -> bool:
        """Check if vulture is available."""
        try:
            subprocess.run(['vulture', '--version'], capture_output=True)
            return True
        except FileNotFoundError:
            return False
    
    async def detect_dead_code(
        self,
        file_path: Path,
        include_unused_imports: bool = True,
        include_unused_variables: bool = True,
        include_unused_functions: bool = True
    ) -> Dict[str, Any]:
        """Detect dead code in a file."""
        logger.debug(f"Detecting dead code in: {file_path}")
        
        dead_code_items = []
        
        # Language-specific detection
        if file_path.suffix == '.py':
            # Use AST analysis
            ast_items = await self._detect_python_dead_code(
                file_path,
                include_unused_imports,
                include_unused_variables,
                include_unused_functions
            )
            dead_code_items.extend(ast_items)
            
            # Use vulture if available
            if self.vulture_available:
                vulture_items = await self._run_vulture(file_path)
                dead_code_items.extend(vulture_items)
        
        return {
            'file_path': str(file_path),
            'total_dead_code': len(dead_code_items),
            'by_type': self._group_by_type(dead_code_items),
            'items': dead_code_items
        }
    
    async def _detect_python_dead_code(
        self,
        file_path: Path,
        include_imports: bool,
        include_variables: bool,
        include_functions: bool
    ) -> List[Dict[str, Any]]:
        """Detect dead code using AST analysis."""
        dead_code = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            # Analyze usage
            analyzer = UsageAnalyzer()
            analyzer.visit(tree)
            
            # Find unused items
            if include_imports:
                for name, node in analyzer.imports.items():
                    if name not in analyzer.used_names:
                        dead_code.append({
                            'type': 'unused_import',
                            'name': name,
                            'line': node.lineno,
                            'message': f"Unused import: {name}"
                        })
            
            if include_variables:
                for name, node in analyzer.variables.items():
                    if name not in analyzer.used_names and not name.startswith('_'):
                        dead_code.append({
                            'type': 'unused_variable',
                            'name': name,
                            'line': node.lineno,
                            'message': f"Unused variable: {name}"
                        })
            
            if include_functions:
                for name, node in analyzer.functions.items():
                    if (name not in analyzer.used_names and 
                        not name.startswith('_') and
                        name not in ['__init__', 'setUp', 'tearDown']):
                        dead_code.append({
                            'type': 'unused_function',
                            'name': name,
                            'line': node.lineno,
                            'message': f"Unused function: {name}"
                        })
            
        except Exception as e:
            logger.error(f"Error detecting dead code in {file_path}: {e}")
        
        return dead_code
    
    async def _run_vulture(self, file_path: Path) -> List[Dict[str, Any]]:
        """Run vulture for comprehensive dead code detection."""
        try:
            cmd = ['vulture', str(file_path), '--min-confidence', '80']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            dead_code = []
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        # Parse vulture output
                        parts = line.split(':')
                        if len(parts) >= 3:
                            line_num = int(parts[1])
                            message = ':'.join(parts[2:]).strip()
                            
                            # Determine type
                            if 'unused import' in message.lower():
                                item_type = 'unused_import'
                            elif 'unused variable' in message.lower():
                                item_type = 'unused_variable'
                            elif 'unused function' in message.lower():
                                item_type = 'unused_function'
                            elif 'unused class' in message.lower():
                                item_type = 'unused_class'
                            else:
                                item_type = 'dead_code'
                            
                            dead_code.append({
                                'type': item_type,
                                'line': line_num,
                                'message': message,
                                'tool': 'vulture'
                            })
            
            return dead_code
            
        except Exception as e:
            logger.error(f"Error running vulture: {e}")
            return []
    
    def _group_by_type(self, items: List[Dict[str, Any]]) -> Dict[str, int]:
        """Group dead code items by type."""
        counts = {}
        for item in items:
            item_type = item['type']
            counts[item_type] = counts.get(item_type, 0) + 1
        return counts


class UsageAnalyzer(ast.NodeVisitor):
    """Analyze variable and function usage in Python code."""
    
    def __init__(self):
        self.imports = {}
        self.variables = {}
        self.functions = {}
        self.classes = {}
        self.used_names = set()
        self.in_function = False
        self.in_class = False
    
    def visit_Import(self, node):
        """Track imports."""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.imports[name] = node
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node):
        """Track from imports."""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.imports[name] = node
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node):
        """Track function definitions."""
        if not self.in_class or node.name.startswith('__'):
            self.functions[node.name] = node
        
        old_in_function = self.in_function
        self.in_function = True
        self.generic_visit(node)
        self.in_function = old_in_function
    
    def visit_ClassDef(self, node):
        """Track class definitions."""
        self.classes[node.name] = node
        
        old_in_class = self.in_class
        self.in_class = True
        self.generic_visit(node)
        self.in_class = old_in_class
    
    def visit_Name(self, node):
        """Track name usage."""
        if isinstance(node.ctx, ast.Store):
            # Variable assignment
            if not self.in_function and not self.in_class:
                self.variables[node.id] = node
        else:
            # Name usage
            self.used_names.add(node.id)
        self.generic_visit(node)
    
    def visit_Attribute(self, node):
        """Track attribute usage."""
        if isinstance(node.value, ast.Name):
            self.used_names.add(node.value.id)
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Track function calls."""
        if isinstance(node.func, ast.Name):
            self.used_names.add(node.func.id)
        self.generic_visit(node)