# src/analyzers/quality.py
import ast
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
import subprocess

from ..utils.logger import logger
from ..config import settings
from ..models.quality import QualityIssue, QualityMetric, CodeSmell

class QualityAnalyzer:
    """Analyze code quality metrics and detect code smells."""
    
    def __init__(self):
        self.smell_detectors = self._init_smell_detectors()
        self.pylint_available = self._check_pylint()
        
    def _check_pylint(self) -> bool:
        """Check if pylint is available."""
        try:
            subprocess.run(['pylint', '--version'], capture_output=True)
            return True
        except FileNotFoundError:
            return False
    
    def _init_smell_detectors(self) -> Dict[str, Any]:
        """Initialize code smell detection patterns."""
        return {
            'long_method': {
                'threshold': 50,
                'message': 'Method is too long. Consider breaking it down.'
            },
            'large_class': {
                'threshold': 300,
                'message': 'Class is too large. Consider splitting responsibilities.'
            },
            'too_many_parameters': {
                'threshold': 5,
                'message': 'Too many parameters. Consider using a configuration object.'
            },
            'duplicate_code': {
                'threshold': 5,
                'message': 'Possible code duplication detected.'
            },
            'nested_complexity': {
                'threshold': 4,
                'message': 'Deeply nested code. Consider extracting methods.'
            },
            'long_line': {
                'threshold': 120,
                'message': 'Line too long. Consider breaking it up.'
            },
            'magic_numbers': {
                'pattern': r'\b\d{2,}\b',
                'message': 'Magic number detected. Consider using named constant.'
            }
        }
    
    async def check_quality(
        self,
        file_path: Path,
        standards: List[str] = None
    ) -> Dict[str, Any]:
        """Check code quality for a file."""
        logger.debug(f"Quality check for: {file_path}")
        
        quality_issues = []
        metrics = {}
        
        # Read file
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            return self._format_quality_results(file_path, [], {}, error=str(e))
        
        # Language-specific analysis
        if file_path.suffix == '.py':
            py_issues, py_metrics = await self._analyze_python_quality(
                file_path, 
                content, 
                lines
            )
            quality_issues.extend(py_issues)
            metrics.update(py_metrics)
            
            # Run pylint if available
            if self.pylint_available and (not standards or 'pylint' in standards):
                pylint_issues = await self._run_pylint(file_path)
                quality_issues.extend(pylint_issues)
        
        # General code smell detection
        smell_issues = await self._detect_code_smells(content, lines, file_path)
        quality_issues.extend(smell_issues)
        
        # Calculate overall quality score
        quality_score = self._calculate_quality_score(quality_issues, metrics)
        
        return self._format_quality_results(
            file_path, 
            quality_issues, 
            metrics,
            quality_score
        )
    
    async def _analyze_python_quality(
        self,
        file_path: Path,
        content: str,
        lines: List[str]
    ) -> Tuple[List[QualityIssue], Dict[str, Any]]:
        """Python-specific quality analysis."""
        issues = []
        metrics = {}
        
        try:
            tree = ast.parse(content)
            
            # Analyze AST
            analyzer = PythonQualityVisitor(lines)
            analyzer.visit(tree)
            
            issues = analyzer.issues
            metrics = {
                'max_function_length': analyzer.max_function_length,
                'max_class_length': analyzer.max_class_length,
                'max_parameters': analyzer.max_parameters,
                'max_nesting_depth': analyzer.max_nesting_depth,
                'total_functions': analyzer.total_functions,
                'total_classes': analyzer.total_classes,
                'docstring_coverage': analyzer.docstring_coverage
            }
            
        except SyntaxError as e:
            logger.warning(f"Syntax error in quality analysis: {e}")
            issues.append(QualityIssue(
                type='syntax_error',
                severity='high',
                message=f"Syntax error: {str(e)}",
                file_path=str(file_path),
                line_number=e.lineno or 0,
                column=e.offset or 0,
                code_snippet=lines[e.lineno-1].strip() if e.lineno and e.lineno <= len(lines) else '',
                reference='',
                fix_suggestion='Fix the syntax error.'
            ))
        
        return issues, metrics
    
    async def _detect_code_smells(
        self,
        content: str,
        lines: List[str],
        file_path: Path
    ) -> List[QualityIssue]:
        """Detect common code smells."""
        issues = []
        
        # Long lines
        for i, line in enumerate(lines):
            if len(line) > self.smell_detectors['long_line']['threshold']:
                issues.append(QualityIssue(
                    type='long_line',
                    severity='low',
                    message=self.smell_detectors['long_line']['message'],
                    file_path=str(file_path),
                    line_number=i + 1,
                    column=self.smell_detectors['long_line']['threshold'],
                    code_snippet=line.strip(),
                    reference='PEP8: E501',
                    fix_suggestion='Break long lines into shorter ones.'
                ))
        
        # Magic numbers
        magic_pattern = re.compile(self.smell_detectors['magic_numbers']['pattern'])
        for i, line in enumerate(lines):
            # Skip comments and strings
            if '#' in line:
                line = line[:line.index('#')]
            
            for match in magic_pattern.finditer(line):
                # Skip common acceptable numbers
                if match.group() not in ['0', '1', '2', '10', '100']:
                    issues.append(QualityIssue(
                        type='magic_number',
                        severity='low',
                        message=self.smell_detectors['magic_numbers']['message'],
                        file_path=str(file_path),
                        line_number=i + 1,
                        column=match.start(),
                        code_snippet=line.strip(),
                        reference='PEP8: Avoid magic numbers',
                        fix_suggestion='Replace with a named constant.'
                    ))
        
        # Duplicate code detection (simple version)
        duplicate_blocks = self._find_duplicate_blocks(lines)
        for dup in duplicate_blocks:
            issues.append(QualityIssue(
                type='duplicate_code',
                severity='medium',
                message=f"Duplicate code block found (lines {dup['start']}-{dup['end']})",
                file_path=str(file_path),
                line_number=dup['start'],
                column=0,
                code_snippet='\n'.join(lines[dup['start']-1:dup['end']]),
                reference='DRY Principle',
                fix_suggestion='Refactor duplicate code into a function or method.'
            ))
        
        return issues
    
    def _find_duplicate_blocks(
        self, 
        lines: List[str], 
        min_size: int = 5
    ) -> List[Dict[str, int]]:
        """Find duplicate code blocks."""
        duplicates = []
        
        # Simple approach: look for exact duplicate blocks
        for i in range(len(lines) - min_size):
            block1 = lines[i:i + min_size]
            
            for j in range(i + min_size, len(lines) - min_size):
                block2 = lines[j:j + min_size]
                
                if block1 == block2:
                    duplicates.append({
                        'start': i + 1,
                        'end': i + min_size,
                        'duplicate_start': j + 1
                    })
        
        return duplicates
    
    async def _run_pylint(self, file_path: Path) -> List[QualityIssue]:
        """Run pylint and parse results."""
        try:
            cmd = [
                'pylint',
                '--output-format=json',
                '--disable=R,C',  # Only errors and warnings
                str(file_path)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if result.stdout:
                data = json.loads(result.stdout)
                issues = []
                
                for item in data:
                    severity = 'high' if item['type'] == 'error' else 'medium'
                    
                    issue = QualityIssue(
                        type=f"pylint_{item['symbol']}",
                        severity=severity,
                        message=item['message'],
                        file_path=str(file_path),
                        line_number=item['line'],
                        column=item['column']
                    )
                    
                    issues.append(issue)
                
                return issues
            
        except Exception as e:
            logger.error(f"Error running pylint: {e}")
        
        return []
    
    def _calculate_quality_score(
        self,
        issues: List[QualityIssue],
        metrics: Dict[str, Any]
    ) -> float:
        """Calculate overall quality score (0-100)."""
        # Start with perfect score
        score = 100.0
        
        # Deduct for issues
        for issue in issues:
            if issue.severity == 'high':
                score -= 5
            elif issue.severity == 'medium':
                score -= 2
            elif issue.severity == 'low':
                score -= 0.5
        
        # Deduct for poor metrics
        if metrics.get('max_function_length', 0) > 100:
            score -= 10
        elif metrics.get('max_function_length', 0) > 50:
            score -= 5
        
        if metrics.get('max_nesting_depth', 0) > 5:
            score -= 10
        elif metrics.get('max_nesting_depth', 0) > 3:
            score -= 5
        
        # Bonus for good documentation
        doc_coverage = metrics.get('docstring_coverage', 0)
        if doc_coverage > 0.8:
            score += 5
        elif doc_coverage < 0.3:
            score -= 5
        
        return max(0, min(100, score))
    
    def _format_quality_results(
        self,
        file_path: Path,
        issues: List[QualityIssue],
        metrics: Dict[str, Any],
        quality_score: float = 0,
        error: Optional[str] = None
    ) -> Dict[str, Any]:
        """Format quality check results."""
        if error:
            return {
                'file_path': str(file_path),
                'status': 'error',
                'error': error
            }
        
        # Group issues by type
        issues_by_type = defaultdict(list)
        for issue in issues:
            issues_by_type[issue.type].append(issue)
        
        return {
            'file_path': str(file_path),
            'status': 'completed',
            'quality_score': round(quality_score, 1),
            'total_issues': len(issues),
            'issues_by_severity': {
                'high': len([i for i in issues if i.severity == 'high']),
                'medium': len([i for i in issues if i.severity == 'medium']),
                'low': len([i for i in issues if i.severity == 'low'])
            },
            'issues_by_type': {
                k: len(v) for k, v in issues_by_type.items()
            },
            'metrics': metrics,
            'issues': [issue.to_dict() for issue in issues[:50]]  # Limit to 50
        }


class PythonQualityVisitor(ast.NodeVisitor):
    """AST visitor for Python quality metrics."""
    
    def __init__(self, lines: List[str]):
        self.lines = lines
        self.issues = []
        self.current_depth = 0
        self.max_nesting_depth = 0
        self.max_function_length = 0
        self.max_class_length = 0
        self.max_parameters = 0
        self.total_functions = 0
        self.total_classes = 0
        self.functions_with_docstrings = 0
        
    def visit_FunctionDef(self, node):
        """Visit function definition."""
        self.total_functions += 1
        
        # Check docstring
        if ast.get_docstring(node):
            self.functions_with_docstrings += 1
        else:
            self.issues.append(QualityIssue(
                type='missing_docstring',
                severity='low',
                message=f"Function '{node.name}' missing docstring",
                file_path="",
                line_number=node.lineno,
                column=node.col_offset,
                code_snippet=self.lines[node.lineno-1].strip() if node.lineno and node.lineno <= len(self.lines) else '',
                reference='PEP8: E251',
                fix_suggestion='Add a docstring to the function.'
            ))
        
        # Check function length
        func_length = node.end_lineno - node.lineno + 1
        if func_length > 50:
            self.issues.append(QualityIssue(
                type='long_function',
                severity='medium',
                message=f"Function '{node.name}' is too long ({func_length} lines)",
                file_path="",
                line_number=node.lineno,
                column=node.col_offset,
                code_snippet=self.lines[node.lineno-1].strip() if node.lineno and node.lineno <= len(self.lines) else '',
                reference='PEP8: E501',
                fix_suggestion='Break long functions into smaller ones.'
            ))
        self.max_function_length = max(self.max_function_length, func_length)
        
        # Check parameters
        num_params = len(node.args.args)
        if num_params > 5:
            self.issues.append(QualityIssue(
                type='too_many_parameters',
                severity='medium',
                message=f"Function '{node.name}' has too many parameters ({num_params})",
                file_path="",
                line_number=node.lineno,
                column=node.col_offset,
                code_snippet=self.lines[node.lineno-1].strip() if node.lineno and node.lineno <= len(self.lines) else '',
                reference='PEP8: R0913',
                fix_suggestion='Consider reducing the number of parameters.'
            ))
        self.max_parameters = max(self.max_parameters, num_params)
        
        # Check nesting
        self.current_depth += 1
        self.max_nesting_depth = max(self.max_nesting_depth, self.current_depth)
        self.generic_visit(node)
        self.current_depth -= 1
    
    def visit_ClassDef(self, node):
        """Visit class definition."""
        self.total_classes += 1
        
        # Check class length
        class_length = node.end_lineno - node.lineno + 1
        if class_length > 300:
            self.issues.append(QualityIssue(
                type='large_class',
                severity='medium',
                message=f"Class '{node.name}' is too large ({class_length} lines)",
                file_path="",
                line_number=node.lineno,
                column=node.col_offset,
                code_snippet=self.lines[node.lineno-1].strip() if node.lineno and node.lineno <= len(self.lines) else '',
                reference='PEP8: E1002',
                fix_suggestion='Consider splitting the class into smaller ones.'
            ))
        self.max_class_length = max(self.max_class_length, class_length)
        
        self.generic_visit(node)
    
    def visit_If(self, node):
        """Track nesting depth."""
        self.current_depth += 1
        self.max_nesting_depth = max(self.max_nesting_depth, self.current_depth)
        self.generic_visit(node)
        self.current_depth -= 1
    
    def visit_For(self, node):
        """Track nesting depth."""
        self.current_depth += 1
        self.max_nesting_depth = max(self.max_nesting_depth, self.current_depth)
        self.generic_visit(node)
        self.current_depth -= 1
    
    def visit_While(self, node):
        """Track nesting depth."""
        self.current_depth += 1
        self.max_nesting_depth = max(self.max_nesting_depth, self.current_depth)
        self.generic_visit(node)
        self.current_depth -= 1
    
    @property
    def docstring_coverage(self) -> float:
        """Calculate docstring coverage percentage."""
        if self.total_functions == 0:
            return 1.0
        return self.functions_with_docstrings / self.total_functions