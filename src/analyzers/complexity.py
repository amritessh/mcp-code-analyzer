# src/analyzers/complexity.py
import ast
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import networkx as nx
from utils.logger import logger
from config import settings
from models.metrics import ComplexityMetric, ComplexityLevel, ComplexityIssue
import radon.complexity as radon_cc
import radon.metrics as radon_metrics
from radon.visitors import ComplexityVisitor

class ComplexityAnalyzer:
    """Analyze code complexity using various metrics."""
    
    def __init__(self):
        self.thresholds = settings.complexity_thresholds
    
    async def analyze_complexity(
        self, 
        file_path: Path, 
        include_details: bool = False
    ) -> Dict[str, Any]:
        """Analyze complexity of a Python file."""
        logger.debug(f"Analyzing complexity for: {file_path}")
        
        # Read file
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            raise
        
        # Get complexity metrics
        cc_results = self._get_cyclomatic_complexity(content, file_path.name)
        mi_score = self._get_maintainability_index(content)
        halstead = self._get_halstead_metrics(content)
        
        # Calculate aggregates
        complexities = [r.complexity for r in cc_results]
        avg_complexity = sum(complexities) / len(complexities) if complexities else 0
        max_complexity = max(complexities) if complexities else 0
        total_complexity = sum(complexities)
        
        # Determine risk level
        risk_level = self._calculate_risk_level(avg_complexity, max_complexity)
        
        result = {
            'file_path': str(file_path),
            'average_complexity': avg_complexity,
            'max_complexity': max_complexity,
            'total_complexity': total_complexity,
            'maintainability_index': mi_score,
            'risk_level': risk_level,
            'metrics_summary': {
                'cyclomatic_complexity': {
                    'average': avg_complexity,
                    'max': max_complexity,
                    'total': total_complexity
                },
                'maintainability_index': mi_score,
                'halstead': halstead
            }
        }
        
        if include_details:
            result['details'] = self._format_complexity_details(cc_results)
            result['hotspots'] = self._identify_hotspots(cc_results, str(file_path), content)
        
        return result
    
    def _get_cyclomatic_complexity(
        self, 
        content: str, 
        filename: str
    ) -> List[ComplexityVisitor]:
        """Calculate cyclomatic complexity."""
        try:
            results = radon_cc.cc_visit(content)
            return sorted(results, key=lambda x: x.complexity, reverse=True)
        except SyntaxError as e:
            logger.error(f"Syntax error in complexity analysis: {e}")
            return []
    
    def _get_maintainability_index(self, content: str) -> float:
        """Calculate maintainability index (0-100)."""
        try:
            mi = radon_metrics.mi_visit(content, multi=True)
            return round(mi, 2)
        except Exception as e:
            logger.error(f"Error calculating MI: {e}")
            return 0.0
    
    def _get_halstead_metrics(self, content: str) -> Dict[str, float]:
        """Calculate Halstead complexity metrics."""
        try:
            h = radon_metrics.h_visit(content)
            # Check if the Halstead object has the expected attributes
            metrics = {}
            
            # Use getattr with default values to handle missing attributes
            metrics['volume'] = round(getattr(h, 'volume', 0), 2)
            metrics['difficulty'] = round(getattr(h, 'difficulty', 0), 2)
            metrics['effort'] = round(getattr(h, 'effort', 0), 2)
            metrics['time'] = round(getattr(h, 'time', 0), 2)
            metrics['bugs'] = round(getattr(h, 'bugs', 0), 2)
            
            return metrics
        except Exception as e:
            logger.error(f"Error calculating Halstead metrics: {e}")
            return {
                'volume': 0,
                'difficulty': 0,
                'effort': 0,
                'time': 0,
                'bugs': 0
            }
    
    def _calculate_risk_level(self, avg: float, max_val: float) -> str:
        """Determine risk level based on complexity."""
        if max_val > self.thresholds['very_high']:
            return "🔴 Very High Risk"
        elif max_val > self.thresholds['high']:
            return "🟠 High Risk"
        elif avg > self.thresholds['medium']:
            return "🟡 Medium Risk"
        elif avg > self.thresholds['low']:
            return "🟢 Low Risk"
        else:
            return "🟢 Very Low Risk"
    
    def _format_complexity_details(
        self, 
        results: List[ComplexityVisitor]
    ) -> List[Dict[str, Any]]:
        """Format complexity results for output."""
        details = []
        
        for r in results:
            complexity_level = self._get_complexity_level(r.complexity)
            detail = {
                'name': r.name,
                'type': r.letter,  # F for function, C for class, M for method
                'complexity': r.complexity,
                'risk_level': complexity_level,
                'line_number': r.lineno,
                'end_line': r.endline
            }
            
            # Only add is_method for functions/methods
            if hasattr(r, 'is_method'):
                detail['is_method'] = r.is_method
                
            details.append(detail)
        
        return details
    
    def _get_complexity_level(self, complexity: int) -> str:
        """Get complexity level for a single item."""
        if complexity > self.thresholds['very_high']:
            return "Very High"
        elif complexity > self.thresholds['high']:
            return "High"
        elif complexity > self.thresholds['medium']:
            return "Medium"
        elif complexity > self.thresholds['low']:
            return "Low"
        else:
            return "Very Low"
    
    def _identify_hotspots(
        self, 
        results: List[ComplexityVisitor],
        file_path: str = None,
        content: str = None
    ) -> List[Dict[str, Any]]:
        """Identify complexity hotspots that need attention."""
        hotspots = []
        lines = content.split('\n') if content else []
        for r in results:
            if r.complexity > self.thresholds['high']:
                snippet = ''
                if lines and r.lineno and r.endline:
                    snippet = '\n'.join(lines[r.lineno-1:r.endline])
                issue = ComplexityIssue(
                    name=r.name,
                    type=r.letter,
                    complexity=r.complexity,
                    risk_level=self._get_complexity_level(r.complexity),
                    file_path=file_path or '',
                    line_number=r.lineno,
                    end_line=r.endline,
                    code_snippet=snippet,
                    reference='Cyclomatic Complexity',
                    fix_suggestion=self._get_recommendation(r.complexity)
                )
                hotspots.append(issue.to_dict())
        return hotspots[:5]  # Top 5 hotspots
    
    def _get_recommendation(self, complexity: int) -> str:
        """Get refactoring recommendation based on complexity."""
        if complexity > 30:
            return "Critical: Consider breaking into multiple functions"
        elif complexity > 20:
            return "High: Extract complex conditions into separate methods"
        elif complexity > 10:
            return "Medium: Consider simplifying logic"
        else:
            return "Low: Minor simplification possible"