# src/models/quality.py
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from enum import Enum

class CodeSmell(Enum):
    """Types of code smells."""
    LONG_METHOD = "long_method"
    LARGE_CLASS = "large_class"
    TOO_MANY_PARAMETERS = "too_many_parameters"
    DUPLICATE_CODE = "duplicate_code"
    DEAD_CODE = "dead_code"
    MAGIC_NUMBERS = "magic_numbers"
    COMPLEX_CONDITIONALS = "complex_conditionals"
    INAPPROPRIATE_INTIMACY = "inappropriate_intimacy"

@dataclass
class QualityIssue:
    """Represents a code quality issue."""
    type: str
    severity: str  # 'low', 'medium', 'high'
    message: str
    file_path: str
    line_number: int
    column: int
    code_snippet: str = ""
    reference: str = ""
    fix_suggestion: str = ""
    suggestion: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.type,
            'severity': self.severity,
            'message': self.message,
            'location': {
                'file': self.file_path,
                'line': self.line_number,
                'column': self.column
            },
            'code_snippet': self.code_snippet,
            'reference': self.reference,
            'fix_suggestion': self.fix_suggestion,
            'suggestion': self.suggestion
        }

@dataclass
class QualityMetric:
    """Code quality metrics."""
    name: str
    value: float
    threshold: float
    status: str  # 'good', 'warning', 'bad'
    
    @property
    def is_violation(self) -> bool:
        return self.status == 'bad'

@dataclass
class QualityReport:
    """Overall quality analysis report."""
    quality_score: float
    total_issues: int
    issues_by_severity: Dict[str, int]
    code_smells: List[str]
    metrics: Dict[str, float]
    suggestions: List[str]