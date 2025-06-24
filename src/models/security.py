# src/models/security.py
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

class Severity(Enum):
    """Security issue severity levels."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    
    def __str__(self):
        return self.name

@dataclass
class SecurityRule:
    """Definition of a security detection rule."""
    id: str
    name: str
    pattern: str
    severity: Severity
    message: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    fix_suggestion: Optional[str] = None

@dataclass
class SecurityIssue:
    """Represents a detected security issue."""
    rule_id: str
    severity: Severity
    message: str
    file_path: str
    line_number: int
    column: int
    code_snippet: str
    cwe: Optional[str] = None
    confidence: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'rule_id': self.rule_id,
            'severity': self.severity.name,
            'severity_value': self.severity.value,
            'message': self.message,
            'location': {
                'file': self.file_path,
                'line': self.line_number,
                'column': self.column
            },
            'code_snippet': self.code_snippet,
            'cwe': self.cwe,
            'confidence': self.confidence
        }
    
    @property
    def is_critical(self) -> bool:
        return self.severity in [Severity.CRITICAL, Severity.HIGH]

@dataclass
class SecurityReport:
    """Overall security analysis report."""
    files_scanned: int
    total_issues: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    info_issues: int
    risk_score: int
    top_vulnerabilities: List[str]
    affected_files: List[str]
    scan_duration: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'summary': {
                'files_scanned': self.files_scanned,
                'total_issues': self.total_issues,
                'risk_score': self.risk_score,
                'scan_duration': f"{self.scan_duration:.2f}s"
            },
            'severity_breakdown': {
                'critical': self.critical_issues,
                'high': self.high_issues,
                'medium': self.medium_issues,
                'low': self.low_issues,
                'info': self.info_issues
            },
            'top_vulnerabilities': self.top_vulnerabilities,
            'affected_files': self.affected_files
        }