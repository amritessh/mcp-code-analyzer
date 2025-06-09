# src/models/metrics.py
from enum import Enum
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

class ComplexityLevel(Enum):
    """Complexity risk levels."""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"

@dataclass
class ComplexityMetric:
    """Represents a complexity measurement."""
    name: str
    metric_type: str  # 'function', 'class', 'method'
    complexity: int
    line_start: int
    line_end: int
    risk_level: ComplexityLevel
    file_path: str
    
    @property
    def is_high_risk(self) -> bool:
        return self.risk_level in [ComplexityLevel.HIGH, ComplexityLevel.VERY_HIGH]

@dataclass
class FileMetrics:
    """Aggregated metrics for a file."""
    file_path: str
    language: str
    loc: int
    complexity_average: float
    complexity_max: int
    maintainability_index: float
    halstead_volume: float
    halstead_difficulty: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'file_path': self.file_path,
            'language': self.language,
            'metrics': {
                'loc': self.loc,
                'complexity': {
                    'average': self.complexity_average,
                    'max': self.complexity_max
                },
                'maintainability_index': self.maintainability_index,
                'halstead': {
                    'volume': self.halstead_volume,
                    'difficulty': self.halstead_difficulty
                }
            }
        }