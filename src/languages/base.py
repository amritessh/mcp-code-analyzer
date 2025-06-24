# src/languages/base.py
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import ast
import re

class LanguageAdapter(ABC):
    """Base class for language-specific analyzers."""
    
    @abstractmethod
    def can_handle(self, file_path: Path) -> bool:
        """Check if this adapter can handle the file."""
        pass
    
    @abstractmethod
    async def analyze_basic(self, file_path: Path) -> Dict[str, Any]:
        """Perform basic analysis (LOC, functions, etc.)."""
        pass
    
    @abstractmethod
    async def analyze_complexity(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Analyze code complexity if applicable."""
        pass
    
    @abstractmethod
    async def analyze_dependencies(self, file_path: Path) -> List[Dict[str, Any]]:
        """Extract import/dependency information."""
        pass
    
    @abstractmethod
    def get_comment_patterns(self) -> Dict[str, str]:
        """Get comment patterns for the language."""
        pass