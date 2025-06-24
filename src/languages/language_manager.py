# src/languages/language_manager.py
from pathlib import Path
from typing import Dict, Any, List, Optional

from .base import LanguageAdapter
from .python import PythonAdapter  # Already exists from week 1
from .javascript import JavaScriptAdapter
from .generic import GenericAdapter
from ..utils.logger import logger

class LanguageManager:
    """Manages language-specific adapters."""
    
    def __init__(self):
        self.adapters = [
            PythonAdapter(),
            JavaScriptAdapter(),
            GenericAdapter()  # Must be last as fallback
        ]
    
    def get_adapter(self, file_path: Path) -> LanguageAdapter:
        """Get appropriate language adapter for file."""
        for adapter in self.adapters:
            if adapter.can_handle(file_path):
                return adapter
        
        # Should never reach here as GenericAdapter handles everything
        return self.adapters[-1]
    
    async def analyze_file(
        self,
        file_path: Path,
        analysis_types: List[str] = None
    ) -> Dict[str, Any]:
        """Analyze file using appropriate adapter."""
        adapter = self.get_adapter(file_path)
        
        if not analysis_types:
            analysis_types = ['basic', 'complexity', 'dependencies']
        
        results = {}
        
        if 'basic' in analysis_types:
            results['basic'] = await adapter.analyze_basic(file_path)
        
        if 'complexity' in analysis_types:
            complexity = await adapter.analyze_complexity(file_path)
            if complexity:
                results['complexity'] = complexity
        
        if 'dependencies' in analysis_types:
            results['dependencies'] = await adapter.analyze_dependencies(file_path)
        
        return results