# src/analyzers/todo_tracker.py
import re
import os
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass

from utils.logger import logger
from config import settings

@dataclass
class TodoItem:
    """Represents a TODO/FIXME comment."""
    type: str  # 'TODO', 'FIXME', 'HACK', 'NOTE', 'XXX'
    message: str
    file_path: str
    line_number: int
    author: Optional[str] = None
    date: Optional[str] = None
    priority: Optional[str] = None  # 'low', 'medium', 'high'
    category: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.type,
            'message': self.message,
            'location': {
                'file': self.file_path,
                'line': self.line_number
            },
            'metadata': {
                'author': self.author,
                'date': self.date,
                'priority': self.priority,
                'category': self.category
            }
        }

class TodoTracker:
    """Track and analyze TODO/FIXME comments."""
    
    def __init__(self):
        self.patterns = self._init_patterns()
        
    def _init_patterns(self) -> Dict[str, re.Pattern]:
        """Initialize regex patterns for different comment types."""
        return {
            'todo': re.compile(
                r'(?:#|//|/\*|\*)\s*(TODO|FIXME|HACK|XXX|NOTE|BUG)'
                r'(?:\s*\(([^)]+)\))?'  # Optional author/date
                r'(?:\s*:)?\s*(.+?)(?:\*/)?$',
                re.IGNORECASE | re.MULTILINE
            ),
            'priority': re.compile(
                r'\b(URGENT|HIGH|MEDIUM|LOW|P[0-5])\b',
                re.IGNORECASE
            ),
            'category': re.compile(
                r'\[([\w\s-]+)\]'
            ),
            'author_date': re.compile(
                r'(\w+)(?:\s+(\d{4}-\d{2}-\d{2}))?'
            )
        }
    
    async def find_todos(
        self,
        path: Path,
        include_patterns: List[str] = None,
        recursive: bool = True
    ) -> Dict[str, Any]:
        """Find all TODO/FIXME comments in a file or directory."""
        logger.debug(f"Searching for TODOs in: {path}")
        
        todos = []
        
        if path.is_file():
            file_todos = await self._scan_file(path, include_patterns)
            todos.extend(file_todos)
        elif path.is_dir() and recursive:
            for file_path in path.rglob('*'):
                if file_path.is_file() and self._should_scan_file(file_path):
                    file_todos = await self._scan_file(file_path, include_patterns)
                    todos.extend(file_todos)
        
        # Analyze and categorize
        analysis = self._analyze_todos(todos)
        
        return {
            'total_todos': len(todos),
            'by_type': analysis['by_type'],
            'by_priority': analysis['by_priority'],
            'by_author': analysis['by_author'],
            'by_file': analysis['by_file'],
            'items': [todo.to_dict() for todo in todos],
            'summary': self._generate_summary(analysis)
        }
    
    def _should_scan_file(self, file_path: Path) -> bool:
        """Check if file should be scanned."""
        # Skip binary files and common non-code files
        skip_extensions = {'.pyc', '.pyo', '.so', '.dll', '.exe', '.bin'}
        skip_dirs = {'__pycache__', '.git', 'node_modules', 'venv', '.env'}
        
        if file_path.suffix in skip_extensions:
            return False
            
        for parent in file_path.parents:
            if parent.name in skip_dirs:
                return False
                
        return True
    
    async def _scan_file(
        self,
        file_path: Path,
        include_patterns: Optional[List[str]] = None
    ) -> List[TodoItem]:
        """Scan a single file for TODO comments."""
        todos = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            logger.warning(f"Error reading {file_path}: {e}")
            return todos
        
        # Find all matches
        for match in self.patterns['todo'].finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            
            todo_type = match.group(1).upper()
            metadata = match.group(2)  # Author/date info
            message = match.group(3).strip()
            
            # Skip if not in include patterns
            if include_patterns and todo_type not in include_patterns:
                continue
            
            # Parse metadata
            author = None
            date = None
            if metadata:
                author_match = self.patterns['author_date'].match(metadata)
                if author_match:
                    author = author_match.group(1)
                    date = author_match.group(2)
            
            # Extract priority
            priority = self._extract_priority(message)
            
            # Extract category
            category = None
            category_match = self.patterns['category'].search(message)
            if category_match:
                category = category_match.group(1)
                # Remove category from message
                message = self.patterns['category'].sub('', message).strip()
            
            todo = TodoItem(
                type=todo_type,
                message=message,
                file_path=str(file_path),
                line_number=line_num,
                author=author,
                date=date,
                priority=priority,
                category=category
            )
            
            todos.append(todo)
        
        return todos
    
    def _extract_priority(self, message: str) -> str:
        """Extract priority from message."""
        priority_match = self.patterns['priority'].search(message)
        
        if priority_match:
            priority_text = priority_match.group(1).upper()
            
            if priority_text in ['URGENT', 'HIGH', 'P0', 'P1']:
                return 'high'
            elif priority_text in ['MEDIUM', 'P2', 'P3']:
                return 'medium'
            else:
                return 'low'
        
        # Default priority based on type
        return 'medium'
    
    def _analyze_todos(self, todos: List[TodoItem]) -> Dict[str, Any]:
        """Analyze TODO items for patterns and statistics."""
        analysis = {
            'by_type': defaultdict(int),
            'by_priority': defaultdict(int),
            'by_author': defaultdict(int),
            'by_file': defaultdict(int),
            'by_category': defaultdict(int),
            'old_todos': []
        }
        
        for todo in todos:
            analysis['by_type'][todo.type] += 1
            analysis['by_priority'][todo.priority or 'unset'] += 1
            analysis['by_file'][todo.file_path] += 1
            
            if todo.author:
                analysis['by_author'][todo.author] += 1
                
            if todo.category:
                analysis['by_category'][todo.category] += 1
            
            # Check for old TODOs
            if todo.date:
                try:
                    todo_date = datetime.strptime(todo.date, '%Y-%m-%d')
                    age_days = (datetime.now() - todo_date).days
                    if age_days > 90:  # Older than 3 months
                        analysis['old_todos'].append({
                            'todo': todo,
                            'age_days': age_days
                        })
                except ValueError:
                    pass
        
        return analysis
    
    def _generate_summary(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary insights."""
        total = sum(analysis['by_type'].values())
        
        return {
            'high_priority_count': analysis['by_priority'].get('high', 0),
            'fixme_count': analysis['by_type'].get('FIXME', 0),
            'hack_count': analysis['by_type'].get('HACK', 0),
            'old_todos_count': len(analysis['old_todos']),
            'files_with_most_todos': sorted(
                analysis['by_file'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5],
            'recommendations': self._generate_recommendations(analysis, total)
        }
    
    def _generate_recommendations(
        self, 
        analysis: Dict[str, Any], 
        total: int
    ) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        if analysis['by_priority'].get('high', 0) > 5:
            recommendations.append(
                "High number of high-priority items. Schedule time to address them."
            )
        
        if analysis['by_type'].get('FIXME', 0) > total * 0.3:
            recommendations.append(
                "Many FIXME items indicate potential bugs. Prioritize fixing these."
            )
        
        if analysis['by_type'].get('HACK', 0) > 3:
            recommendations.append(
                "Multiple HACK items suggest technical debt. Plan refactoring."
            )
        
        if len(analysis['old_todos']) > 10:
            recommendations.append(
                f"{len(analysis['old_todos'])} TODOs are over 3 months old. "
                "Review and close or update them."
            )
        
        # Check concentration
        if analysis['by_file']:
            top_file_count = max(analysis['by_file'].values())
            if top_file_count > total * 0.3:
                recommendations.append(
                    "TODOs are concentrated in few files. These may need refactoring."
                )
        
        return recommendations