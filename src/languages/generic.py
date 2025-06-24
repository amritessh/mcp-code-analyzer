# src/languages/generic.py
import re
from pathlib import Path
from typing import Dict, Any, List, Optional

from .base import LanguageAdapter
from ..utils.logger import logger

class GenericAdapter(LanguageAdapter):
    """Generic language adapter for unsupported languages."""
    
    def __init__(self):
        self.comment_patterns = {
            '#': r'#.*$',           # Python, Ruby, Shell
            '//': r'//.*$',         # C, C++, Java, Go
            '--': r'--.*$',         # SQL, Haskell
            ';': r';.*$',           # Assembly, Lisp
            '%': r'%.*$',           # LaTeX, Matlab
        }
    
    def can_handle(self, file_path: Path) -> bool:
        """Generic adapter can handle any text file."""
        try:
            # Check if it's a text file
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return not bool(chunk.translate(None, bytes(range(32, 127))))
        except:
            return False
    
    async def analyze_basic(self, file_path: Path) -> Dict[str, Any]:
        """Basic analysis for generic files."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.split('\n')
            
            # Detect likely comment style
            comment_char = self._detect_comment_style(lines)
            comment_lines = self._count_comments(lines, comment_char) if comment_char else 0
            
            metrics = {
                'total_lines': len(lines),
                'blank_lines': sum(1 for line in lines if not line.strip()),
                'comment_lines': comment_lines,
                'loc': sum(1 for line in lines if line.strip())
            }
            
            return {
                'language': self._detect_language(file_path),
                'metrics': metrics
            }
            
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
            return {'error': str(e)}
    
    async def analyze_complexity(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Generic complexity analysis."""
        # For generic files, we can't calculate meaningful complexity
        return None
    
    async def analyze_dependencies(self, file_path: Path) -> List[Dict[str, Any]]:
        """Generic dependency extraction."""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Look for common import patterns
            patterns = [
                r'import\s+(\S+)',          # General import
                r'include\s+[<"]([^>"]+)',  # C/C++ style
                r'require\s+[\'"]([^\'"]+)', # Ruby/Node style
                r'use\s+(\S+)',             # Rust/Perl style
            ]
            
            for pattern in patterns:
                for match in re.finditer(pattern, content):
                    dependencies.append({
                        'source': str(file_path),
                        'target': match.group(1),
                        'type': 'generic_import',
                        'line': content[:match.start()].count('\n') + 1
                    })
            
        except Exception as e:
            logger.error(f"Error extracting dependencies: {e}")
        
        return dependencies
    
    def get_comment_patterns(self) -> Dict[str, str]:
        return self.comment_patterns
    
    def _detect_comment_style(self, lines: List[str]) -> Optional[str]:
        """Detect the most likely comment character."""
        comment_counts = {}
        
        for char, pattern in self.comment_patterns.items():
            count = sum(1 for line in lines if re.search(pattern, line))
            if count > 0:
                comment_counts[char] = count
        
        if comment_counts:
            return max(comment_counts.items(), key=lambda x: x[1])[0]
        return None
    
    def _count_comments(self, lines: List[str], comment_char: str) -> int:
        """Count comment lines using detected style."""
        if comment_char not in self.comment_patterns:
            return 0
        
        pattern = self.comment_patterns[comment_char]
        return sum(1 for line in lines if re.search(pattern, line.strip()))
    
    def _detect_language(self, file_path: Path) -> str:
        """Try to detect language from file extension."""
        ext_to_lang = {
            '.java': 'Java',
            '.go': 'Go',
            '.rs': 'Rust',
            '.rb': 'Ruby',
            '.php': 'PHP',
            '.swift': 'Swift',
            '.kt': 'Kotlin',
            '.scala': 'Scala',
            '.r': 'R',
            '.m': 'Objective-C',
            '.pl': 'Perl',
            '.lua': 'Lua',
            '.jl': 'Julia',
            '.cpp': 'C++',
            '.c': 'C',
            '.h': 'C/C++ Header',
            '.cs': 'C#',
            '.vb': 'Visual Basic',
            '.sql': 'SQL',
            '.sh': 'Shell',
            '.bat': 'Batch',
            '.ps1': 'PowerShell'
        }
        
        return ext_to_lang.get(file_path.suffix.lower(), 'Unknown')