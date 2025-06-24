# src/analyzers/sast_integration.py
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Optional
import subprocess
import json

from ..utils.logger import logger
from ..models.security import SecurityIssue, Severity

class SASTIntegration:
    """Integrate with external SAST tools."""
    
    def __init__(self):
        self.semgrep_available = self._check_tool_available('semgrep')
        self.codeql_available = self._check_tool_available('codeql')
        
    def _check_tool_available(self, tool_name: str) -> bool:
        """Check if external tool is available."""
        try:
            subprocess.run(
                [tool_name, '--version'],
                capture_output=True,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    async def run_semgrep(
        self,
        target_path: Path,
        rules: List[str] = None
    ) -> List[SecurityIssue]:
        """Run Semgrep security scanning."""
        if not self.semgrep_available:
            logger.warning("Semgrep not available")
            return []
        
        try:
            # Default to auto rules if none specified
            if not rules:
                rules = ['auto']
            
            cmd = [
                'semgrep',
                '--json',
                '--config=' + ','.join(rules),
                str(target_path)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"Semgrep error: {result.stderr}")
                return []
            
            # Parse results
            data = json.loads(result.stdout)
            issues = []
            
            for finding in data.get('results', []):
                severity = self._map_semgrep_severity(
                    finding.get('extra', {}).get('severity', 'WARNING')
                )
                
                issue = SecurityIssue(
                    rule_id=f"SEMGREP-{finding.get('check_id', 'UNKNOWN')}",
                    severity=severity,
                    message=finding.get('extra', {}).get('message', 'Security issue detected'),
                    file_path=finding.get('path', ''),
                    line_number=finding.get('start', {}).get('line', 0),
                    column=finding.get('start', {}).get('col', 0),
                    code_snippet=finding.get('extra', {}).get('lines', ''),
                    cwe=finding.get('extra', {}).get('cwe', None),
                    confidence='HIGH'
                )
                
                issues.append(issue)
            
            return issues
            
        except Exception as e:
            logger.error(f"Error running Semgrep: {e}")
            return []
    
    def _map_semgrep_severity(self, severity: str) -> Severity:
        """Map Semgrep severity to our severity levels."""
        mapping = {
            'ERROR': Severity.CRITICAL,
            'WARNING': Severity.HIGH,
            'INFO': Severity.MEDIUM,
            'INVENTORY': Severity.LOW
        }
        return mapping.get(severity.upper(), Severity.MEDIUM)