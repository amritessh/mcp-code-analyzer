# src/analyzers/security.py
import re
import ast
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

import bandit
from bandit.core import manager
from bandit.core import config

from ..utils.logger import logger
from ..config import settings
from ..models.security import SecurityIssue, Severity, SecurityRule

class SecurityAnalyzer:
    """Analyze code for security vulnerabilities."""
    
    def __init__(self):
        self.rules = self._load_security_rules()
        self.bandit_manager = self._init_bandit()
        
    def _load_security_rules(self) -> Dict[str, SecurityRule]:
        """Load security detection rules."""
        rules = {
            # Hardcoded secrets
            'hardcoded_password': SecurityRule(
                id='SEC001',
                name='Hardcoded Password',
                pattern=r'(?i)(password|passwd|pwd)\s*=\s*["\'](?!.*\{)(?!.*\$).+["\']',
                severity=Severity.HIGH,
                message='Hardcoded password detected. Use environment variables.',
                cwe='CWE-798'
            ),
            'api_key': SecurityRule(
                id='SEC002',
                name='Hardcoded API Key',
                pattern=r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*=\s*["\'][\w\-]{20,}["\']',
                severity=Severity.HIGH,
                message='Hardcoded API key detected. Store in secure configuration.',
                cwe='CWE-798'
            ),
            'aws_credentials': SecurityRule(
                id='SEC003',
                name='AWS Credentials',
                pattern=r'(?i)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)\s*=\s*["\'].+["\']',
                severity=Severity.CRITICAL,
                message='AWS credentials exposed. Use IAM roles or secure storage.',
                cwe='CWE-798'
            ),
            
            # SQL Injection
            'sql_injection_concat': SecurityRule(
                id='SEC004',
                name='SQL Injection via String Concatenation',
                pattern=r'(?i)(execute|query)\s*\(\s*["\'].*["\'].*\+.*\)',
                severity=Severity.HIGH,
                message='Potential SQL injection via string concatenation.',
                cwe='CWE-89'
            ),
            'sql_injection_format': SecurityRule(
                id='SEC005',
                name='SQL Injection via String Formatting',
                pattern=r'(?i)(execute|query)\s*\(\s*["\'].*%[s|d].*["\'].*%',
                severity=Severity.HIGH,
                message='Potential SQL injection via string formatting.',
                cwe='CWE-89'
            ),
            
            # Command Injection
            'command_injection': SecurityRule(
                id='SEC006',
                name='Command Injection',
                pattern=r'(?i)(os\.system|subprocess\.call|subprocess\.run)\s*\([^)]*\+[^)]*\)',
                severity=Severity.CRITICAL,
                message='Potential command injection vulnerability.',
                cwe='CWE-78'
            ),
            
            # Path Traversal
            'path_traversal': SecurityRule(
                id='SEC007',
                name='Path Traversal',
                pattern=r'(?i)(open|file)\s*\([^)]*\.\.[/\\][^)]*\)',
                severity=Severity.HIGH,
                message='Potential path traversal vulnerability.',
                cwe='CWE-22'
            ),
            
            # Weak Cryptography
            'weak_hash_md5': SecurityRule(
                id='SEC008',
                name='Weak Hash Algorithm (MD5)',
                pattern=r'(?i)(hashlib\.md5|md5\.new)',
                severity=Severity.MEDIUM,
                message='MD5 is cryptographically weak. Use SHA-256 or stronger.',
                cwe='CWE-327'
            ),
            'weak_hash_sha1': SecurityRule(
                id='SEC009',
                name='Weak Hash Algorithm (SHA1)',
                pattern=r'(?i)(hashlib\.sha1|sha1\.new)',
                severity=Severity.MEDIUM,
                message='SHA1 is deprecated. Use SHA-256 or stronger.',
                cwe='CWE-327'
            ),
            
            # Insecure Random
            'insecure_random': SecurityRule(
                id='SEC010',
                name='Insecure Random Number Generator',
                pattern=r'(?i)random\.(random|randint|choice)\s*\(',
                severity=Severity.MEDIUM,
                message='Use secrets module for cryptographic randomness.',
                cwe='CWE-330'
            ),
            
            # Debug/Development Code
            'debug_enabled': SecurityRule(
                id='SEC011',
                name='Debug Mode Enabled',
                pattern=r'(?i)(debug\s*=\s*true|DEBUG\s*=\s*True)',
                severity=Severity.LOW,
                message='Debug mode should be disabled in production.',
                cwe='CWE-489'
            ),
            
            # Eval Usage
            'eval_usage': SecurityRule(
                id='SEC012',
                name='Use of eval()',
                pattern=r'(?i)eval\s*\(',
                severity=Severity.HIGH,
                message='eval() is dangerous and can lead to code injection.',
                cwe='CWE-95'
            ),
            
            # Private Key Detection
            'private_key': SecurityRule(
                id='SEC013',
                name='Private Key Exposed',
                pattern=r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
                severity=Severity.CRITICAL,
                message='Private key detected in source code.',
                cwe='CWE-798'
            ),
            
            # JWT Secret
            'jwt_secret': SecurityRule(
                id='SEC014',
                name='JWT Secret Hardcoded',
                pattern=r'(?i)(jwt[_-]?secret|secret[_-]?key)\s*=\s*["\'][^"\']+["\']',
                severity=Severity.HIGH,
                message='JWT secret should not be hardcoded.',
                cwe='CWE-798'
            )
        }
        
        return rules
    
    def _init_bandit(self) -> manager.BanditManager:
        """Initialize Bandit for Python-specific security scanning."""
        conf = config.BanditConfig()
        return manager.BanditManager(conf, 'file')
    
    async def scan_security(
        self,
        file_path: Path,
        custom_rules: List[str] = None,
        include_info: bool = False
    ) -> Dict[str, Any]:
        """Scan file for security issues."""
        logger.debug(f"Security scan for: {file_path}")
        
        issues = []
        
        # Read file content
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            return self._format_scan_results(file_path, [], error=str(e))
        
        # Pattern-based scanning
        pattern_issues = await self._scan_patterns(
            content, 
            lines, 
            file_path,
            custom_rules
        )
        issues.extend(pattern_issues)
        
        # Language-specific scanning
        if file_path.suffix == '.py':
            bandit_issues = await self._scan_python_security(file_path)
            issues.extend(bandit_issues)
        elif file_path.suffix in ['.js', '.ts']:
            js_issues = await self._scan_javascript_security(content, lines, file_path)
            issues.extend(js_issues)
        
        # Filter by severity
        if not include_info:
            issues = [i for i in issues if i.severity != Severity.INFO]
        
        # Sort by severity and line number
        issues.sort(key=lambda x: (x.severity.value, x.line_number))
        
        return self._format_scan_results(file_path, issues)
    
    async def _scan_patterns(
        self,
        content: str,
        lines: List[str],
        file_path: Path,
        custom_rules: Optional[List[str]] = None
    ) -> List[SecurityIssue]:
        """Scan using regex patterns."""
        issues = []
        
        # Select rules to apply
        rules_to_apply = self.rules
        if custom_rules:
            rules_to_apply = {
                k: v for k, v in self.rules.items() 
                if v.id in custom_rules
            }
        
        for rule_name, rule in rules_to_apply.items():
            matches = list(re.finditer(rule.pattern, content, re.MULTILINE))
            
            for match in matches:
                # Find line number
                line_start = content[:match.start()].count('\n') + 1
                
                # Get the actual line content
                line_content = lines[line_start - 1].strip() if line_start <= len(lines) else ""
                
                # Extract code snippet (3 lines context)
                snippet_start = max(0, line_start - 2)
                snippet_end = min(len(lines), line_start + 1)
                snippet = '\n'.join(lines[snippet_start:snippet_end])
                
                issue = SecurityIssue(
                    rule_id=rule.id,
                    severity=rule.severity,
                    message=rule.message,
                    file_path=str(file_path),
                    line_number=line_start,
                    column=match.start() - content.rfind('\n', 0, match.start()),
                    code_snippet=snippet,
                    cwe=rule.cwe,
                    confidence='HIGH'
                )
                
                issues.append(issue)
        
        return issues
    
    async def _scan_python_security(self, file_path: Path) -> List[SecurityIssue]:
        """Use Bandit for Python-specific security scanning."""
        issues = []
        
        try:
            # Run Bandit
            self.bandit_manager.discover_files([str(file_path)])
            self.bandit_manager.run_tests()
            
            # Convert Bandit results to our format
            for result in self.bandit_manager.get_issue_list():
                severity_map = {
                    'LOW': Severity.LOW,
                    'MEDIUM': Severity.MEDIUM,
                    'HIGH': Severity.HIGH
                }
                
                issue = SecurityIssue(
                    rule_id=f"BANDIT-{result.test_id}",
                    severity=severity_map.get(result.severity, Severity.MEDIUM),
                    message=result.text,
                    file_path=str(file_path),
                    line_number=result.lineno,
                    column=result.col_offset,
                    code_snippet=result.get_code(),
                    cwe=result.cwe.id if hasattr(result, 'cwe') else None,
                    confidence=result.confidence
                )
                
                issues.append(issue)
                
        except Exception as e:
            logger.error(f"Bandit scan error: {e}")
        
        return issues
    
    async def _scan_javascript_security(
        self, 
        content: str, 
        lines: List[str],
        file_path: Path
    ) -> List[SecurityIssue]:
        """JavaScript-specific security patterns."""
        js_rules = {
            'xss_innerhtml': SecurityRule(
                id='JS001',
                name='XSS via innerHTML',
                pattern=r'\.innerHTML\s*=\s*[^\'"`]+[\'"`]',
                severity=Severity.HIGH,
                message='Potential XSS via innerHTML. Use textContent or sanitize input.',
                cwe='CWE-79'
            ),
            'xss_document_write': SecurityRule(
                id='JS002',
                name='XSS via document.write',
                pattern=r'document\.write\s*\(',
                severity=Severity.HIGH,
                message='document.write can lead to XSS vulnerabilities.',
                cwe='CWE-79'
            ),
            'eval_js': SecurityRule(
                id='JS003',
                name='JavaScript eval() usage',
                pattern=r'(?<!\.)(eval|Function)\s*\(',
                severity=Severity.HIGH,
                message='eval() and Function() can execute arbitrary code.',
                cwe='CWE-95'
            )
        }
        
        issues = []
        for rule_name, rule in js_rules.items():
            matches = list(re.finditer(rule.pattern, content))
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                issue = SecurityIssue(
                    rule_id=rule.id,
                    severity=rule.severity,
                    message=rule.message,
                    file_path=str(file_path),
                    line_number=line_num,
                    column=match.start() - content.rfind('\n', 0, match.start()),
                    code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
                    cwe=rule.cwe,
                    confidence='MEDIUM'
                )
                issues.append(issue)
        
        return issues
    
    def _format_scan_results(
        self,
        file_path: Path,
        issues: List[SecurityIssue],
        error: Optional[str] = None
    ) -> Dict[str, Any]:
        """Format security scan results."""
        if error:
            return {
                'file_path': str(file_path),
                'scan_status': 'error',
                'error': error,
                'issues': []
            }
        
        # Group by severity
        severity_counts = {
            'critical': len([i for i in issues if i.severity == Severity.CRITICAL]),
            'high': len([i for i in issues if i.severity == Severity.HIGH]),
            'medium': len([i for i in issues if i.severity == Severity.MEDIUM]),
            'low': len([i for i in issues if i.severity == Severity.LOW]),
            'info': len([i for i in issues if i.severity == Severity.INFO])
        }
        
        return {
            'file_path': str(file_path),
            'scan_status': 'completed',
            'total_issues': len(issues),
            'severity_counts': severity_counts,
            'risk_score': self._calculate_risk_score(issues),
            'issues': [issue.to_dict() for issue in issues]
        }
    
    def _calculate_risk_score(self, issues: List[SecurityIssue]) -> int:
        """Calculate overall risk score (0-100)."""
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0
        }
        
        score = sum(weights[issue.severity] for issue in issues)
        return min(100, score)  # Cap at 100