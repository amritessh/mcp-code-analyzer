# src/analyzers/dependency_security.py
import asyncio
import aiohttp
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlparse
from utils.logger import logger
from models.security import Severity, SecurityIssue
import subprocess
import requests
import toml

class DependencyScanner:
    """Scan for vulnerable dependencies."""
    
    def __init__(self):
        self.vulnerability_db_url = "https://api.osv.dev/v1/query"
        
    async def scan_dependencies(self, project_path: Path) -> Dict[str, Any]:
        """Scan project dependencies for known vulnerabilities."""
        results = {
            'python': await self._scan_python_deps(project_path),
            'javascript': await self._scan_js_deps(project_path),
            'vulnerabilities': []
        }
        
        # Aggregate vulnerabilities
        for lang_result in results.values():
            if isinstance(lang_result, dict) and 'vulnerabilities' in lang_result:
                results['vulnerabilities'].extend(lang_result['vulnerabilities'])
        
        return results
    
    async def _scan_python_deps(self, project_path: Path) -> Dict[str, Any]:
        """Scan Python dependencies."""
        requirements_files = [
            'requirements.txt',
            'requirements.in',
            'Pipfile',
            'pyproject.toml',
            'setup.py'
        ]
        
        vulnerabilities = []
        
        for req_file in requirements_files:
            file_path = project_path / req_file
            if file_path.exists():
                if req_file == 'requirements.txt':
                    deps = self._parse_requirements_txt(file_path)
                elif req_file == 'Pipfile':
                    deps = self._parse_pipfile(file_path)
                elif req_file == 'pyproject.toml':
                    deps = self._parse_pyproject_toml(file_path)
                else:
                    continue
                
                # Check each dependency
                for dep_name, dep_version in deps.items():
                    vulns = await self._check_vulnerability(
                        'PyPI', 
                        dep_name, 
                        dep_version
                    )
                    vulnerabilities.extend(vulns)
        
        return {
            'language': 'Python',
            'vulnerabilities': vulnerabilities
        }
    
    async def _scan_js_deps(self, project_path: Path) -> Dict[str, Any]:
        """Scan JavaScript dependencies."""
        package_json = project_path / 'package.json'
        
        if not package_json.exists():
            return {'language': 'JavaScript', 'vulnerabilities': []}
        
        try:
            with open(package_json, 'r') as f:
                data = json.load(f)
            
            vulnerabilities = []
            
            # Check both dependencies and devDependencies
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in data:
                    for dep_name, dep_version in data[dep_type].items():
                        vulns = await self._check_vulnerability(
                            'npm',
                            dep_name,
                            dep_version
                        )
                        vulnerabilities.extend(vulns)
            
            return {
                'language': 'JavaScript',
                'vulnerabilities': vulnerabilities
            }
            
        except Exception as e:
            logger.error(f"Error scanning JS dependencies: {e}")
            return {'language': 'JavaScript', 'vulnerabilities': []}
    
    def _parse_requirements_txt(self, file_path: Path) -> Dict[str, str]:
        """Parse requirements.txt file."""
        deps = {}
        
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Handle different formats
                    if '==' in line:
                        name, version = line.split('==')
                        deps[name.strip()] = version.strip()
                    elif '>=' in line:
                        name, version = line.split('>=')
                        deps[name.strip()] = f">={version.strip()}"
                    else:
                        # No version specified
                        deps[line] = "*"
        
        return deps
    
    def _parse_pipfile(self, file_path: Path) -> Dict[str, str]:
        """Parse Pipfile."""
        try:
            with open(file_path, 'r') as f:
                data = toml.load(f)
            
            deps = {}
            if 'packages' in data:
                for name, spec in data['packages'].items():
                    if isinstance(spec, str):
                        deps[name] = spec
                    elif isinstance(spec, dict) and 'version' in spec:
                        deps[name] = spec['version']
            
            return deps
            
        except Exception as e:
            logger.error(f"Error parsing Pipfile: {e}")
            return {}
    
    def _parse_pyproject_toml(self, file_path: Path) -> Dict[str, str]:
        """Parse pyproject.toml."""
        try:
            with open(file_path, 'r') as f:
                data = toml.load(f)
            
            deps = {}
            
            # Poetry format
            if 'tool' in data and 'poetry' in data['tool']:
                if 'dependencies' in data['tool']['poetry']:
                    for name, spec in data['tool']['poetry']['dependencies'].items():
                        if name != 'python':  # Skip Python version
                            deps[name] = spec if isinstance(spec, str) else '*'
            
            # PEP 621 format
            elif 'project' in data and 'dependencies' in data['project']:
                for dep in data['project']['dependencies']:
                    if '==' in dep:
                        name, version = dep.split('==')
                        deps[name] = version
                    else:
                        deps[dep] = '*'
            
            return deps
            
        except Exception as e:
            logger.error(f"Error parsing pyproject.toml: {e}")
            return {}
    
    async def _check_vulnerability(
        self,
        ecosystem: str,
        package: str,
        version: str
    ) -> List[SecurityIssue]:
        """Check package for known vulnerabilities using OSV API."""
        try:
            # Clean version string
            version = version.strip().replace('==', '').replace('>=', '')
            if version == '*':
                return []
            
            # Query OSV database
            payload = {
                "package": {
                    "ecosystem": ecosystem,
                    "name": package
                },
                "version": version
            }
            
            response = requests.post(
                self.vulnerability_db_url,
                json=payload,
                timeout=5
            )
            
            if response.status_code != 200:
                return []
            
            data = response.json()
            vulnerabilities = []
            
            for vuln in data.get('vulns', []):
                severity = self._map_cvss_to_severity(
                    vuln.get('database_specific', {}).get('cvss_score', 5)
                )
                
                issue = SecurityIssue(
                    rule_id=vuln.get('id', 'UNKNOWN'),
                    severity=severity,
                    message=f"Vulnerable dependency: {package}=={version}",
                    file_path="dependencies",
                    line_number=0,
                    column=0,
                    code_snippet=f"{package}=={version}",
                    cwe=vuln.get('cwe_ids', [None])[0] if vuln.get('cwe_ids') else None,
                    confidence='HIGH'
                )
                
                vulnerabilities.append(issue)
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error checking vulnerability for {package}: {e}")
            return []
    
    def _map_cvss_to_severity(self, cvss_score: float) -> Severity:
        """Map CVSS score to severity level."""
        if cvss_score >= 9.0:
            return Severity.CRITICAL
        elif cvss_score >= 7.0:
            return Severity.HIGH
        elif cvss_score >= 4.0:
            return Severity.MEDIUM
        elif cvss_score >= 0.1:
            return Severity.LOW
        else:
            return Severity.INFO