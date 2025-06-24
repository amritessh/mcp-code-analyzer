# src/analyzers/github_security.py
import asyncio
import aiohttp
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from utils.logger import logger

class GitHubSecurityScanner:
    """Scan GitHub repositories for security issues."""
    
    def __init__(self, github_token: Optional[str] = None):
        self.github_token = github_token
        self.headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'MCP-Code-Analyzer'
        }
        if self.github_token:
            self.headers['Authorization'] = f'token {self.github_token}'
    
    async def scan_github_security(
        self,
        owner: str,
        repo: str
    ) -> Dict[str, Any]:
        """Scan repository for security vulnerabilities."""
        results = {
            'vulnerabilities': [],
            'security_advisories': [],
            'dependabot_alerts': [],
            'secret_scanning': [],
            'security_score': 100
        }
        
        async with aiohttp.ClientSession() as session:
            # Check for security advisories
            advisories = await self._get_security_advisories(
                session, 
                owner, 
                repo
            )
            results['security_advisories'] = advisories
            
            # Check for Dependabot alerts (requires auth)
            if self.github_token:
                alerts = await self._get_dependabot_alerts(
                    session,
                    owner,
                    repo
                )
                results['dependabot_alerts'] = alerts
                
                # Check secret scanning
                secrets = await self._get_secret_scanning_alerts(
                    session,
                    owner,
                    repo
                )
                results['secret_scanning'] = secrets
            
            # Check common security files
            security_files = await self._check_security_files(
                session,
                owner,
                repo
            )
            results['security_files'] = security_files
            
            # Calculate security score
            results['security_score'] = self._calculate_security_score(results)
            
            # Generate recommendations
            results['recommendations'] = self._generate_security_recommendations(
                results
            )
        
        return results
    
    async def _get_security_advisories(
        self,
        session: aiohttp.ClientSession,
        owner: str,
        repo: str
    ) -> List[Dict[str, Any]]:
        """Get repository security advisories."""
        try:
            # GitHub GraphQL API for security advisories
            query = """
            query($owner: String!, $repo: String!) {
                repository(owner: $owner, name: $repo) {
                    vulnerabilityAlerts(first: 100) {
                        nodes {
                            id
                            createdAt
                            dismissedAt
                            securityVulnerability {
                                severity
                                package {
                                    name
                                }
                                advisory {
                                    summary
                                    description
                                    cvss {
                                        score
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """
            
            url = "https://api.github.com/graphql"
            payload = {
                'query': query,
                'variables': {'owner': owner, 'repo': repo}
            }
            
            async with session.post(
                url, 
                json=payload, 
                headers=self.headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    alerts = data.get('data', {}).get('repository', {}).get(
                        'vulnerabilityAlerts', {}
                    ).get('nodes', [])
                    
                    return [
                        {
                            'severity': alert.get('securityVulnerability', {}).get('severity'),
                            'package': alert.get('securityVulnerability', {}).get('package', {}).get('name'),
                            'summary': alert.get('securityVulnerability', {}).get('advisory', {}).get('summary'),
                            'score': alert.get('securityVulnerability', {}).get('advisory', {}).get('cvss', {}).get('score')
                        }
                        for alert in alerts
                        if not alert.get('dismissedAt')
                    ]
                    
        except Exception as e:
            logger.error(f"Error fetching security advisories: {e}")
        
        return []
    
    async def _get_dependabot_alerts(
        self,
        session: aiohttp.ClientSession,
        owner: str,
        repo: str
    ) -> List[Dict[str, Any]]:
        """Get Dependabot vulnerability alerts."""
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/dependabot/alerts"
            
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    alerts = await response.json()
                    
                    return [
                        {
                            'state': alert['state'],
                            'severity': alert['security_advisory']['severity'],
                            'package': alert['security_vulnerability']['package']['name'],
                            'vulnerable_version': alert['security_vulnerability']['vulnerable_version_range'],
                            'description': alert['security_advisory']['description'],
                            'cve_id': alert['security_advisory'].get('cve_id')
                        }
                        for alert in alerts
                        if alert['state'] == 'open'
                    ]
                elif response.status == 404:
                    logger.info("Dependabot alerts not available for this repository")
                    
        except Exception as e:
            logger.error(f"Error fetching Dependabot alerts: {e}")
        
        return []
    
    async def _get_secret_scanning_alerts(
        self,
        session: aiohttp.ClientSession,
        owner: str,
        repo: str
    ) -> List[Dict[str, Any]]:
        """Get secret scanning alerts."""
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/secret-scanning/alerts"
            
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    alerts = await response.json()
                    
                    return [
                        {
                            'secret_type': alert['secret_type'],
                            'created_at': alert['created_at'],
                            'state': alert['state'],
                            'resolution': alert.get('resolution')
                        }
                        for alert in alerts
                        if alert['state'] == 'open'
                    ]
                    
        except Exception as e:
            logger.error(f"Error fetching secret scanning alerts: {e}")
        
        return []
    
    async def _check_security_files(
        self,
        session: aiohttp.ClientSession,
        owner: str,
        repo: str
    ) -> Dict[str, bool]:
        """Check for presence of security-related files."""
        security_files = {
            'SECURITY.md': False,
            '.github/SECURITY.md': False,
            '.github/dependabot.yml': False,
            '.github/workflows/codeql-analysis.yml': False,
            '.github/workflows/security.yml': False,
            '.snyk': False,
            '.gitignore': False
        }
        
        for file_path in security_files.keys():
            url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}"
            
            try:
                async with session.head(url, headers=self.headers) as response:
                    security_files[file_path] = response.status == 200
            except:
                pass
        
        return security_files
    
    def _calculate_security_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall security score."""
        score = 100.0
        
        # Deduct for vulnerabilities
        for advisory in results.get('security_advisories', []):
            severity = advisory.get('severity', 'LOW')
            if severity == 'CRITICAL':
                score -= 20
            elif severity == 'HIGH':
                score -= 15
            elif severity == 'MODERATE':
                score -= 10
            elif severity == 'LOW':
                score -= 5
        
        # Deduct for Dependabot alerts
        for alert in results.get('dependabot_alerts', []):
            severity = alert.get('severity', 'low')
            if severity == 'critical':
                score -= 15
            elif severity == 'high':
                score -= 10
            elif severity == 'moderate':
                score -= 5
            elif severity == 'low':
                score -= 2
        
        # Deduct for secret scanning
        score -= len(results.get('secret_scanning', [])) * 25
        
        # Bonus for security files
        security_files = results.get('security_files', {})
        if security_files.get('SECURITY.md') or security_files.get('.github/SECURITY.md'):
            score += 5
        if security_files.get('.github/dependabot.yml'):
            score += 5
        if any('codeql' in f for f in security_files if security_files[f]):
            score += 5
        
        return max(0, min(100, score))
    
    def _generate_security_recommendations(
        self,
        results: Dict[str, Any]
    ) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        # Check for vulnerabilities
        if results.get('security_advisories'):
            recommendations.append(
                f"🚨 Fix {len(results['security_advisories'])} security vulnerabilities"
            )
        
        if results.get('dependabot_alerts'):
            recommendations.append(
                f"🔧 Update {len(results['dependabot_alerts'])} vulnerable dependencies"
            )
        
        if results.get('secret_scanning'):
            recommendations.append(
                f"🔑 Remove {len(results['secret_scanning'])} exposed secrets immediately"
            )
        
        # Check for missing security files
        security_files = results.get('security_files', {})
        
        if not (security_files.get('SECURITY.md') or security_files.get('.github/SECURITY.md')):
            recommendations.append(
                "📄 Add SECURITY.md file with vulnerability disclosure policy"
            )
        
        if not security_files.get('.github/dependabot.yml'):
            recommendations.append(
                "🤖 Enable Dependabot for automated dependency updates"
            )
        
        if not any('codeql' in f for f in security_files if security_files.get(f)):
            recommendations.append(
                "🔍 Set up CodeQL analysis for automated security scanning"
            )
        
        if not security_files.get('.gitignore'):
            recommendations.append(
                "📝 Add .gitignore to prevent committing sensitive files"
            )
        
        return recommendations