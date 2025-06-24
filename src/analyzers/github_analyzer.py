# src/analyzers/github_analyzer.py
import os
import tempfile
import shutil
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
import aiohttp
import git
from git import Repo
import base64
import json

from ..utils.logger import logger
from ..config import settings
from .project_analyzer import ProjectAnalyzer

class GitHubAnalyzer:
    """Analyze GitHub repositories without cloning."""
    
    def __init__(self, github_token: Optional[str] = None):
        self.github_token = github_token or os.getenv('GITHUB_TOKEN')
        self.api_base = "https://api.github.com"
        self.headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'MCP-Code-Analyzer'
        }
        if self.github_token:
            self.headers['Authorization'] = f'token {self.github_token}'
        
        self.project_analyzer = ProjectAnalyzer()
        self.temp_dir = Path(tempfile.gettempdir()) / "mcp_github_repos"
        self.temp_dir.mkdir(exist_ok=True)
    
    async def analyze_github_repo(
        self,
        repo_url: str,
        branch: str = "main",
        analysis_mode: str = "full",  # 'full', 'quick', 'files_only'
        config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Analyze a GitHub repository."""
        logger.info(f"Analyzing GitHub repository: {repo_url}")
        
        # Parse repository information
        repo_info = self._parse_github_url(repo_url)
        if not repo_info:
            raise ValueError(f"Invalid GitHub URL: {repo_url}")
        
        # Initialize results
        results = {
            'repository': {
                'url': repo_url,
                'owner': repo_info['owner'],
                'name': repo_info['repo'],
                'branch': branch,
                'analysis_mode': analysis_mode
            },
            'metadata': {},
            'analysis': {}
        }
        
        try:
            # Fetch repository metadata
            results['metadata'] = await self._fetch_repo_metadata(
                repo_info['owner'], 
                repo_info['repo']
            )
            
            if analysis_mode == 'quick':
                # Quick analysis using GitHub API only
                results['analysis'] = await self._quick_analysis(
                    repo_info['owner'],
                    repo_info['repo'],
                    branch
                )
            elif analysis_mode == 'files_only':
                # Analyze specific files without full clone
                results['analysis'] = await self._selective_analysis(
                    repo_info['owner'],
                    repo_info['repo'],
                    branch,
                    config
                )
            else:
                # Full analysis with clone
                results['analysis'] = await self._full_analysis(
                    repo_url,
                    branch,
                    config
                )
            
            # Add GitHub-specific insights
            results['insights'] = await self._generate_github_insights(
                results['metadata'],
                results['analysis']
            )
            
        except Exception as e:
            logger.error(f"Error analyzing GitHub repo: {e}")
            results['error'] = str(e)
        
        return results
    
    def _parse_github_url(self, url: str) -> Optional[Dict[str, str]]:
        """Parse GitHub URL to extract owner and repo."""
        # Handle different GitHub URL formats
        patterns = [
            r'github\.com[/:]([^/]+)/([^/\.]+)',
            r'github\.com/([^/]+)/([^/]+)\.git',
        ]
        
        import re
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return {
                    'owner': match.group(1),
                    'repo': match.group(2).replace('.git', '')
                }
        return None
    
    async def _fetch_repo_metadata(self, owner: str, repo: str) -> Dict[str, Any]:
        """Fetch repository metadata from GitHub API."""
        async with aiohttp.ClientSession() as session:
            # Repository info
            url = f"{self.api_base}/repos/{owner}/{repo}"
            async with session.get(url, headers=self.headers) as response:
                if response.status == 404:
                    raise ValueError(f"Repository not found: {owner}/{repo}")
                elif response.status == 403:
                    raise ValueError("GitHub API rate limit exceeded")
                
                repo_data = await response.json()
            
            # Languages
            lang_url = f"{self.api_base}/repos/{owner}/{repo}/languages"
            async with session.get(lang_url, headers=self.headers) as response:
                languages = await response.json() if response.status == 200 else {}
            
            # Contributors
            contrib_url = f"{self.api_base}/repos/{owner}/{repo}/contributors"
            async with session.get(contrib_url, headers=self.headers) as response:
                contributors = await response.json() if response.status == 200 else []
            
            # Recent commits
            commits_url = f"{self.api_base}/repos/{owner}/{repo}/commits"
            async with session.get(
                commits_url, 
                headers=self.headers,
                params={'per_page': 10}
            ) as response:
                recent_commits = await response.json() if response.status == 200 else []
            
            return {
                'name': repo_data['name'],
                'description': repo_data.get('description', ''),
                'stars': repo_data['stargazers_count'],
                'forks': repo_data['forks_count'],
                'open_issues': repo_data['open_issues_count'],
                'size_kb': repo_data['size'],
                'created_at': repo_data['created_at'],
                'updated_at': repo_data['updated_at'],
                'default_branch': repo_data['default_branch'],
                'languages': languages,
                'primary_language': repo_data.get('language', 'Unknown'),
                'contributors': len(contributors),
                'recent_commits': len(recent_commits),
                'license': repo_data.get('license', {}).get('name', 'None'),
                'topics': repo_data.get('topics', [])
            }
    
    async def _quick_analysis(
        self, 
        owner: str, 
        repo: str, 
        branch: str
    ) -> Dict[str, Any]:
        """Quick analysis using GitHub API without cloning."""
        logger.info("Performing quick analysis via GitHub API")
        
        analysis = {
            'mode': 'quick',
            'file_summary': {},
            'structure': {},
            'key_files': []
        }
        
        async with aiohttp.ClientSession() as session:
            # Get repository tree
            tree_url = f"{self.api_base}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
            async with session.get(tree_url, headers=self.headers) as response:
                if response.status != 200:
                    raise ValueError(f"Failed to fetch repository tree: {response.status}")
                
                tree_data = await response.json()
            
            # Analyze file structure
            files = [item for item in tree_data['tree'] if item['type'] == 'blob']
            
            # Count files by extension
            extension_counts = {}
            total_size = 0
            
            for file in files:
                path = Path(file['path'])
                ext = path.suffix.lower()
                
                if ext in settings.supported_extensions:
                    extension_counts[ext] = extension_counts.get(ext, 0) + 1
                
                total_size += file.get('size', 0)
                
                # Identify key files
                if path.name in ['README.md', 'setup.py', 'requirements.txt', 
                                'package.json', 'Dockerfile', '.gitignore']:
                    analysis['key_files'].append(str(path))
            
            analysis['file_summary'] = {
                'total_files': len(files),
                'total_size_bytes': total_size,
                'by_extension': extension_counts,
                'supported_files': sum(extension_counts.values())
            }
            
            # Analyze directory structure
            dirs = set()
            for file in files:
                parts = Path(file['path']).parts[:-1]
                for i in range(len(parts)):
                    dirs.add('/'.join(parts[:i+1]))
            
            analysis['structure'] = {
                'total_directories': len(dirs),
                'max_depth': max(len(Path(f['path']).parts) for f in files) if files else 0,
                'has_tests': any('test' in f['path'].lower() for f in files),
                'has_docs': any('doc' in f['path'].lower() for f in files),
                'has_ci': any('.github/workflows' in f['path'] or 
                             '.gitlab-ci' in f['path'] for f in files)
            }
            
            # Sample analysis of a few files
            sample_files = await self._analyze_sample_files(
                owner, 
                repo, 
                branch, 
                files[:10]  # Analyze first 10 files
            )
            analysis['sample_analysis'] = sample_files
        
        return analysis
    
    async def _analyze_sample_files(
        self,
        owner: str,
        repo: str,
        branch: str,
        files: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze a sample of files via API."""
        results = {
            'files_analyzed': 0,
            'total_loc': 0,
            'issues_found': 0,
            'complexity_samples': []
        }
        
        async with aiohttp.ClientSession() as session:
            for file in files:
                if Path(file['path']).suffix in ['.py', '.js', '.ts']:
                    # Fetch file content
                    content_url = f"{self.api_base}/repos/{owner}/{repo}/contents/{file['path']}?ref={branch}"
                    
                    async with session.get(content_url, headers=self.headers) as response:
                        if response.status == 200:
                            data = await response.json()
                            
                            # Decode content
                            content = base64.b64decode(data['content']).decode('utf-8')
                            lines = content.split('\n')
                            
                            results['files_analyzed'] += 1
                            results['total_loc'] += len([l for l in lines if l.strip()])
                            
                            # Basic complexity check
                            if file['path'].endswith('.py'):
                                complexity = self._estimate_python_complexity(content)
                                results['complexity_samples'].append({
                                    'file': file['path'],
                                    'complexity': complexity
                                })
        
        return results
    
    def _estimate_python_complexity(self, content: str) -> int:
        """Quick complexity estimation."""
        complexity_keywords = [
            'if ', 'elif ', 'else:', 'for ', 'while ',
            'try:', 'except:', 'finally:', 'with ',
            'and ', 'or ', 'not '
        ]
        
        complexity = 1
        for keyword in complexity_keywords:
            complexity += content.count(keyword)
        
        # Estimate per function
        function_count = content.count('def ') or 1
        return complexity // function_count
    
    async def _selective_analysis(
        self,
        owner: str,
        repo: str,
        branch: str,
        config: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze specific files without full clone."""
        logger.info("Performing selective file analysis")
        
        # Create temporary directory for files
        temp_analysis_dir = self.temp_dir / f"{owner}_{repo}_{branch}"
        temp_analysis_dir.mkdir(exist_ok=True)
        
        try:
            # Get list of files to analyze
            async with aiohttp.ClientSession() as session:
                tree_url = f"{self.api_base}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
                async with session.get(tree_url, headers=self.headers) as response:
                    tree_data = await response.json()
                
                # Filter files based on config
                files_to_analyze = []
                for item in tree_data['tree']:
                    if item['type'] == 'blob':
                        path = Path(item['path'])
                        if path.suffix in settings.supported_extensions:
                            # Apply exclusion patterns
                            if config and 'exclude_patterns' in config:
                                if any(path.match(pattern) for pattern in config['exclude_patterns']):
                                    continue
                            
                            files_to_analyze.append(item)
                
                # Download and analyze files
                logger.info(f"Analyzing {len(files_to_analyze)} files")
                
                downloaded_files = []
                for file_info in files_to_analyze[:100]:  # Limit to 100 files
                    file_path = await self._download_file(
                        owner,
                        repo,
                        branch,
                        file_info['path'],
                        temp_analysis_dir
                    )
                    if file_path:
                        downloaded_files.append(file_path)
                
                # Run analysis on downloaded files
                if downloaded_files:
                    # Use project analyzer on the temporary directory
                    analysis_result = await self.project_analyzer.analyze_project(
                        temp_analysis_dir,
                        config
                    )
                    
                    # Add download info
                    analysis_result['analysis_info'] = {
                        'mode': 'selective',
                        'files_analyzed': len(downloaded_files),
                        'total_available': len(files_to_analyze)
                    }
                    
                    return analysis_result
                else:
                    return {'error': 'No files downloaded for analysis'}
                    
        finally:
            # Cleanup
            if temp_analysis_dir.exists():
                shutil.rmtree(temp_analysis_dir)
    
    async def _download_file(
        self,
        owner: str,
        repo: str,
        branch: str,
        file_path: str,
        target_dir: Path
    ) -> Optional[Path]:
        """Download a single file from GitHub."""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_base}/repos/{owner}/{repo}/contents/{file_path}?ref={branch}"
                
                async with session.get(url, headers=self.headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Create file path
                        target_path = target_dir / file_path
                        target_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        # Decode and save content
                        content = base64.b64decode(data['content'])
                        target_path.write_bytes(content)
                        
                        return target_path
                    else:
                        logger.warning(f"Failed to download {file_path}: {response.status}")
                        return None
                        
        except Exception as e:
            logger.error(f"Error downloading file {file_path}: {e}")
            return None
    
    async def _full_analysis(
        self,
        repo_url: str,
        branch: str,
        config: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Full analysis with repository clone."""
        logger.info("Performing full analysis with repository clone")
        
        # Parse repo info
        repo_info = self._parse_github_url(repo_url)
        clone_dir = self.temp_dir / f"{repo_info['owner']}_{repo_info['repo']}"
        
        try:
            # Clone repository
            if clone_dir.exists():
                shutil.rmtree(clone_dir)
            
            logger.info(f"Cloning repository to {clone_dir}")
            
            # Use git to clone
            repo = Repo.clone_from(
                repo_url,
                clone_dir,
                branch=branch,
                depth=1  # Shallow clone for speed
            )
            
            # Run full project analysis
            analysis_result = await self.project_analyzer.analyze_project(
                clone_dir,
                config
            )
            
            # Add git-specific information
            analysis_result['git_info'] = self._extract_git_info(repo)
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error in full analysis: {e}")
            return {'error': str(e)}
            
        finally:
            # Cleanup
            if clone_dir.exists() and settings.cleanup_temp_repos:
                shutil.rmtree(clone_dir)
    
    def _extract_git_info(self, repo: Repo) -> Dict[str, Any]:
        """Extract git-specific information."""
        try:
            # Get recent commits
            commits = list(repo.iter_commits(max_count=20))
            
            # Analyze commit patterns
            commit_authors = {}
            commit_times = []
            
            for commit in commits:
                author = commit.author.name
                commit_authors[author] = commit_authors.get(author, 0) + 1
                commit_times.append(commit.committed_datetime)
            
            # Calculate metrics
            if commit_times:
                time_span = (commit_times[0] - commit_times[-1]).days
                commit_frequency = len(commits) / max(time_span, 1)
            else:
                commit_frequency = 0
            
            return {
                'recent_commits': len(commits),
                'active_contributors': len(commit_authors),
                'top_contributors': sorted(
                    commit_authors.items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )[:5],
                'commit_frequency_per_day': round(commit_frequency, 2),
                'branches': [b.name for b in repo.branches],
                'tags': [t.name for t in repo.tags]
            }
            
        except Exception as e:
            logger.error(f"Error extracting git info: {e}")
            return {}
    
    async def _generate_github_insights(
        self,
        metadata: Dict[str, Any],
        analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate GitHub-specific insights."""
        insights = {
            'health_indicators': {},
            'recommendations': [],
            'badges': []
        }
        
        # Repository health indicators
        health = insights['health_indicators']
        
        # Activity
        if metadata.get('recent_commits', 0) > 5:
            health['activity'] = 'active'
            insights['badges'].append('🟢 Active Development')
        else:
            health['activity'] = 'low'
            insights['recommendations'].append(
                "Low commit activity - project may be abandoned or stable"
            )
        
        # Community
        if metadata.get('stars', 0) > 100:
            health['popularity'] = 'high'
            insights['badges'].append('⭐ Popular Project')
        
        if metadata.get('contributors', 0) > 5:
            health['community'] = 'healthy'
            insights['badges'].append('👥 Active Community')
        
        # Code quality (from analysis)
        if 'summary' in analysis:
            quality_score = analysis['summary'].get('quality_score', 0)
            if quality_score > 80:
                insights['badges'].append('✅ High Quality')
            elif quality_score < 60:
                insights['recommendations'].append(
                    "Code quality needs improvement - consider refactoring"
                )
        
        # Documentation
        if 'key_files' in analysis and 'README.md' in analysis['key_files']:
            health['documentation'] = 'present'
        else:
            insights['recommendations'].append(
                "Add README.md for better documentation"
            )
        
        # Testing
        if analysis.get('structure', {}).get('has_tests'):
            health['testing'] = 'present'
            insights['badges'].append('🧪 Has Tests')
        else:
            insights['recommendations'].append(
                "No test directory found - consider adding tests"
            )
        
        # CI/CD
        if analysis.get('structure', {}).get('has_ci'):
            health['ci_cd'] = 'configured'
            insights['badges'].append('🔄 CI/CD Configured')
        
        # License
        if metadata.get('license') and metadata['license'] != 'None':
            health['license'] = 'present'
            insights['badges'].append('📄 Licensed')
        else:
            insights['recommendations'].append(
                "No license found - add a LICENSE file"
            )
        
        # Calculate overall health score
        health_score = sum([
            1 for indicator in health.values() 
            if indicator in ['active', 'high', 'healthy', 'present', 'configured']
        ]) / len(health) * 100 if health else 0
        
        insights['overall_health_score'] = round(health_score, 1)
        
        return insights


class GitHubURLHandler:
    """Handle various GitHub URL formats and extract information."""
    
    @staticmethod
    def parse_url(url: str) -> Dict[str, Any]:
        """Parse GitHub URL and extract components."""
        import re
        
        # Patterns for different GitHub URLs
        patterns = {
            'repo_https': r'https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$',
            'repo_ssh': r'git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$',
            'file_url': r'https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$',
            'dir_url': r'https://github\.com/([^/]+)/([^/]+)/tree/([^/]+)/(.+)$',
            'commit_url': r'https://github\.com/([^/]+)/([^/]+)/commit/([a-f0-9]+)$',
            'pr_url': r'https://github\.com/([^/]+)/([^/]+)/pull/(\d+)$',
        }
        
        for url_type, pattern in patterns.items():
            match = re.match(pattern, url)
            if match:
                if url_type in ['repo_https', 'repo_ssh']:
                    return {
                        'type': 'repository',
                        'owner': match.group(1),
                        'repo': match.group(2),
                        'url': url
                    }
                elif url_type == 'file_url':
                    return {
                        'type': 'file',
                        'owner': match.group(1),
                        'repo': match.group(2),
                        'branch': match.group(3),
                        'path': match.group(4),
                        'url': url
                    }
                elif url_type == 'dir_url':
                    return {
                        'type': 'directory',
                        'owner': match.group(1),
                        'repo': match.group(2),
                        'branch': match.group(3),
                        'path': match.group(4),
                        'url': url
                    }
                # Add more URL types as needed
        
        return {'type': 'unknown', 'url': url}
    
    @staticmethod
    def construct_api_url(parsed_info: Dict[str, Any]) -> str:
        """Construct GitHub API URL from parsed info."""
        base = "https://api.github.com"
        
        if parsed_info['type'] == 'repository':
            return f"{base}/repos/{parsed_info['owner']}/{parsed_info['repo']}"
        elif parsed_info['type'] == 'file':
            return f"{base}/repos/{parsed_info['owner']}/{parsed_info['repo']}/contents/{parsed_info['path']}"
        # Add more as needed
        
        return ""