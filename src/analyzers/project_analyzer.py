# src/analyzers/project_analyzer.py
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from datetime import datetime
import json
from collections import defaultdict, Counter

from ..utils.logger import logger
from ..config import settings
from .basic import BasicAnalyzer
from .complexity import ComplexityAnalyzer
from .security import SecurityAnalyzer
from .quality import QualityAnalyzer
from .dependencies import DependencyAnalyzer
from .todo_tracker import TodoTracker
from .dead_code import DeadCodeDetector
from ..storage.database import AnalysisDatabase
from ..utils.visualizer import DependencyVisualizer, TreemapVisualizer

class ProjectAnalyzer:
    """Comprehensive project-wide analysis."""
    
    def __init__(self):
        self.basic_analyzer = BasicAnalyzer()
        self.complexity_analyzer = ComplexityAnalyzer()
        self.security_analyzer = SecurityAnalyzer()
        self.quality_analyzer = QualityAnalyzer()
        self.dependency_analyzer = DependencyAnalyzer()
        self.todo_tracker = TodoTracker()
        self.dead_code_detector = DeadCodeDetector()
        self.database = AnalysisDatabase()
        self.visualizer = DependencyVisualizer()
        self.treemap_viz = TreemapVisualizer()
    
    async def analyze_project(
        self,
        project_path: Path,
        config: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """Perform comprehensive analysis of entire project."""
        logger.info(f"Starting project analysis: {project_path}")
        
        start_time = datetime.now()
        config = config or self._get_default_config()
        
        # Initialize results
        results = {
            'project_path': str(project_path),
            'started_at': start_time.isoformat(),
            'config': config,
            'summary': {},
            'files': {},
            'issues': [],
            'metrics': {},
            'dependencies': {},
            'visualizations': {}
        }
        
        try:
            # Step 1: Discover files
            files = await self._discover_files(project_path, config)
            total_files = len(files)
            results['summary']['total_files'] = total_files
            
            if progress_callback:
                progress_callback("Discovering files", 0, total_files)
            
            # Step 2: Analyze individual files
            file_results = await self._analyze_files(
                files, 
                config, 
                progress_callback
            )
            results['files'] = file_results
            
            # Step 3: Aggregate metrics
            results['metrics'] = await self._aggregate_metrics(file_results)
            
            # Step 4: Analyze dependencies
            if config.get('analyze_dependencies', True):
                results['dependencies'] = await self._analyze_project_dependencies(
                    project_path,
                    config
                )
            
            # Step 5: Find project-wide issues
            results['issues'] = await self._find_project_issues(
                file_results,
                results['dependencies']
            )
            
            # Step 6: Generate visualizations
            if config.get('generate_visualizations', True):
                results['visualizations'] = await self._generate_visualizations(
                    results,
                    project_path
                )
            
            # Step 7: Calculate scores
            results['summary'].update(self._calculate_project_scores(results))
            
            # Step 8: Generate recommendations
            results['recommendations'] = self._generate_project_recommendations(results)
            
            # Save to database
            await self._save_analysis_to_db(results)
            
        except Exception as e:
            logger.error(f"Project analysis failed: {e}")
            results['error'] = str(e)
        
        finally:
            end_time = datetime.now()
            results['completed_at'] = end_time.isoformat()
            results['duration'] = (end_time - start_time).total_seconds()
        
        return results
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default analysis configuration."""
        return {
            'file_extensions': settings.supported_extensions,
            'exclude_patterns': ['**/venv/**', '**/__pycache__/**', '**/node_modules/**'],
            'max_file_size': settings.max_file_size,
            'analyze_security': True,
            'analyze_quality': True,
            'analyze_complexity': True,
            'analyze_dependencies': True,
            'find_todos': True,
            'detect_dead_code': True,
            'generate_visualizations': True,
            'parallel_workers': 4
        }
    
    async def _discover_files(
        self,
        project_path: Path,
        config: Dict[str, Any]
    ) -> List[Path]:
        """Discover all files to analyze."""
        files = []
        exclude_patterns = config.get('exclude_patterns', [])
        
        for ext in config.get('file_extensions', ['.py']):
            for file_path in project_path.rglob(f'*{ext}'):
                # Check exclusions
                if any(file_path.match(pattern) for pattern in exclude_patterns):
                    continue
                
                # Check file size
                if file_path.stat().st_size > config.get('max_file_size', 1048576):
                    logger.warning(f"Skipping large file: {file_path}")
                    continue
                
                files.append(file_path)
        
        logger.info(f"Discovered {len(files)} files for analysis")
        return files
    
    async def _analyze_files(
        self,
        files: List[Path],
        config: Dict[str, Any],
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Dict[str, Any]]:
        """Analyze individual files in parallel."""
        results = {}
        
        # Create worker pool
        semaphore = asyncio.Semaphore(config.get('parallel_workers', 4))
        
        async def analyze_file_with_semaphore(file_path: Path, index: int):
            async with semaphore:
                if progress_callback:
                    progress_callback(f"Analyzing {file_path.name}", index, len(files))
                
                try:
                    file_result = await self._analyze_single_file(file_path, config)
                    results[str(file_path)] = file_result
                except Exception as e:
                    logger.error(f"Error analyzing {file_path}: {e}")
                    results[str(file_path)] = {'error': str(e)}
        
        # Analyze files in parallel
        tasks = [
            analyze_file_with_semaphore(file_path, i)
            for i, file_path in enumerate(files)
        ]
        
        await asyncio.gather(*tasks)
        
        return results
    
    async def _analyze_single_file(
        self,
        file_path: Path,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze a single file with all analyzers."""
        result = {
            'file_path': str(file_path),
            'analyses': {}
        }
        
        # Basic analysis
        try:
            basic = await self.basic_analyzer.analyze_basic(file_path)
            result['analyses']['basic'] = basic
        except Exception as e:
            logger.error(f"Basic analysis failed for {file_path}: {e}")
        
        # Language-specific analyses
        if file_path.suffix == '.py':
            # Complexity
            if config.get('analyze_complexity', True):
                try:
                    complexity = await self.complexity_analyzer.analyze_complexity(
                        file_path,
                        include_details=True
                    )
                    result['analyses']['complexity'] = complexity
                except Exception as e:
                    logger.error(f"Complexity analysis failed for {file_path}: {e}")
            
            # Security
            if config.get('analyze_security', True):
                try:
                    security = await self.security_analyzer.scan_security(file_path)
                    result['analyses']['security'] = security
                except Exception as e:
                    logger.error(f"Security analysis failed for {file_path}: {e}")
            
            # Quality
            if config.get('analyze_quality', True):
                try:
                    quality = await self.quality_analyzer.check_quality(file_path)
                    result['analyses']['quality'] = quality
                except Exception as e:
                    logger.error(f"Quality analysis failed for {file_path}: {e}")
            
            # Dead code
            if config.get('detect_dead_code', True):
                try:
                    dead_code = await self.dead_code_detector.detect_dead_code(file_path)
                    result['analyses']['dead_code'] = dead_code
                except Exception as e:
                    logger.error(f"Dead code detection failed for {file_path}: {e}")
        
        return result
    
    async def _analyze_project_dependencies(
        self,
        project_path: Path,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze project-wide dependencies."""
        return await self.dependency_analyzer.analyze_dependencies(
            project_path,
            depth=config.get('dependency_depth', 3),
            include_external=True,
            include_stdlib=False
        )
    
    async def _aggregate_metrics(
        self,
        file_results: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Aggregate metrics across all files."""
        metrics = {
            'totals': {
                'files': len(file_results),
                'loc': 0,
                'functions': 0,
                'classes': 0,
                'complexity_total': 0,
                'issues_total': 0
            },
            'averages': {},
            'distributions': defaultdict(list),
            'by_language': defaultdict(lambda: defaultdict(int))
        }
        
        complexity_values = []
        quality_scores = []
        
        for file_path, file_data in file_results.items():
            if 'error' in file_data:
                continue
            
            analyses = file_data.get('analyses', {})
            
            # Basic metrics
            if 'basic' in analyses:
                basic = analyses['basic']
                language = basic.get('language', 'Unknown')
                
                metrics['totals']['loc'] += basic.get('metrics', {}).get('loc', 0)
                metrics['totals']['functions'] += basic.get('metrics', {}).get('functions', 0)
                metrics['totals']['classes'] += basic.get('metrics', {}).get('classes', 0)
                
                metrics['by_language'][language]['files'] += 1
                metrics['by_language'][language]['loc'] += basic.get('metrics', {}).get('loc', 0)
            
            # Complexity metrics
            if 'complexity' in analyses:
                complexity = analyses['complexity']
                avg_complexity = complexity.get('average_complexity', 0)
                complexity_values.append(avg_complexity)
                metrics['totals']['complexity_total'] += complexity.get('total_complexity', 0)
                metrics['distributions']['complexity'].append(avg_complexity)
            
            # Quality metrics
            if 'quality' in analyses:
                quality = analyses['quality']
                score = quality.get('quality_score', 0)
                quality_scores.append(score)
                metrics['distributions']['quality'].append(score)
                metrics['totals']['issues_total'] += quality.get('total_issues', 0)
            
            # Security issues
            if 'security' in analyses:
                security = analyses['security']
                metrics['totals']['issues_total'] += security.get('total_issues', 0)
        
        # Calculate averages
        if complexity_values:
            metrics['averages']['complexity'] = sum(complexity_values) / len(complexity_values)
        
        if quality_scores:
            metrics['averages']['quality'] = sum(quality_scores) / len(quality_scores)
        
        if metrics['totals']['files'] > 0:
            metrics['averages']['loc_per_file'] = (
                metrics['totals']['loc'] / metrics['totals']['files']
            )
        
        return metrics
    
    async def _find_project_issues(
        self,
        file_results: Dict[str, Dict[str, Any]],
        dependencies: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find and prioritize project-wide issues."""
        all_issues = []
        
        # Collect issues from file analyses
        for file_path, file_data in file_results.items():
            if 'error' in file_data:
                continue
            
            analyses = file_data.get('analyses', {})
            
            # Security issues
            if 'security' in analyses:
                for issue in analyses['security'].get('issues', []):
                    issue['file'] = file_path
                    issue['category'] = 'security'
                    all_issues.append(issue)
            
            # Quality issues
            if 'quality' in analyses:
                for issue in analyses['quality'].get('issues', []):
                    issue['file'] = file_path
                    issue['category'] = 'quality'
                    all_issues.append(issue)
            
            # Complexity issues
            if 'complexity' in analyses:
                complexity = analyses['complexity']
                if complexity.get('average_complexity', 0) > 10:
                    all_issues.append({
                        'file': file_path,
                        'category': 'complexity',
                        'severity': 'HIGH' if complexity['average_complexity'] > 20 else 'MEDIUM',
                        'message': f"High average complexity: {complexity['average_complexity']:.1f}",
                        'location': {'file': file_path, 'line': 0}
                    })
        
        # Dependency issues
        if dependencies:
            # Circular dependencies
            for cycle in dependencies.get('metrics', {}).get('circular_dependencies', []):
                all_issues.append({
                    'category': 'dependency',
                    'severity': 'HIGH',
                    'message': f"Circular dependency: {' → '.join(cycle[:3])}...",
                    'modules': cycle
                })
            
            # God modules
            for god_module in dependencies.get('patterns', {}).get('god_modules', []):
                all_issues.append({
                    'category': 'dependency',
                    'severity': 'MEDIUM',
                    'message': f"God module with {god_module['outgoing_dependencies']} dependencies",
                    'file': god_module['module']
                })
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        all_issues.sort(key=lambda x: severity_order.get(x.get('severity', 'INFO'), 5))
        
        return all_issues
    
    async def _generate_visualizations(
        self,
        results: Dict[str, Any],
        project_path: Path
    ) -> Dict[str, str]:
        """Generate all visualizations."""
        visualizations = {}
        
        # Dependency graph
        if 'dependencies' in results and results['dependencies'].get('visualization'):
            viz_data = results['dependencies']['visualization']
            
            # Mermaid diagram
            visualizations['dependency_graph_mermaid'] = self.visualizer.generate_dependency_graph(
                viz_data,
                output_format='mermaid',
                highlight_cycles=True
            )
            
            # D3 data
            visualizations['dependency_graph_d3'] = self.visualizer.generate_dependency_graph(
                viz_data,
                output_format='d3'
            )
        
        # Complexity treemap
        file_metrics = {}
        for file_path, file_data in results['files'].items():
            if 'analyses' in file_data and 'complexity' in file_data['analyses']:
                complexity = file_data['analyses']['complexity']
                basic = file_data['analyses'].get('basic', {})
                
                file_metrics[file_path] = {
                    'complexity': complexity.get('average_complexity', 0),
                    'loc': basic.get('metrics', {}).get('loc', 0)
                }
        
        if file_metrics:
            treemap_html = self.treemap_viz.generate_complexity_treemap(file_metrics)
            visualizations['complexity_treemap'] = treemap_html
        
        # Dashboard
        dashboard_data = self._prepare_dashboard_data(results)
        visualizations['dashboard_html'] = self.visualizer.generate_metrics_dashboard(
            dashboard_data,
            output_format='html'
        )
        visualizations['dashboard_markdown'] = self.visualizer.generate_metrics_dashboard(
            dashboard_data,
            output_format='markdown'
        )
        
        return visualizations
    
    def _prepare_dashboard_data(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for dashboard visualization."""
        # Count issues by type
        issue_counts = Counter()
        severity_counts = Counter()
        
        for issue in results.get('issues', []):
            issue_counts[issue.get('category', 'unknown')] += 1
            severity_counts[issue.get('severity', 'unknown')] += 1
        
        # Get top complex files
        complex_files = []
        for file_path, file_data in results['files'].items():
            if 'analyses' in file_data and 'complexity' in file_data['analyses']:
                complexity = file_data['analyses']['complexity'].get('average_complexity', 0)
                complex_files.append({
                    'file': Path(file_path).name,
                    'complexity': complexity
                })
        
        complex_files.sort(key=lambda x: x['complexity'], reverse=True)
        
        return {
            'timestamp': results.get('completed_at', 'N/A'),
            'total_files': results['summary'].get('total_files', 0),
            'total_issues': len(results.get('issues', [])),
            'average_complexity': results['metrics'].get('averages', {}).get('complexity', 0),
            'code_quality_score': results['summary'].get('quality_score', 0),
            'security_score': results['summary'].get('security_score', 0),
            'critical_issues': severity_counts.get('CRITICAL', 0),
            'high_issues': severity_counts.get('HIGH', 0),
            'medium_issues': severity_counts.get('MEDIUM', 0),
            'low_issues': severity_counts.get('LOW', 0),
            'security_issues': issue_counts.get('security', 0),
            'quality_issues': issue_counts.get('quality', 0),
            'complexity_issues': issue_counts.get('complexity', 0),
            'dead_code_issues': issue_counts.get('dead_code', 0),
            'complex_files': complex_files[:10],
            'circular_dependencies': results.get('dependencies', {}).get('metrics', {}).get('circular_dependencies', []),
            'recommendations': results.get('recommendations', []),
            'file_complexities': {
                f: d['analyses']['complexity']['average_complexity']
                for f, d in results['files'].items()
                if 'analyses' in d and 'complexity' in d['analyses']
            },
            'top_issues': [
                {
                    'file': Path(issue.get('file', 'unknown')).name,
                    'message': issue.get('message', 'No message'),
                    'severity': issue.get('severity', 'UNKNOWN'),
                    'line': issue.get('location', {}).get('line', 0)
                }
                for issue in results.get('issues', [])[:10]
            ]
        }
    
    def _calculate_project_scores(self, results: Dict[str, Any]) -> Dict[str, float]:
        """Calculate overall project scores."""
        scores = {}
        
        # Security score (0-100)
        security_issues = [i for i in results['issues'] if i.get('category') == 'security']
        critical_security = sum(1 for i in security_issues if i.get('severity') == 'CRITICAL')
        high_security = sum(1 for i in security_issues if i.get('severity') == 'HIGH')
        
        security_penalty = (critical_security * 20) + (high_security * 10)
        scores['security_score'] = max(0, 100 - security_penalty)
        
        # Quality score (0-100)
        avg_quality = results['metrics'].get('averages', {}).get('quality', 75)
        scores['quality_score'] = avg_quality
        
        # Complexity score (0-100)
        avg_complexity = results['metrics'].get('averages', {}).get('complexity', 0)
        if avg_complexity <= 5:
            complexity_score = 100
        elif avg_complexity <= 10:
            complexity_score = 90 - (avg_complexity - 5) * 4
        elif avg_complexity <= 20:
            complexity_score = 70 - (avg_complexity - 10) * 3
        else:
            complexity_score = max(0, 40 - (avg_complexity - 20))
        
        scores['complexity_score'] = complexity_score
        
        # Maintainability score (combination)
        scores['maintainability_score'] = (
            scores['quality_score'] * 0.4 +
            scores['complexity_score'] * 0.4 +
            scores['security_score'] * 0.2
        )
        
        # Overall health score
        scores['overall_health'] = (
            scores['security_score'] * 0.3 +
            scores['quality_score'] * 0.3 +
            scores['complexity_score'] * 0.2 +
            scores['maintainability_score'] * 0.2
        )
        
        return scores
    
    def _generate_project_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        # Security recommendations
        security_issues = [i for i in results['issues'] if i.get('category') == 'security']
        if len(security_issues) > 10:
            recommendations.append(
                f"🔒 HIGH PRIORITY: Fix {len(security_issues)} security vulnerabilities. "
                "Focus on CRITICAL and HIGH severity issues first."
            )
        
        # Complexity recommendations
        avg_complexity = results['metrics'].get('averages', {}).get('complexity', 0)
        if avg_complexity > 15:
            recommendations.append(
                f"🧮 Reduce code complexity (current avg: {avg_complexity:.1f}). "
                "Break down complex functions and apply SOLID principles."
            )
        
        # Circular dependencies
        circular_deps = results.get('dependencies', {}).get('metrics', {}).get('circular_dependencies', [])
        if circular_deps:
            recommendations.append(
                f"🔄 Resolve {len(circular_deps)} circular dependencies. "
                "Consider using dependency injection or interfaces."
            )
        
        # Dead code
        dead_code_count = sum(
            1 for f in results['files'].values()
            if 'analyses' in f and 'dead_code' in f['analyses'] 
            and f['analyses']['dead_code'].get('total_dead_code', 0) > 0
        )
        if dead_code_count > 5:
            recommendations.append(
                f"🧹 Remove dead code from {dead_code_count} files. "
                "This will improve maintainability and reduce confusion."
            )
        
        # Documentation
        avg_quality = results['metrics'].get('averages', {}).get('quality', 0)
        if avg_quality < 70:
            recommendations.append(
                "📝 Improve code documentation. Add docstrings to public functions and classes."
            )
        
        # Testing
        test_file_count = sum(
            1 for f in results['files'].keys()
            if 'test' in f.lower()
        )
        total_files = results['summary'].get('total_files', 1)
        test_ratio = test_file_count / total_files if total_files > 0 else 0
        
        if test_ratio < 0.2:
            recommendations.append(
                "🧪 Increase test coverage. Aim for at least one test file per module."
            )
        
        # Architecture
        god_modules = results.get('dependencies', {}).get('patterns', {}).get('god_modules', [])
        if god_modules:
            recommendations.append(
                f"🏗️ Refactor {len(god_modules)} god modules. "
                "Split responsibilities and reduce coupling."
            )
        
        return recommendations
    
    async def _save_analysis_to_db(self, results: Dict[str, Any]) -> None:
        """Save analysis results to database."""
        try:
            # Save analysis history using the correct database pattern
            async with self.database.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO analysis_history
                    (project_path, analysis_type, total_files, total_issues, 
                     duration_seconds, started_at, summary)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    results['project_path'],
                    'comprehensive',
                    results['summary'].get('total_files', 0),
                    len(results.get('issues', [])),
                    results.get('duration', 0),
                    results.get('started_at'),
                    json.dumps(results['summary'])
                ))
                conn.commit()
            
            logger.info("Analysis results saved to database")
            
        except Exception as e:
            logger.warning(f"Failed to save analysis to database (continuing without database save): {e}")
            # Don't fail the entire analysis if database save fails


class AnalysisReportGenerator:
    """Generate comprehensive analysis reports."""
    
    def __init__(self):
        self.templates = self._load_templates()
    
    def _load_templates(self) -> Dict[str, str]:
        """Load report templates."""
        return {
            'executive_summary': """
# Executive Summary

**Project:** {project_name}  
**Analysis Date:** {date}  
**Overall Health Score:** {overall_health:.1f}/100

## Key Findings

- **Files Analyzed:** {total_files}
- **Total Issues:** {total_issues}
- **Critical Issues:** {critical_issues}
- **Average Complexity:** {avg_complexity:.1f}

## Risk Assessment

{risk_assessment}

## Top Recommendations

{top_recommendations}
""",
            'detailed_report': """
# Comprehensive Code Analysis Report

{executive_summary}

## Detailed Analysis

### Security Analysis
{security_section}

### Code Quality
{quality_section}

### Complexity Analysis
{complexity_section}

### Dependencies
{dependencies_section}

### Technical Debt
{debt_section}

## Appendices

### A. File-by-File Analysis
{file_analysis}

### B. Visualizations
{visualizations}
"""
        }
    
    def generate_report(
        self,
        analysis_results: Dict[str, Any],
        report_type: str = 'detailed',
        output_format: str = 'markdown'
    ) -> str:
        """Generate analysis report."""
        
        if report_type == 'executive':
            return self._generate_executive_summary(analysis_results)
        elif report_type == 'detailed':
            return self._generate_detailed_report(analysis_results)
        else:
            raise ValueError(f"Unknown report type: {report_type}")
    
    def _generate_executive_summary(self, results: Dict[str, Any]) -> str:
        """Generate executive summary."""
        project_name = Path(results['project_path']).name
        
        # Risk assessment
        risk_level = self._assess_risk_level(results)
        risk_assessment = self._format_risk_assessment(risk_level, results)
        
        # Top recommendations
        top_recs = results.get('recommendations', [])[:3]
        top_recommendations = '\n'.join(f"{i+1}. {rec}" for i, rec in enumerate(top_recs))
        
        return self.templates['executive_summary'].format(
            project_name=project_name,
            date=results.get('completed_at', 'N/A'),
            overall_health=results['summary'].get('overall_health', 0),
            total_files=results['summary'].get('total_files', 0),
            total_issues=len(results.get('issues', [])),
            critical_issues=sum(
                1 for i in results.get('issues', []) 
                if i.get('severity') == 'CRITICAL'
            ),
            avg_complexity=results['metrics'].get('averages', {}).get('complexity', 0),
            risk_assessment=risk_assessment,
            top_recommendations=top_recommendations
        )
    
    def _generate_detailed_report(self, results: Dict[str, Any]) -> str:
        """Generate detailed report."""
        sections = {
            'executive_summary': self._generate_executive_summary(results),
            'security_section': self._generate_security_section(results),
            'quality_section': self._generate_quality_section(results),
            'complexity_section': self._generate_complexity_section(results),
            'dependencies_section': self._generate_dependencies_section(results),
            'debt_section': self._generate_debt_section(results),
            'file_analysis': self._generate_file_analysis_section(results),
            'visualizations': self._generate_visualizations_section(results)
        }
        
        return self.templates['detailed_report'].format(**sections)
    
    def _assess_risk_level(self, results: Dict[str, Any]) -> str:
        """Assess overall project risk level."""
        health_score = results['summary'].get('overall_health', 0)
        
        if health_score >= 80:
            return "LOW"
        elif health_score >= 60:
            return "MEDIUM"
        elif health_score >= 40:
            return "HIGH"
        else:
            return "CRITICAL"
    
    def _format_risk_assessment(self, risk_level: str, results: Dict[str, Any]) -> str:
        """Format risk assessment section."""
        assessments = {
            "LOW": "The project is in good health with minimal risks.",
            "MEDIUM": "The project has moderate risks that should be addressed.",
            "HIGH": "The project has significant risks requiring immediate attention.",
            "CRITICAL": "The project has critical issues that pose serious risks."
        }
        
        base_assessment = assessments[risk_level]
        
        # Add specific risks
        risks = []
        
        security_score = results['summary'].get('security_score', 100)
        if security_score < 60:
            risks.append("- **Security vulnerabilities** pose a significant risk")
        
        avg_complexity = results['metrics'].get('averages', {}).get('complexity', 0)
        if avg_complexity > 15:
            risks.append("- **High code complexity** makes maintenance difficult")
        
        circular_deps = results.get('dependencies', {}).get('metrics', {}).get('circular_dependencies', [])
        if len(circular_deps) > 5:
            risks.append("- **Circular dependencies** create architectural risks")
        
        if risks:
            return f"{base_assessment}\n\n**Key Risk Areas:**\n" + "\n".join(risks)
        else:
            return base_assessment
    
    def _generate_security_section(self, results: Dict[str, Any]) -> str:
        """Generate security analysis section."""
        security_issues = [
            i for i in results.get('issues', []) 
            if i.get('category') == 'security'
        ]
        
        if not security_issues:
            return "No security vulnerabilities detected. ✅"
        
        # Group by severity
        by_severity = defaultdict(list)
        for issue in security_issues:
            by_severity[issue.get('severity', 'UNKNOWN')].append(issue)
        
        section = f"Found **{len(security_issues)}** security vulnerabilities:\n\n"
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in by_severity:
                section += f"### {severity} Severity ({len(by_severity[severity])} issues)\n\n"
                for issue in by_severity[severity][:5]:  # Top 5
                    section += f"- **{issue.get('rule_id', 'N/A')}**: {issue.get('message', 'No message')}\n"
                    section += f"  - File: `{Path(issue.get('file', 'unknown')).name}`\n"
                    section += f"  - Line: {issue.get('location', {}).get('line', 'N/A')}\n\n"
                
                if len(by_severity[severity]) > 5:
                    section += f"  *...and {len(by_severity[severity]) - 5} more*\n\n"
        
        return section
    
    def _generate_quality_section(self, results: Dict[str, Any]) -> str:
        """Generate quality analysis section."""
        avg_quality = results['metrics'].get('averages', {}).get('quality', 0)
        quality_issues = [
            i for i in results.get('issues', []) 
            if i.get('category') == 'quality'
        ]
        
        section = f"""
**Average Quality Score:** {avg_quality:.1f}/100  
**Quality Issues:** {len(quality_issues)}

### Quality Metrics

| Metric | Value |
|--------|-------|
| Documentation Coverage | {self._get_doc_coverage(results):.1f}% |
| Average Function Length | {self._get_avg_function_length(results):.1f} lines |
| Code Duplication | {self._get_duplication_percentage(results):.1f}% |
"""
        
        if quality_issues:
            section += "\n### Top Quality Issues\n\n"
            for issue in quality_issues[:5]:
                section += f"- {issue.get('message', 'No message')} "
                section += f"(`{Path(issue.get('file', 'unknown')).name}`)\n"
        
        return section
    
    def _generate_complexity_section(self, results: Dict[str, Any]) -> str:
        """Generate complexity analysis section."""
        avg_complexity = results['metrics'].get('averages', {}).get('complexity', 0)
        
        # Find most complex files
        complex_files = []
        for file_path, file_data in results['files'].items():
            if 'analyses' in file_data and 'complexity' in file_data['analyses']:
                complexity = file_data['analyses']['complexity']
                complex_files.append({
                    'file': Path(file_path).name,
                    'complexity': complexity.get('average_complexity', 0),
                    'max': complexity.get('max_complexity', 0)
                })
        
        complex_files.sort(key=lambda x: x['complexity'], reverse=True)
        
        section = f"""
**Average Cyclomatic Complexity:** {avg_complexity:.1f}  
**Complexity Distribution:**
- Low (1-5): {self._count_complexity_range(results, 0, 5)} files
- Medium (6-10): {self._count_complexity_range(results, 6, 10)} files
- High (11-20): {self._count_complexity_range(results, 11, 20)} files
- Very High (>20): {self._count_complexity_range(results, 21, 999)} files

### Most Complex Files

| File | Average Complexity | Max Complexity |
|------|-------------------|----------------|
"""
        
        for file_info in complex_files[:10]:
            section += f"| {file_info['file']} | {file_info['complexity']:.1f} | {file_info['max']} |\n"
        
        return section
    
    def _generate_dependencies_section(self, results: Dict[str, Any]) -> str:
        """Generate dependencies section."""
        deps = results.get('dependencies', {})
        if not deps:
            return "Dependency analysis not performed."
        
        metrics = deps.get('metrics', {})
        patterns = deps.get('patterns', {})
        
        section = f"""
### Dependency Metrics

- **Total Dependencies:** {metrics.get('total_dependencies', 0)}
- **External Dependencies:** {metrics.get('external_dependencies', 0)}
- **Circular Dependencies:** {len(metrics.get('circular_dependencies', []))}
- **Average Coupling:** {metrics.get('coupling_score', 0):.1f}
- **Instability:** {metrics.get('instability', 0):.2f}
"""
        
        # Circular dependencies
        circular = metrics.get('circular_dependencies', [])
        if circular:
            section += "\n### Circular Dependencies\n\n"
            for i, cycle in enumerate(circular[:5]):
                section += f"{i+1}. {' → '.join(cycle[:4])}"
                if len(cycle) > 4:
                    section += f" → ... ({len(cycle)} modules total)"
                section += "\n"
        
        # God modules
        god_modules = patterns.get('god_modules', [])
        if god_modules:
            section += "\n### God Modules (High Fan-out)\n\n"
            for module in god_modules[:5]:
                section += f"- **{module['module']}**: {module['outgoing_dependencies']} dependencies\n"
        
        return section
    
    def _generate_debt_section(self, results: Dict[str, Any]) -> str:
        """Generate technical debt section."""
        # Count TODOs
        todo_count = 0
        for file_data in results['files'].values():
            if 'analyses' in file_data and 'todos' in file_data['analyses']:
                todo_count += file_data['analyses']['todos'].get('total_todos', 0)
        
        # Count dead code
        dead_code_files = sum(
            1 for f in results['files'].values()
            if 'analyses' in f and 'dead_code' in f['analyses']
            and f['analyses']['dead_code'].get('total_dead_code', 0) > 0
        )
        
        section = f"""
### Technical Debt Indicators

- **TODO/FIXME Comments:** {todo_count}
- **Files with Dead Code:** {dead_code_files}
- **Code Duplication:** {self._get_duplication_percentage(results):.1f}%
- **Missing Documentation:** {100 - self._get_doc_coverage(results):.1f}%

### Debt Reduction Priorities

1. **Remove Dead Code**: Eliminate unused imports, variables, and functions
2. **Resolve TODOs**: Address pending tasks and known issues
3. **Reduce Duplication**: Extract common code into shared modules
4. **Improve Documentation**: Add missing docstrings and comments
"""
        
        return section
    
    def _generate_file_analysis_section(self, results: Dict[str, Any]) -> str:
        """Generate file-by-file analysis section."""
        section = "Detailed analysis for each file:\n\n"
        
        # Sort files by total issues
        files_with_issues = []
        for file_path, file_data in results['files'].items():
            if 'error' in file_data:
                continue
            
            issue_count = 0
            analyses = file_data.get('analyses', {})
            
            if 'security' in analyses:
                issue_count += analyses['security'].get('total_issues', 0)
            if 'quality' in analyses:
                issue_count += analyses['quality'].get('total_issues', 0)
            
            if issue_count > 0:
                files_with_issues.append((file_path, file_data, issue_count))
        
        files_with_issues.sort(key=lambda x: x[2], reverse=True)
        
        # Show top 20 files
        for file_path, file_data, issue_count in files_with_issues[:20]:
            section += f"#### `{Path(file_path).name}`\n"
            section += f"- **Issues:** {issue_count}\n"
            
            analyses = file_data.get('analyses', {})
            if 'complexity' in analyses:
                complexity = analyses['complexity']
                section += f"- **Complexity:** {complexity.get('average_complexity', 0):.1f} (avg), "
                section += f"{complexity.get('max_complexity', 0)} (max)\n"
            
            if 'basic' in analyses:
                basic = analyses['basic']
                section += f"- **LOC:** {basic.get('metrics', {}).get('loc', 0)}\n"
            
            section += "\n"
        
        if len(files_with_issues) > 20:
            section += f"*...and {len(files_with_issues) - 20} more files*\n"
        
        return section
    
    def _generate_visualizations_section(self, results: Dict[str, Any]) -> str:
        """Generate visualizations section."""
        viz = results.get('visualizations', {})
        
        if not viz:
            return "No visualizations generated."
        
        section = "### Available Visualizations\n\n"
        
        if 'dependency_graph_mermaid' in viz:
            section += "#### Dependency Graph\n\n```mermaid\n"
            section += viz['dependency_graph_mermaid']
            section += "\n```\n\n"
        
        if 'dashboard_html' in viz:
            section += "#### Interactive Dashboard\n"
            section += "An interactive HTML dashboard is available with detailed metrics and charts.\n\n"
        
        if 'complexity_treemap' in viz:
            section += "#### Complexity Treemap\n"
            section += "A treemap visualization showing file sizes and complexity is available.\n\n"
        
        return section
    
    # Helper methods
    def _get_doc_coverage(self, results: Dict[str, Any]) -> float:
        """Calculate documentation coverage percentage."""
        total_functions = 0
        documented_functions = 0
        
        for file_data in results['files'].values():
            if 'analyses' in file_data and 'quality' in file_data['analyses']:
                metrics = file_data['analyses']['quality'].get('metrics', {})
                if 'total_functions' in metrics and 'functions_with_docstrings' in metrics:
                    total_functions += metrics['total_functions']
                    documented_functions += metrics['functions_with_docstrings']
        
        if total_functions == 0:
            return 100.0
        
        return (documented_functions / total_functions) * 100
    
    def _get_avg_function_length(self, results: Dict[str, Any]) -> float:
        """Calculate average function length."""
        lengths = []
        
        for file_data in results['files'].values():
            if 'analyses' in file_data and 'quality' in file_data['analyses']:
                metrics = file_data['analyses']['quality'].get('metrics', {})
                if 'max_function_length' in metrics:
                    lengths.append(metrics['max_function_length'])
        
        return sum(lengths) / len(lengths) if lengths else 0
    
    def _get_duplication_percentage(self, results: Dict[str, Any]) -> float:
        """Estimate code duplication percentage."""
        # Simplified estimation based on quality issues
        quality_issues = [
            i for i in results.get('issues', [])
            if i.get('category') == 'quality' and 'duplicate' in i.get('message', '').lower()
        ]
        
        total_files = results['summary'].get('total_files', 1)
        if total_files == 0:
            return 0
        
        return min((len(quality_issues) / total_files) * 100, 100)
    
    def _count_complexity_range(self, results: Dict[str, Any], min_val: int, max_val: int) -> int:
        """Count files in complexity range."""
        count = 0
        
        for file_data in results['files'].values():
            if 'analyses' in file_data and 'complexity' in file_data['analyses']:
                complexity = file_data['analyses']['complexity'].get('average_complexity', 0)
                if min_val <= complexity <= max_val:
                    count += 1
        
        return count