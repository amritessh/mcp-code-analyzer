# src/analyzers/dependencies.py
import ast
import re
import json
from pathlib import Path
from typing import Dict, Any, List, Set, Optional, Tuple
from collections import defaultdict, deque
import networkx as nx
from dataclasses import dataclass

from ..utils.logger import logger
from ..config import settings

@dataclass
class Dependency:
    """Represents a code dependency."""
    source: str  # Source module/file
    target: str  # Target module/file
    import_type: str  # 'import', 'from', 'dynamic'
    line_number: int
    is_external: bool
    is_standard_lib: bool
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'source': self.source,
            'target': self.target,
            'type': self.import_type,
            'line': self.line_number,
            'external': self.is_external,
            'stdlib': self.is_standard_lib
        }

@dataclass
class DependencyMetrics:
    """Metrics for dependency analysis."""
    total_dependencies: int
    external_dependencies: int
    internal_dependencies: int
    circular_dependencies: List[List[str]]
    coupling_score: float
    cohesion_score: float
    instability: float
    abstractness: float

class DependencyAnalyzer:
    """Analyze code dependencies and relationships."""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.standard_libs = self._load_standard_libs()
        self.external_packages = set()
        
    def _load_standard_libs(self) -> Set[str]:
        """Load Python standard library module names."""
        import sys
        stdlib_modules = set(sys.stdlib_module_names)
        
        # Add common standard library packages
        stdlib_modules.update({
            'os', 'sys', 'math', 'json', 'csv', 'sqlite3',
            'datetime', 'collections', 'itertools', 'functools',
            'pathlib', 'typing', 'dataclasses', 'enum',
            're', 'ast', 'logging', 'asyncio', 'concurrent',
            'urllib', 'http', 'email', 'xml', 'html'
        })
        
        return stdlib_modules
    
    async def analyze_dependencies(
        self,
        path: Path,
        depth: int = 3,
        include_external: bool = True,
        include_stdlib: bool = False
    ) -> Dict[str, Any]:
        """Analyze dependencies for a file or project."""
        logger.info(f"Analyzing dependencies for: {path}")
        
        # Clear previous analysis
        self.graph.clear()
        self.external_packages.clear()
        
        if path.is_file():
            await self._analyze_file_dependencies(path)
        else:
            await self._analyze_project_dependencies(path, depth)
        
        # Calculate metrics
        metrics = self._calculate_metrics()
        
        # Find patterns
        patterns = self._find_dependency_patterns()
        
        # Generate visualization data
        viz_data = self._generate_visualization_data(
            include_external, 
            include_stdlib
        )
        
        return {
            'path': str(path),
            'metrics': {
                'total_dependencies': metrics.total_dependencies,
                'external_dependencies': metrics.external_dependencies,
                'internal_dependencies': metrics.internal_dependencies,
                'circular_dependencies': metrics.circular_dependencies,
                'coupling_score': metrics.coupling_score,
                'cohesion_score': metrics.cohesion_score,
                'instability': metrics.instability,
                'abstractness': metrics.abstractness
            },
            'patterns': patterns,
            'visualization': viz_data,
            'dependencies': self._get_dependency_list(),
            'recommendations': self._generate_recommendations(metrics, patterns)
        }
    
    async def _analyze_file_dependencies(self, file_path: Path) -> None:
        """Analyze dependencies for a single file."""
        if file_path.suffix != '.py':
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            # Extract imports
            visitor = ImportVisitor(str(file_path), self.standard_libs)
            visitor.visit(tree)
            
            # Add to graph
            for dep in visitor.dependencies:
                self._add_dependency(dep)
                
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
    
    async def _analyze_project_dependencies(
        self, 
        project_path: Path, 
        max_depth: int
    ) -> None:
        """Analyze dependencies for entire project."""
        python_files = list(project_path.rglob('*.py'))
        
        logger.info(f"Found {len(python_files)} Python files")
        
        # First pass: analyze all files
        for file_path in python_files:
            if any(part.startswith('.') for part in file_path.parts):
                continue  # Skip hidden directories
            if 'venv' in file_path.parts or '__pycache__' in file_path.parts:
                continue  # Skip virtual environments
            
            await self._analyze_file_dependencies(file_path)
        
        # Second pass: resolve relative imports
        self._resolve_relative_imports(project_path)
        
        # Load external package info if available
        self._load_external_packages(project_path)
    
    def _add_dependency(self, dep: Dependency) -> None:
        """Add dependency to graph."""
        self.graph.add_edge(
            dep.source,
            dep.target,
            import_type=dep.import_type,
            line=dep.line_number,
            external=dep.is_external,
            stdlib=dep.is_standard_lib
        )
        
        # Track external packages
        if dep.is_external and not dep.is_standard_lib:
            self.external_packages.add(dep.target.split('.')[0])
    
    def _resolve_relative_imports(self, project_path: Path) -> None:
        """Resolve relative imports to absolute paths."""
        # Convert relative imports like "from . import x" to absolute paths
        updates = []
        
        for source, target, data in self.graph.edges(data=True):
            if target.startswith('.'):
                # Resolve relative import
                source_path = Path(source)
                if source_path.is_absolute():
                    source_rel = source_path.relative_to(project_path)
                else:
                    source_rel = source_path
                
                # Calculate absolute import path
                parent_parts = source_rel.parent.parts
                relative_parts = target.split('.')
                
                # Handle different relative import levels
                level = len([p for p in relative_parts if p == ''])
                if level > 0:
                    parent_parts = parent_parts[:-level+1]
                
                absolute_target = '.'.join(parent_parts + tuple(
                    p for p in relative_parts if p
                ))
                
                updates.append((source, target, absolute_target))
        
        # Apply updates
        for source, old_target, new_target in updates:
            data = self.graph[source][old_target]
            self.graph.remove_edge(source, old_target)
            self.graph.add_edge(source, new_target, **data)
    
    def _load_external_packages(self, project_path: Path) -> None:
        """Load external package information."""
        # Check for requirements.txt
        req_file = project_path / 'requirements.txt'
        if req_file.exists():
            try:
                with open(req_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Extract package name
                            pkg_name = re.split(r'[<>=!]', line)[0].strip()
                            self.external_packages.add(pkg_name)
            except Exception as e:
                logger.error(f"Error reading requirements.txt: {e}")
        
        # Check for setup.py, pyproject.toml, etc.
        # (Implementation similar to Week 2's dependency scanner)
    
    def _calculate_metrics(self) -> DependencyMetrics:
        """Calculate dependency metrics."""
        nodes = list(self.graph.nodes())
        edges = list(self.graph.edges(data=True))
        
        # Count dependencies
        total_deps = len(edges)
        external_deps = sum(1 for _, _, d in edges if d.get('external', False))
        internal_deps = total_deps - external_deps
        
        # Find circular dependencies
        circular_deps = self._find_circular_dependencies()
        
        # Calculate coupling (fan-out)
        coupling_scores = []
        for node in nodes:
            out_degree = self.graph.out_degree(node)
            if out_degree > 0:
                coupling_scores.append(out_degree)
        
        avg_coupling = sum(coupling_scores) / len(coupling_scores) if coupling_scores else 0
        
        # Calculate cohesion (how well modules work together)
        cohesion = self._calculate_cohesion()
        
        # Calculate instability (I = Ce / (Ca + Ce))
        # Ce = Efferent coupling (outgoing dependencies)
        # Ca = Afferent coupling (incoming dependencies)
        instability_scores = []
        for node in nodes:
            ce = self.graph.out_degree(node)
            ca = self.graph.in_degree(node)
            if ce + ca > 0:
                instability = ce / (ce + ca)
                instability_scores.append(instability)
        
        avg_instability = sum(instability_scores) / len(instability_scores) if instability_scores else 0
        
        # Calculate abstractness (simplified - ratio of abstract elements)
        abstractness = self._calculate_abstractness()
        
        return DependencyMetrics(
            total_dependencies=total_deps,
            external_dependencies=external_deps,
            internal_dependencies=internal_deps,
            circular_dependencies=circular_deps,
            coupling_score=round(avg_coupling, 2),
            cohesion_score=round(cohesion, 2),
            instability=round(avg_instability, 2),
            abstractness=round(abstractness, 2)
        )
    
    def _find_circular_dependencies(self) -> List[List[str]]:
        """Find circular dependencies in the graph."""
        cycles = []
        
        try:
            # Find all simple cycles
            all_cycles = nx.simple_cycles(self.graph)
            for cycle in all_cycles:
                if len(cycle) > 1:  # Ignore self-loops
                    cycles.append(cycle)
        except Exception as e:
            logger.error(f"Error finding cycles: {e}")
        
        return cycles[:10]  # Limit to first 10 cycles
    
    def _calculate_cohesion(self) -> float:
        """Calculate cohesion metric."""
        # Simplified cohesion: ratio of internal connections to possible connections
        if len(self.graph) < 2:
            return 1.0
        
        # Find strongly connected components
        components = list(nx.strongly_connected_components(self.graph))
        
        cohesion_scores = []
        for component in components:
            if len(component) > 1:
                subgraph = self.graph.subgraph(component)
                actual_edges = subgraph.number_of_edges()
                possible_edges = len(component) * (len(component) - 1)
                if possible_edges > 0:
                    cohesion = actual_edges / possible_edges
                    cohesion_scores.append(cohesion)
        
        return sum(cohesion_scores) / len(cohesion_scores) if cohesion_scores else 0.5
    
    def _calculate_abstractness(self) -> float:
        """Calculate abstractness metric."""
        # Simplified: modules with fewer outgoing dependencies are more abstract
        if not self.graph:
            return 0.0
        
        abstractness_scores = []
        max_out_degree = max(self.graph.out_degree(n) for n in self.graph.nodes()) or 1
        
        for node in self.graph.nodes():
            out_degree = self.graph.out_degree(node)
            abstractness = 1 - (out_degree / max_out_degree)
            abstractness_scores.append(abstractness)
        
        return sum(abstractness_scores) / len(abstractness_scores)
    
    def _find_dependency_patterns(self) -> Dict[str, Any]:
        """Find common dependency patterns and anti-patterns."""
        patterns = {
            'hub_modules': [],
            'god_modules': [],
            'isolated_modules': [],
            'tightly_coupled_groups': [],
            'layering_violations': []
        }
        
        # Find hub modules (high fan-in)
        for node in self.graph.nodes():
            in_degree = self.graph.in_degree(node)
            if in_degree > 10:  # Threshold
                patterns['hub_modules'].append({
                    'module': node,
                    'incoming_dependencies': in_degree
                })
        
        # Find god modules (high fan-out)
        for node in self.graph.nodes():
            out_degree = self.graph.out_degree(node)
            if out_degree > 15:  # Threshold
                patterns['god_modules'].append({
                    'module': node,
                    'outgoing_dependencies': out_degree
                })
        
        # Find isolated modules
        for node in self.graph.nodes():
            if self.graph.degree(node) == 0:
                patterns['isolated_modules'].append(node)
        
        # Find tightly coupled groups
        components = nx.strongly_connected_components(self.graph)
        for component in components:
            if len(component) > 2:
                patterns['tightly_coupled_groups'].append(list(component))
        
        # Check for layering violations (simplified)
        patterns['layering_violations'] = self._check_layering_violations()
        
        return patterns
    
    def _check_layering_violations(self) -> List[Dict[str, str]]:
        """Check for architectural layering violations."""
        violations = []
        
        # Define common layer patterns
        layers = {
            'models': 0,
            'database': 1,
            'services': 2,
            'controllers': 3,
            'views': 4
        }
        
        for source, target in self.graph.edges():
            source_layer = None
            target_layer = None
            
            # Determine layers based on path
            for layer_name, layer_level in layers.items():
                if layer_name in source.lower():
                    source_layer = layer_level
                if layer_name in target.lower():
                    target_layer = layer_level
            
            # Check for upward dependencies
            if source_layer is not None and target_layer is not None:
                if source_layer > target_layer:
                    violations.append({
                        'source': source,
                        'target': target,
                        'violation': f"{source} depends on lower layer {target}"
                    })
        
        return violations
    
    def _generate_visualization_data(
        self,
        include_external: bool,
        include_stdlib: bool
    ) -> Dict[str, Any]:
        """Generate data for visualization."""
        nodes = []
        edges = []
        
        # Filter nodes
        for node in self.graph.nodes():
            node_data = {
                'id': node,
                'label': Path(node).name if '/' in node else node,
                'type': 'internal'
            }
            
            # Determine node type
            if node in self.external_packages:
                if not include_external:
                    continue
                node_data['type'] = 'external'
            elif any(node.startswith(lib) for lib in self.standard_libs):
                if not include_stdlib:
                    continue
                node_data['type'] = 'stdlib'
            
            # Add metrics
            node_data['in_degree'] = self.graph.in_degree(node)
            node_data['out_degree'] = self.graph.out_degree(node)
            
            nodes.append(node_data)
        
        # Filter edges
        node_ids = {n['id'] for n in nodes}
        for source, target, data in self.graph.edges(data=True):
            if source in node_ids and target in node_ids:
                edges.append({
                    'source': source,
                    'target': target,
                    'type': data.get('import_type', 'import')
                })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'format': 'network'
        }
    
    def _get_dependency_list(self) -> List[Dict[str, Any]]:
        """Get flat list of all dependencies."""
        deps = []
        
        for source, target, data in self.graph.edges(data=True):
            deps.append({
                'source': source,
                'target': target,
                'type': data.get('import_type', 'import'),
                'line': data.get('line', 0),
                'external': data.get('external', False),
                'stdlib': data.get('stdlib', False)
            })
        
        return sorted(deps, key=lambda x: (x['source'], x['target']))
    
    def _generate_recommendations(
        self,
        metrics: DependencyMetrics,
        patterns: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        
        # Check coupling
        if metrics.coupling_score > 10:
            recommendations.append(
                f"High coupling detected (avg: {metrics.coupling_score}). "
                "Consider reducing dependencies between modules."
            )
        
        # Check circular dependencies
        if metrics.circular_dependencies:
            recommendations.append(
                f"Found {len(metrics.circular_dependencies)} circular dependencies. "
                "These should be resolved to improve maintainability."
            )
        
        # Check god modules
        if patterns['god_modules']:
            god_modules = ', '.join(m['module'] for m in patterns['god_modules'][:3])
            recommendations.append(
                f"God modules detected: {god_modules}. "
                "Consider splitting these modules into smaller, focused components."
            )
        
        # Check hub modules
        if patterns['hub_modules']:
            recommendations.append(
                "Several modules have high fan-in. "
                "Ensure these are stable interfaces or consider abstracting common functionality."
            )
        
        # Check instability
        if metrics.instability > 0.8:
            recommendations.append(
                "High instability detected. Many modules depend on external packages. "
                "Consider creating abstraction layers."
            )
        
        # Check isolated modules
        if len(patterns['isolated_modules']) > 5:
            recommendations.append(
                f"Found {len(patterns['isolated_modules'])} isolated modules. "
                "Review if these are actually used or can be removed."
            )
        
        return recommendations


class ImportVisitor(ast.NodeVisitor):
    """AST visitor to extract import statements."""
    
    def __init__(self, source_file: str, stdlib_modules: Set[str]):
        self.source_file = source_file
        self.stdlib_modules = stdlib_modules
        self.dependencies = []
        
    def visit_Import(self, node: ast.Import) -> None:
        """Handle 'import x' statements."""
        for alias in node.names:
            target = alias.name
            self.dependencies.append(Dependency(
                source=self.source_file,
                target=target,
                import_type='import',
                line_number=node.lineno,
                is_external=not self._is_internal_module(target),
                is_standard_lib=self._is_stdlib(target)
            ))
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Handle 'from x import y' statements."""
        if node.module:
            target = node.module
        else:
            # Relative import
            target = '.' * node.level
        
        self.dependencies.append(Dependency(
            source=self.source_file,
            target=target,
            import_type='from',
            line_number=node.lineno,
            is_external=not self._is_internal_module(target),
            is_standard_lib=self._is_stdlib(target)
        ))
        self.generic_visit(node)
    
    def _is_internal_module(self, module: str) -> bool:
        """Check if module is internal to the project."""
        if module.startswith('.'):
            return True  # Relative import
        
        # Check if it's a known external package or stdlib
        return not (self._is_stdlib(module) or self._is_known_external(module))
    
    def _is_stdlib(self, module: str) -> bool:
        """Check if module is from standard library."""
        base_module = module.split('.')[0]
        return base_module in self.stdlib_modules
    
    def _is_known_external(self, module: str) -> bool:
        """Check if module is a known external package."""
        # Common external packages
        external_indicators = {
            'numpy', 'pandas', 'requests', 'flask', 'django',
            'pytest', 'setuptools', 'pip', 'wheel',
            'matplotlib', 'seaborn', 'scipy', 'sklearn',
            'tensorflow', 'torch', 'keras'
        }
        
        base_module = module.split('.')[0]
        return base_module in external_indicators