# src/analyzers/circular_dependencies.py
import ast
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict, deque
import networkx as nx
from utils.logger import logger

class CircularDependencyDetector:
    """Detect and analyze circular dependencies."""
    
    def __init__(self, dependency_graph: nx.DiGraph):
        self.graph = dependency_graph
        
    def detect_cycles(self) -> Dict[str, Any]:
        """Detect all circular dependencies."""
        cycles = self._find_all_cycles()
        
        # Analyze cycles
        analysis = {
            'total_cycles': len(cycles),
            'cycles': [],
            'affected_modules': set(),
            'severity_scores': [],
            'breaking_points': []
        }
        
        for cycle in cycles:
            cycle_info = self._analyze_cycle(cycle)
            analysis['cycles'].append(cycle_info)
            analysis['affected_modules'].update(cycle)
            analysis['severity_scores'].append(cycle_info['severity'])
            
            # Find best breaking points
            breaking_point = self._find_breaking_point(cycle)
            if breaking_point:
                analysis['breaking_points'].append(breaking_point)
        
        # Overall severity
        if analysis['severity_scores']:
            analysis['overall_severity'] = max(analysis['severity_scores'])
        else:
            analysis['overall_severity'] = 0
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_resolution_recommendations(
            analysis['cycles']
        )
        
        return analysis
    
    def _find_all_cycles(self) -> List[List[str]]:
        """Find all circular dependencies."""
        try:
            # Use Johnson's algorithm for finding all cycles
            cycles = list(nx.simple_cycles(self.graph))
            
            # Filter out self-loops and sort by length
            cycles = [c for c in cycles if len(c) > 1]
            cycles.sort(key=len)
            
            return cycles
            
        except Exception as e:
            logger.error(f"Error finding cycles: {e}")
            return []
    
    def _analyze_cycle(self, cycle: List[str]) -> Dict[str, Any]:
        """Analyze a single circular dependency."""
        edges = []
        
        # Get edge information
        for i in range(len(cycle)):
            source = cycle[i]
            target = cycle[(i + 1) % len(cycle)]
            
            if self.graph.has_edge(source, target):
                edge_data = self.graph[source][target]
                edges.append({
                    'source': source,
                    'target': target,
                    'import_type': edge_data.get('import_type', 'unknown'),
                    'line': edge_data.get('line', 0)
                })
        
        # Calculate severity (based on cycle length and module types)
        severity = self._calculate_cycle_severity(cycle, edges)
        
        # Determine cycle type
        cycle_type = self._classify_cycle(cycle)
        
        return {
            'modules': cycle,
            'length': len(cycle),
            'edges': edges,
            'severity': severity,
            'type': cycle_type,
            'description': self._generate_cycle_description(cycle, cycle_type)
        }
    
    def _calculate_cycle_severity(
        self, 
        cycle: List[str], 
        edges: List[Dict[str, Any]]
    ) -> int:
        """Calculate severity score for a cycle (1-10)."""
        base_severity = min(len(cycle), 5)  # Longer cycles are worse
        
        # Check if core modules are involved
        core_indicators = ['core', 'base', 'model', 'database', 'config']
        if any(indicator in module.lower() for module in cycle 
               for indicator in core_indicators):
            base_severity += 2
        
        # Check if external dependencies are involved
        if any(self._is_external_module(module) for module in cycle):
            base_severity += 1
        
        # Check import types (from imports are slightly better than direct imports)
        from_imports = sum(1 for e in edges if e['import_type'] == 'from')
        if from_imports < len(edges) / 2:
            base_severity += 1
        
        return min(base_severity, 10)
    
    def _classify_cycle(self, cycle: List[str]) -> str:
        """Classify the type of circular dependency."""
        # Check for common patterns
        if len(cycle) == 2:
            return "mutual"
        elif len(cycle) == 3:
            return "triangular"
        elif self._is_layered_cycle(cycle):
            return "layered"
        elif self._is_package_cycle(cycle):
            return "package"
        else:
            return "complex"
    
    def _is_layered_cycle(self, cycle: List[str]) -> bool:
        """Check if cycle crosses architectural layers."""
        layers = ['model', 'view', 'controller', 'service', 'repository']
        cycle_layers = []
        
        for module in cycle:
            for layer in layers:
                if layer in module.lower():
                    cycle_layers.append(layer)
                    break
        
        return len(set(cycle_layers)) > 1
    
    def _is_package_cycle(self, cycle: List[str]) -> bool:
        """Check if cycle is between packages."""
        packages = set()
        
        for module in cycle:
            parts = module.split('.')
            if len(parts) > 1:
                packages.add(parts[0])
        
        return len(packages) > 1
    
    def _is_external_module(self, module: str) -> bool:
        """Check if module is external."""
        # Simple heuristic - can be improved
        return not ('/' in module or '.' in module)
    
    def _generate_cycle_description(self, cycle: List[str], cycle_type: str) -> str:
        """Generate human-readable description of the cycle."""
        if cycle_type == "mutual":
            return f"{cycle[0]} and {cycle[1]} depend on each other"
        elif cycle_type == "triangular":
            return f"Triangular dependency between {', '.join(cycle)}"
        elif cycle_type == "layered":
            return f"Cross-layer circular dependency involving {len(cycle)} modules"
        elif cycle_type == "package":
            return f"Inter-package circular dependency with {len(cycle)} modules"
        else:
            return f"Complex circular dependency chain of {len(cycle)} modules"
    
    def _find_breaking_point(self, cycle: List[str]) -> Optional[Dict[str, Any]]:
        """Find the best edge to break in a cycle."""
        candidates = []
        
        for i in range(len(cycle)):
            source = cycle[i]
            target = cycle[(i + 1) % len(cycle)]
            
            if self.graph.has_edge(source, target):
                # Calculate impact of breaking this edge
                impact = self._calculate_breaking_impact(source, target, cycle)
                
                candidates.append({
                    'source': source,
                    'target': target,
                    'impact_score': impact,
                    'suggestion': self._generate_breaking_suggestion(source, target)
                })
        
        # Return the edge with lowest impact
        if candidates:
            return min(candidates, key=lambda x: x['impact_score'])
        
        return None
    
    def _calculate_breaking_impact(
        self, 
        source: str, 
        target: str, 
        cycle: List[str]
    ) -> float:
        """Calculate the impact of breaking an edge."""
        impact = 0.0
        
        # Prefer breaking edges to external modules
        if self._is_external_module(target):
            impact -= 2.0
        
        # Prefer breaking edges from high-level to low-level modules
        if 'controller' in source and 'model' in target:
            impact -= 1.0
        elif 'model' in source and 'controller' in target:
            impact += 2.0  # Avoid breaking this
        
        # Consider the centrality of the nodes
        if nx.degree_centrality(self.graph).get(source, 0) > 0.5:
            impact += 1.0  # Avoid breaking edges from central nodes
        
        return impact
    
    def _generate_breaking_suggestion(self, source: str, target: str) -> str:
        """Generate suggestion for breaking a dependency."""
        suggestions = []
        
        # Check if interface can be introduced
        if 'service' in source.lower() or 'service' in target.lower():
            suggestions.append(
                f"Introduce an interface between {source} and {target}"
            )
        
        # Check if dependency can be inverted
        if self._should_invert_dependency(source, target):
            suggestions.append(
                f"Invert dependency: make {target} depend on abstraction"
            )
        
        # Check if functionality can be moved
        suggestions.append(
            f"Consider moving shared functionality to a separate module"
        )
        
        return " OR ".join(suggestions)
    
    def _should_invert_dependency(self, source: str, target: str) -> bool:
        """Check if dependency inversion is appropriate."""
        # High-level modules shouldn't depend on low-level modules
        high_level = ['controller', 'service', 'api']
        low_level = ['database', 'repository', 'dao']
        
        source_high = any(h in source.lower() for h in high_level)
        target_low = any(l in target.lower() for l in low_level)
        
        return source_high and target_low
    
    def _generate_resolution_recommendations(
        self, 
        cycles: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate recommendations for resolving circular dependencies."""
        recommendations = []
        
        if not cycles:
            return ["No circular dependencies found!"]
        
        # Priority 1: Fix high-severity cycles
        high_severity = [c for c in cycles if c['severity'] >= 7]
        if high_severity:
            recommendations.append(
                f"CRITICAL: Fix {len(high_severity)} high-severity circular dependencies first"
            )
        
        # Analyze patterns
        cycle_types = [c['type'] for c in cycles]
        
        if cycle_types.count('mutual') > 3:
            recommendations.append(
                "Multiple mutual dependencies detected. Consider introducing interfaces or dependency injection"
            )
        
        if cycle_types.count('layered') > 0:
            recommendations.append(
                "Layered architecture violations detected. Ensure dependencies flow downward only"
            )
        
        if cycle_types.count('package') > 0:
            recommendations.append(
                "Package-level cycles found. Consider reorganizing package structure"
            )
        
        # Suggest refactoring patterns
        total_modules = len(set(module for c in cycles for module in c['modules']))
        if total_modules > 10:
            recommendations.append(
                f"{total_modules} modules involved in circular dependencies. "
                "Consider a major refactoring using Dependency Inversion Principle"
            )
        
        return recommendations


class DependencyRefactorer:
    """Suggest refactoring strategies for dependency issues."""
    
    def __init__(self, graph: nx.DiGraph):
        self.graph = graph
        
    def suggest_refactoring(
        self,
        circular_deps: List[List[str]],
        god_modules: List[str],
        coupling_threshold: float = 10.0
    ) -> Dict[str, Any]:
        """Generate comprehensive refactoring suggestions."""
        suggestions = {
            'patterns': [],
            'specific_changes': [],
            'new_modules': [],
            'interfaces': []
        }
        
        # Analyze and suggest patterns
        if circular_deps:
            suggestions['patterns'].extend(
                self._suggest_patterns_for_cycles(circular_deps)
            )
        
        if god_modules:
            suggestions['patterns'].extend(
                self._suggest_patterns_for_god_modules(god_modules)
            )
        
        # Suggest specific changes
        suggestions['specific_changes'] = self._suggest_specific_changes()
        
        # Suggest new modules to introduce
        suggestions['new_modules'] = self._suggest_new_modules()
        
        # Suggest interfaces
        suggestions['interfaces'] = self._suggest_interfaces()
        
        return suggestions
    
    def _suggest_patterns_for_cycles(
        self, 
        cycles: List[List[str]]
    ) -> List[Dict[str, Any]]:
        """Suggest design patterns for breaking cycles."""
        patterns = []
        
        for cycle in cycles:
            if len(cycle) == 2:
                # Mutual dependency
                patterns.append({
                    'pattern': 'Mediator',
                    'description': f"Introduce mediator between {cycle[0]} and {cycle[1]}",
                    'modules': cycle,
                    'implementation': self._generate_mediator_example(cycle)
                })
            elif self._is_data_cycle(cycle):
                # Data-related cycle
                patterns.append({
                    'pattern': 'Repository',
                    'description': "Centralize data access through repository pattern",
                    'modules': cycle,
                    'implementation': self._generate_repository_example(cycle)
                })
            else:
                # General cycle
                patterns.append({
                    'pattern': 'Dependency Inversion',
                    'description': "Introduce abstractions to invert dependencies",
                    'modules': cycle,
                    'implementation': self._generate_dip_example(cycle)
                })
        
        return patterns
    
    def _suggest_patterns_for_god_modules(
        self, 
        god_modules: List[str]
    ) -> List[Dict[str, Any]]:
        """Suggest patterns for refactoring god modules."""
        patterns = []
        
        for module in god_modules:
            out_degree = self.graph.out_degree(module)
            
            if out_degree > 20:
                patterns.append({
                    'pattern': 'Facade',
                    'description': f"Create facade to simplify {module}'s interface",
                    'modules': [module],
                    'implementation': self._generate_facade_example(module)
                })
            
            # Analyze what the module depends on
            dependencies = list(self.graph.successors(module))
            dep_categories = self._categorize_dependencies(dependencies)
            
            if len(dep_categories) > 3:
                patterns.append({
                    'pattern': 'Single Responsibility',
                    'description': f"Split {module} into focused modules",
                    'modules': [module],
                    'suggested_split': dep_categories
                })
        
        return patterns
    
    def _is_data_cycle(self, cycle: List[str]) -> bool:
        """Check if cycle involves data/model modules."""
        data_indicators = ['model', 'entity', 'data', 'repository', 'dao']
        return any(
            indicator in module.lower() 
            for module in cycle 
            for indicator in data_indicators
        )
    
    def _categorize_dependencies(
        self, 
        dependencies: List[str]
    ) -> Dict[str, List[str]]:
        """Categorize dependencies by their type."""
        categories = defaultdict(list)
        
        for dep in dependencies:
            if any(x in dep.lower() for x in ['model', 'entity', 'data']):
                categories['data'].append(dep)
            elif any(x in dep.lower() for x in ['service', 'logic', 'business']):
                categories['business'].append(dep)
            elif any(x in dep.lower() for x in ['util', 'helper', 'common']):
                categories['utility'].append(dep)
            elif any(x in dep.lower() for x in ['api', 'controller', 'view']):
                categories['presentation'].append(dep)
            else:
                categories['other'].append(dep)
        
        return dict(categories)
    
    def _generate_mediator_example(self, modules: List[str]) -> str:
        """Generate mediator pattern example."""
        return f"""
# Instead of direct dependency between {modules[0]} and {modules[1]}
# Introduce a mediator:

class {modules[0].split('.')[-1]}_{modules[1].split('.')[-1]}_Mediator:
    def __init__(self):
        self.{modules[0].lower()} = None
        self.{modules[1].lower()} = None
    
    def register(self, module):
        # Register modules with mediator
        pass
    
    def handle_interaction(self, source, action, data):
        # Handle communication between modules
        pass
"""
    
    def _generate_repository_example(self, modules: List[str]) -> str:
        """Generate repository pattern example."""
        return f"""
# Centralize data access through repository:

class DataRepository:
    def __init__(self):
        # Initialize data sources
        pass
    
    def get_data(self, identifier):
        # Centralized data access
        pass
    
    def save_data(self, data):
        # Centralized data persistence
        pass

# Modules depend on repository instead of each other
"""
    
    def _generate_dip_example(self, modules: List[str]) -> str:
        """Generate dependency inversion example."""
        return f"""
# Define abstraction/interface:

from abc import ABC, abstractmethod

class {modules[0].split('.')[-1]}Interface(ABC):
    @abstractmethod
    def process(self, data):
        pass

# High-level module depends on abstraction:
class {modules[1].split('.')[-1]}:
    def __init__(self, processor: {modules[0].split('.')[-1]}Interface):
        self.processor = processor

# Low-level module implements abstraction:
class {modules[0].split('.')[-1]}(Interface):
    def process(self, data):
        # Implementation
        pass
"""
    
    def _generate_facade_example(self, module: str) -> str:
        """Generate facade pattern example."""
        return f"""
# Simplify complex module interface:

class {module.split('.')[-1]}Facade:
    def __init__(self):
        self._module = {module.split('.')[-1]}()
    
    def simple_operation_1(self, param):
        # Combine multiple internal calls
        result1 = self._module.complex_method_1(param)
        result2 = self._module.complex_method_2(result1)
        return self._module.finalize(result2)
    
    def simple_operation_2(self, param):
        # Hide complexity
        pass
"""
    
    def _suggest_specific_changes(self) -> List[Dict[str, str]]:
        """Suggest specific code changes."""
        changes = []
        
        # Find problematic imports
        for source, target, data in self.graph.edges(data=True):
            if data.get('import_type') == 'import':
                # Suggest changing to from imports for specific items
                changes.append({
                    'file': source,
                    'current': f"import {target}",
                    'suggested': f"from {target} import SpecificClass",
                    'reason': "Import only what you need"
                })
        
        return changes[:10]  # Limit suggestions
    
    def _suggest_new_modules(self) -> List[Dict[str, Any]]:
        """Suggest new modules to introduce."""
        suggestions = []
        
        # Find common dependencies
        dependency_counts = defaultdict(int)
        for node in self.graph.nodes():
            for dep in self.graph.successors(node):
                dependency_counts[dep] += 1
        
        # Suggest extracting highly used dependencies
        for dep, count in dependency_counts.items():
            if count > 5:
                suggestions.append({
                    'name': f"{dep}_interface",
                    'purpose': f"Abstract interface for {dep}",
                    'reason': f"Used by {count} modules - good candidate for abstraction"
                })
        
        return suggestions[:5]
    
    def _suggest_interfaces(self) -> List[Dict[str, Any]]:
        """Suggest interfaces to introduce."""
        interfaces = []
        
        # Find modules with high fan-in
        for node in self.graph.nodes():
            in_degree = self.graph.in_degree(node)
            if in_degree > 5:
                interfaces.append({
                    'module': node,
                    'interface_name': f"I{node.split('.')[-1]}",
                    'reason': f"High fan-in ({in_degree}) - define clear contract",
                    'methods': self._suggest_interface_methods(node)
                })
        
        return interfaces[:5]
    
    def _suggest_interface_methods(self, module: str) -> List[str]:
        """Suggest methods for an interface."""
        # This is simplified - in real implementation, 
        # would analyze actual module code
        return [
            "def process(self, data) -> Result",
            "def validate(self, input) -> bool",
            "def get_status(self) -> Status"
        ]