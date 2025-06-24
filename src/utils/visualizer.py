# src/utils/visualizer.py
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import networkx as nx
from pyvis.network import Network
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict

from ..utils.logger import logger

class DependencyVisualizer:
    """Generate various visualizations for code analysis."""
    
    def __init__(self):
        self.color_schemes = {
            'complexity': {
                'low': '#28a745',      # Green
                'medium': '#ffc107',   # Yellow
                'high': '#fd7e14',     # Orange
                'very_high': '#dc3545' # Red
            },
            'module_type': {
                'internal': '#007bff',  # Blue
                'external': '#6c757d',  # Gray
                'stdlib': '#17a2b8',    # Cyan
                'test': '#28a745'       # Green
            },
            'layer': {
                'model': '#dc3545',     # Red
                'service': '#fd7e14',   # Orange
                'controller': '#ffc107', # Yellow
                'view': '#28a745',      # Green
                'util': '#6c757d'       # Gray
            }
        }
    
    def generate_dependency_graph(
        self,
        graph_data: Dict[str, Any],
        output_format: str = 'mermaid',
        layout: str = 'hierarchical',
        highlight_cycles: bool = True
    ) -> str:
        """Generate dependency graph visualization."""
        
        if output_format == 'mermaid':
            return self._generate_mermaid_diagram(
                graph_data, 
                layout, 
                highlight_cycles
            )
        elif output_format == 'd3':
            return self._generate_d3_data(graph_data)
        elif output_format == 'graphviz':
            return self._generate_graphviz(graph_data)
        elif output_format == 'pyvis':
            return self._generate_interactive_graph(graph_data)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
    
    def _generate_mermaid_diagram(
        self,
        graph_data: Dict[str, Any],
        layout: str,
        highlight_cycles: bool
    ) -> str:
        """Generate Mermaid diagram."""
        lines = ["graph TD" if layout == "top-down" else "graph LR"]
        
        # Add nodes with styling
        for node in graph_data['nodes']:
            node_id = self._sanitize_mermaid_id(node['id'])
            label = node['label']
            
            # Style based on node type
            if node['type'] == 'external':
                lines.append(f'    {node_id}["{label}"]:::external')
            elif node['type'] == 'stdlib':
                lines.append(f'    {node_id}["{label}"]:::stdlib')
            else:
                # Style based on metrics
                if node.get('out_degree', 0) > 10:
                    lines.append(f'    {node_id}["{label}"]:::god')
                elif node.get('in_degree', 0) > 10:
                    lines.append(f'    {node_id}["{label}"]:::hub')
                else:
                    lines.append(f'    {node_id}["{label}"]')
        
        # Add edges
        cycles = graph_data.get('cycles', [])
        cycle_edges = set()
        
        if highlight_cycles and cycles:
            # Build set of cycle edges
            for cycle in cycles:
                for i in range(len(cycle)):
                    source = cycle[i]
                    target = cycle[(i + 1) % len(cycle)]
                    cycle_edges.add((source, target))
        
        for edge in graph_data['edges']:
            source_id = self._sanitize_mermaid_id(edge['source'])
            target_id = self._sanitize_mermaid_id(edge['target'])
            
            if (edge['source'], edge['target']) in cycle_edges:
                lines.append(f'    {source_id} -.-> {target_id}')
            else:
                lines.append(f'    {source_id} --> {target_id}')
        
        # Add styling
        lines.extend([
            '',
            '    classDef external fill:#6c757d,stroke:#333,stroke-width:2px,color:#fff',
            '    classDef stdlib fill:#17a2b8,stroke:#333,stroke-width:2px,color:#fff',
            '    classDef god fill:#dc3545,stroke:#333,stroke-width:4px,color:#fff',
            '    classDef hub fill:#fd7e14,stroke:#333,stroke-width:3px,color:#fff',
            '    classDef default fill:#007bff,stroke:#333,stroke-width:2px,color:#fff'
        ])
        
        return '\n'.join(lines)
    
    def _sanitize_mermaid_id(self, node_id: str) -> str:
        """Sanitize node ID for Mermaid."""
        # Replace special characters
        sanitized = node_id.replace('/', '_').replace('.', '_').replace('-', '_')
        # Ensure it starts with a letter
        if sanitized and sanitized[0].isdigit():
            sanitized = 'n_' + sanitized
        return sanitized
    
    def _generate_d3_data(self, graph_data: Dict[str, Any]) -> str:
        """Generate D3.js compatible JSON data."""
        d3_data = {
            'nodes': [],
            'links': []
        }
        
        # Create node index mapping
        node_index = {node['id']: i for i, node in enumerate(graph_data['nodes'])}
        
        # Add nodes with additional properties for D3
        for node in graph_data['nodes']:
            d3_node = {
                'id': node['id'],
                'name': node['label'],
                'type': node['type'],
                'in_degree': node.get('in_degree', 0),
                'out_degree': node.get('out_degree', 0),
                'group': self._get_node_group(node),
                'size': self._calculate_node_size(node)
            }
            d3_data['nodes'].append(d3_node)
        
        # Add links
        for edge in graph_data['edges']:
            if edge['source'] in node_index and edge['target'] in node_index:
                d3_data['links'].append({
                    'source': node_index[edge['source']],
                    'target': node_index[edge['target']],
                    'type': edge.get('type', 'import'),
                    'value': 1
                })
        
        return json.dumps(d3_data, indent=2)
    
    def _get_node_group(self, node: Dict[str, Any]) -> int:
        """Assign group number for D3 coloring."""
        if node['type'] == 'external':
            return 1
        elif node['type'] == 'stdlib':
            return 2
        elif node.get('out_degree', 0) > 10:
            return 3  # God module
        elif node.get('in_degree', 0) > 10:
            return 4  # Hub module
        else:
            return 0  # Normal
    
    def _calculate_node_size(self, node: Dict[str, Any]) -> int:
        """Calculate node size based on connections."""
        total_degree = node.get('in_degree', 0) + node.get('out_degree', 0)
        return min(5 + total_degree * 2, 50)  # Size between 5 and 50
    
    def _generate_graphviz(self, graph_data: Dict[str, Any]) -> str:
        """Generate Graphviz DOT format."""
        lines = ['digraph dependencies {']
        lines.append('    rankdir=TB;')
        lines.append('    node [shape=box, style=filled];')
        
        # Group nodes by type
        groups = defaultdict(list)
        for node in graph_data['nodes']:
            groups[node['type']].append(node)
        
        # Add nodes by group
        for group_type, nodes in groups.items():
            if nodes:
                lines.append(f'    subgraph cluster_{group_type} {{')
                lines.append(f'        label="{group_type.title()}";')
                
                for node in nodes:
                    color = self.color_schemes['module_type'][group_type]
                    lines.append(
                        f'        "{node["id"]}" [label="{node["label"]}", '
                        f'fillcolor="{color}", fontcolor="white"];'
                    )
                
                lines.append('    }')
        
        # Add edges
        for edge in graph_data['edges']:
            style = 'dashed' if edge.get('type') == 'dynamic' else 'solid'
            lines.append(
                f'    "{edge["source"]}" -> "{edge["target"]}" [style={style}];'
            )
        
        lines.append('}')
        return '\n'.join(lines)
    
    def _generate_interactive_graph(self, graph_data: Dict[str, Any]) -> str:
        """Generate interactive graph using pyvis."""
        net = Network(height='750px', width='100%', directed=True)
        
        # Configure physics
        net.set_options('''
        var options = {
            "physics": {
                "enabled": true,
                "solver": "barnesHut",
                "barnesHut": {
                    "gravitationalConstant": -8000,
                    "springConstant": 0.001,
                    "springLength": 200
                }
            },
            "nodes": {
                "font": {
                    "size": 12
                }
            },
            "edges": {
                "smooth": {
                    "type": "continuous"
                }
            }
        }
        ''')
        
        # Add nodes
        for node in graph_data['nodes']:
            color = self.color_schemes['module_type'][node['type']]
            size = self._calculate_node_size(node)
            
            net.add_node(
                node['id'],
                label=node['label'],
                color=color,
                size=size,
                title=f"{node['id']}\nIn: {node.get('in_degree', 0)}, "
                      f"Out: {node.get('out_degree', 0)}"
            )
        
        # Add edges
        for edge in graph_data['edges']:
            net.add_edge(
                edge['source'],
                edge['target'],
                title=edge.get('type', 'import')
            )
        
        # Generate HTML
        return net.generate_html()
    
    def generate_complexity_heatmap(
        self,
        project_path: Path,
        metrics: Dict[str, Dict[str, float]],
        output_path: Optional[Path] = None
    ) -> Optional[Path]:
        """Generate complexity heatmap for project files."""
        # Prepare data for heatmap
        files = []
        complexity_values = []
        
        for file_path, file_metrics in metrics.items():
            files.append(Path(file_path).name)
            complexity_values.append(file_metrics.get('complexity', 0))
        
        if not files:
            return None
        
        # Create figure
        plt.figure(figsize=(12, max(6, len(files) * 0.3)))
        
        # Create heatmap data
        data = [[val] for val in complexity_values]
        
        # Create heatmap
        sns.heatmap(
            data,
            yticklabels=files,
            xticklabels=['Complexity'],
            annot=True,
            fmt='.1f',
            cmap='RdYlGn_r',
            cbar_kws={'label': 'Cyclomatic Complexity'},
            vmin=0,
            vmax=30
        )
        
        plt.title('Code Complexity Heatmap')
        plt.tight_layout()
        
        # Save or display
        if output_path:
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            return output_path
        else:
            plt.show()
            return None
    
    def generate_metrics_dashboard(
        self,
        analysis_results: Dict[str, Any],
        output_format: str = 'html'
    ) -> str:
        """Generate comprehensive metrics dashboard."""
        
        if output_format == 'html':
            return self._generate_html_dashboard(analysis_results)
        elif output_format == 'markdown':
            return self._generate_markdown_dashboard(analysis_results)
        else:
            raise ValueError(f"Unsupported dashboard format: {output_format}")
    
    def _generate_html_dashboard(self, results: Dict[str, Any]) -> str:
        """Generate HTML dashboard with charts."""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Code Analysis Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .metric {{
            display: inline-block;
            margin: 10px 20px;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            color: #007bff;
        }}
        .metric-label {{
            color: #666;
            font-size: 0.9em;
        }}
        .chart-container {{
            position: relative;
            height: 400px;
            margin: 20px 0;
        }}
        .severity-critical {{ color: #dc3545; }}
        .severity-high {{ color: #fd7e14; }}
        .severity-medium {{ color: #ffc107; }}
        .severity-low {{ color: #28a745; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Code Analysis Dashboard</h1>
        
        <div class="card">
            <h2>Overview</h2>
            <div class="metrics">
                <div class="metric">
                    <div class="metric-value">{results.get('total_files', 0)}</div>
                    <div class="metric-label">Files Analyzed</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{results.get('total_issues', 0)}</div>
                    <div class="metric-label">Total Issues</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{results.get('average_complexity', 0):.1f}</div>
                    <div class="metric-label">Avg Complexity</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{results.get('code_quality_score', 0):.1f}</div>
                    <div class="metric-label">Quality Score</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>Issue Distribution</h2>
            <div class="chart-container">
                <canvas id="issueChart"></canvas>
            </div>
        </div>
        
        <div class="card">
            <h2>Complexity Distribution</h2>
            <div class="chart-container">
                <canvas id="complexityChart"></canvas>
            </div>
        </div>
        
        <div class="card">
            <h2>Top Issues</h2>
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <th style="text-align: left; padding: 10px; border-bottom: 1px solid #ddd;">File</th>
                    <th style="text-align: left; padding: 10px; border-bottom: 1px solid #ddd;">Issue</th>
                    <th style="text-align: left; padding: 10px; border-bottom: 1px solid #ddd;">Severity</th>
                    <th style="text-align: left; padding: 10px; border-bottom: 1px solid #ddd;">Line</th>
                </tr>
                {self._generate_issue_rows(results.get('top_issues', []))}
            </table>
        </div>
    </div>
    
    <script>
        // Issue distribution chart
        const issueCtx = document.getElementById('issueChart').getContext('2d');
        new Chart(issueCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Security', 'Quality', 'Complexity', 'Dead Code'],
                datasets: [{{
                    data: {json.dumps(self._get_issue_distribution(results))},
                    backgroundColor: ['#dc3545', '#ffc107', '#fd7e14', '#6c757d']
                }}]
            }}
        }});
        
        // Complexity distribution chart
        const complexityCtx = document.getElementById('complexityChart').getContext('2d');
        new Chart(complexityCtx, {{
            type: 'bar',
            data: {{
                labels: {json.dumps(self._get_complexity_labels(results))},
                datasets: [{{
                    label: 'Cyclomatic Complexity',
                    data: {json.dumps(self._get_complexity_values(results))},
                    backgroundColor: {json.dumps(self._get_complexity_colors(results))}
                }}]
            }},
            options: {{
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>
"""
        return html
    
    def _generate_issue_rows(self, issues: List[Dict[str, Any]]) -> str:
        """Generate HTML table rows for issues."""
        rows = []
        for issue in issues[:10]:  # Top 10
            severity_class = f"severity-{issue['severity'].lower()}"
            rows.append(f"""
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #eee;">{issue['file']}</td>
                    <td style="padding: 10px; border-bottom: 1px solid #eee;">{issue['message']}</td>
                    <td style="padding: 10px; border-bottom: 1px solid #eee;" class="{severity_class}">{issue['severity']}</td>
                    <td style="padding: 10px; border-bottom: 1px solid #eee;">{issue['line']}</td>
                </tr>
            """)
        return ''.join(rows)
    
    def _get_issue_distribution(self, results: Dict[str, Any]) -> List[int]:
        """Get issue counts by category."""
        return [
            results.get('security_issues', 0),
            results.get('quality_issues', 0),
            results.get('complexity_issues', 0),
            results.get('dead_code_issues', 0)
        ]
    
    def _get_complexity_labels(self, results: Dict[str, Any]) -> List[str]:
        """Get file labels for complexity chart."""
        files = results.get('file_complexities', {})
        return [Path(f).name for f in list(files.keys())[:20]]  # Top 20
    
    def _get_complexity_values(self, results: Dict[str, Any]) -> List[float]:
        """Get complexity values for chart."""
        files = results.get('file_complexities', {})
        return [v for v in list(files.values())[:20]]
    
    def _get_complexity_colors(self, results: Dict[str, Any]) -> List[str]:
        """Get colors based on complexity values."""
        values = self._get_complexity_values(results)
        colors = []
        
        for val in values:
            if val > 20:
                colors.append('#dc3545')  # Red
            elif val > 10:
                colors.append('#fd7e14')  # Orange
            elif val > 5:
                colors.append('#ffc107')  # Yellow
            else:
                colors.append('#28a745')  # Green
        
        return colors
    
    def _generate_markdown_dashboard(self, results: Dict[str, Any]) -> str:
        """Generate Markdown dashboard."""
        md = f"""# Code Analysis Report

Generated: {results.get('timestamp', 'N/A')}

## 📊 Overview

| Metric | Value |
|--------|-------|
| Files Analyzed | {results.get('total_files', 0)} |
| Total Issues | {results.get('total_issues', 0)} |
| Average Complexity | {results.get('average_complexity', 0):.1f} |
| Quality Score | {results.get('code_quality_score', 0):.1f}/100 |
| Security Score | {results.get('security_score', 0):.1f}/100 |

## 🔍 Issue Summary

### By Severity
- 🔴 Critical: {results.get('critical_issues', 0)}
- 🟠 High: {results.get('high_issues', 0)}
- 🟡 Medium: {results.get('medium_issues', 0)}
- 🟢 Low: {results.get('low_issues', 0)}

### By Category
- 🔒 Security: {results.get('security_issues', 0)}
- 📏 Quality: {results.get('quality_issues', 0)}
- 🧮 Complexity: {results.get('complexity_issues', 0)}
- 🧹 Dead Code: {results.get('dead_code_issues', 0)}

## 📈 Top Complex Files

| File | Complexity | Risk Level |
|------|------------|------------|
"""
       
        # Add top complex files
        complex_files = results.get('complex_files', [])
        for file_info in complex_files[:10]:
            risk_emoji = self._get_risk_emoji(file_info['complexity'])
            md += f"| {file_info['file']} | {file_info['complexity']} | {risk_emoji} |\n"
       
        md += f"""
## 🔄 Circular Dependencies

Found {len(results.get('circular_dependencies', []))} circular dependency chains.

"""
       
        # Add circular dependencies
        for i, cycle in enumerate(results.get('circular_dependencies', [])[:5]):
            md += f"{i+1}. {' → '.join(cycle)} → {cycle[0]}\n"
       
        md += """
## 💡 Recommendations

"""
       
        # Add recommendations
        for i, rec in enumerate(results.get('recommendations', [])[:10]):
            md += f"{i+1}. {rec}\n"
       
        return md
   
    def _get_risk_emoji(self, complexity: float) -> str:
        """Get risk emoji based on complexity."""
        if complexity > 20:
            return "🔴 Very High"
        elif complexity > 10:
            return "🟠 High"
        elif complexity > 5:
            return "🟡 Medium"
        else:
            return "🟢 Low"


class TreemapVisualizer:
   """Generate treemap visualizations for code metrics."""
   
   def __init__(self):
       import plotly.graph_objects as go
       self.go = go
   
   def generate_complexity_treemap(
       self,
       file_metrics: Dict[str, Dict[str, Any]],
       output_path: Optional[Path] = None
   ) -> str:
       """Generate treemap showing file sizes and complexity."""
       
       # Prepare data
       labels = []
       parents = []
       values = []
       colors = []
       
       # Group files by directory
       dir_sizes = defaultdict(float)
       dir_complexities = defaultdict(list)
       
       for file_path, metrics in file_metrics.items():
           path = Path(file_path)
           
           # Add file
           labels.append(path.name)
           parents.append(str(path.parent))
           values.append(metrics.get('loc', 0))
           colors.append(metrics.get('complexity', 0))
           
           # Track directory metrics
           for parent in path.parents:
               if parent != Path('.'):
                   dir_sizes[str(parent)] += metrics.get('loc', 0)
                   dir_complexities[str(parent)].append(metrics.get('complexity', 0))
       
       # Add directories
       for dir_path, size in dir_sizes.items():
           labels.append(dir_path)
           parent = str(Path(dir_path).parent) if Path(dir_path).parent != Path('.') else ""
           parents.append(parent)
           values.append(size)
           
           # Average complexity for directory
           avg_complexity = sum(dir_complexities[dir_path]) / len(dir_complexities[dir_path])
           colors.append(avg_complexity)
       
       # Create treemap
       fig = self.go.Figure(self.go.Treemap(
           labels=labels,
           parents=parents,
           values=values,
           marker=dict(
               colorscale='RdYlGn_r',
               cmid=10,
               colorbar=dict(title="Complexity"),
               showscale=True
           ),
           text=[f"LOC: {v}<br>Complexity: {c:.1f}" 
                 for v, c in zip(values, colors)],
           textinfo="label+text",
           hovertemplate='<b>%{label}</b><br>Size: %{value} LOC<br>Complexity: %{color:.1f}<extra></extra>'
       ))
       
       fig.update_layout(
           title="Code Complexity Treemap",
           width=1200,
           height=800
       )
       
       if output_path:
           fig.write_html(str(output_path))
           return str(output_path)
       else:
           return fig.to_html()