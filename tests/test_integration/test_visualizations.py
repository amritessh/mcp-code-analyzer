
# tests/test_integration/test_visualizations.py
import pytest
from src.utils.visualizer import DependencyVisualizer

def test_mermaid_generation():
    """Test Mermaid diagram generation."""
    visualizer = DependencyVisualizer()
    
    graph_data = {
        'nodes': [
            {'id': 'module_a', 'label': 'Module A', 'type': 'internal'},
            {'id': 'module_b', 'label': 'Module B', 'type': 'internal'},
            {'id': 'external_lib', 'label': 'External', 'type': 'external'}
        ],
        'edges': [
            {'source': 'module_a', 'target': 'module_b', 'type': 'import'},
            {'source': 'module_a', 'target': 'external_lib', 'type': 'import'}
        ]
    }
    
    diagram = visualizer.generate_dependency_graph(
        graph_data,
        output_format='mermaid'
    )
    
    assert 'graph' in diagram
    assert 'module_a' in diagram
    assert 'module_b' in diagram
    assert '-->' in diagram  # Edge indicator

def test_d3_data_generation():
    """Test D3.js data generation."""
    visualizer = DependencyVisualizer()
    
    graph_data = {
        'nodes': [
            {'id': 'a', 'label': 'A', 'type': 'internal', 'in_degree': 0, 'out_degree': 1},
            {'id': 'b', 'label': 'B', 'type': 'internal', 'in_degree': 1, 'out_degree': 0}
        ],
        'edges': [
            {'source': 'a', 'target': 'b', 'type': 'import'}
        ]
    }
    
    d3_json = visualizer.generate_dependency_graph(
        graph_data,
        output_format='d3'
    )
    
    import json
    d3_data = json.loads(d3_json)
    
    assert 'nodes' in d3_data
    assert 'links' in d3_data
    assert len(d3_data['nodes']) == 2
    assert len(d3_data['links']) == 1