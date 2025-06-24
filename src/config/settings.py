import os
from pathlib import Path
from typing import Dict, Any, Optional
import json

class Settings:
    """Configuration settings for the MCP Code Analyzer."""
    
    def __init__(self):
        self.config_file = Path(".analysis-config.json")
        self.load_config()
    
    def load_config(self):
        """Load configuration from file or use defaults."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                self._update_from_dict(config_data)
            except Exception as e:
                print(f"Warning: Could not load config file: {e}")
                self._set_defaults()
        else:
            self._set_defaults()
    
    def _set_defaults(self):
        """Set default configuration values."""
        self.analysis_depth = 3
        self.max_file_size = 1024 * 1024  # 1MB
        self.include_hidden = False
        self.exclude_patterns = [
            "*.pyc", "*.pyo", "__pycache__", ".git", ".svn", 
            "node_modules", "venv", ".venv", "env", ".env"
        ]
        self.security_scan_enabled = True
        self.quality_scan_enabled = True
        self.complexity_scan_enabled = True
        self.dependency_scan_enabled = True
        self.github_integration_enabled = True
        self.database_path = "analysis.db"
        self.cache_enabled = True
        self.cache_ttl = 3600  # 1 hour
        self.log_level = "INFO"
        self.output_format = "console"
        self.visualization_enabled = True
        
        # Security settings
        self.security_rules = {
            "sql_injection": True,
            "xss": True,
            "command_injection": True,
            "path_traversal": True,
            "hardcoded_secrets": True
        }
        
        # Quality settings
        self.quality_thresholds = {
            "max_complexity": 10,
            "max_function_length": 50,
            "max_line_length": 120,
            "min_test_coverage": 80
    }
    
        # GitHub settings
        self.github_rate_limit = 5000
        self.github_timeout = 30
        
        # Visualization settings
        self.graph_max_nodes = 100
        self.graph_max_edges = 200
    
    def _update_from_dict(self, config_data: Dict[str, Any]):
        """Update settings from dictionary."""
        for key, value in config_data.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    def save_config(self):
        """Save current configuration to file."""
        config_data = {}
        for key in dir(self):
            if not key.startswith('_') and not callable(getattr(self, key)):
                config_data[key] = getattr(self, key)
        
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save config file: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with default."""
        return getattr(self, key, default)
    
    def set(self, key: str, value: Any):
        """Set configuration value."""
        setattr(self, key, value)
    
    def update(self, **kwargs):
        """Update multiple configuration values."""
        for key, value in kwargs.items():
            self.set(key, value)

# Global settings instance
settings = Settings()
