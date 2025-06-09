from pydantic import BaseSettings, Field
from typing import Optional, List
from pathlib import Path

class Settings(BaseSettings):
    """Application settings."""
    
    # Server settings
    server_name: str = "code-analyzer"
    host: str = "localhost"
    port: int = 3000
    
    # Analysis settings
    max_file_size: int = Field(default=1_048_576, description="Max file size in bytes (1MB)")
    supported_extensions: List[str] = [".py", ".js", ".ts", ".java", ".go"]
    
    # Complexity thresholds
    complexity_thresholds: dict = {
        "low": 5,
        "medium": 10,
        "high": 20,
        "very_high": 30
    }
    
    # Cache settings
    enable_cache: bool = True
    cache_ttl: int = 3600  # 1 hour
    cache_dir: Path = Path(".cache")
    
    # Output settings
    pretty_print: bool = True
    include_metrics_details: bool = True
    
    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'

settings = Settings()
