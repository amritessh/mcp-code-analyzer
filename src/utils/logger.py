# src/utils/logger.py
import logging
from rich.logging import RichHandler
from pathlib import Path

def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    """Set up a logger with rich formatting."""
    
    # Create logs directory
    Path("logs").mkdir(exist_ok=True)
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Console handler with Rich
    console_handler = RichHandler(
        rich_tracebacks=True,
        markup=True
    )
    console_handler.setLevel(level)
    
    # File handler
    file_handler = logging.FileHandler(f"logs/{name}.log")
    file_handler.setLevel(logging.DEBUG)
    
    # Formatter for file
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    
    # Add handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger

# Global logger instance
logger = setup_logger("code-analyzer")