# src/storage/database.py
import sqlite3
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
import asyncio
from contextlib import asynccontextmanager
import threading

from utils.logger import logger
from config import settings

class AnalysisDatabase:
    """SQLite database for storing analysis results."""
    
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or settings.cache_dir / "analysis.db"
        self.db_path.parent.mkdir(exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path, check_same_thread=False) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS file_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    analysis_type TEXT NOT NULL,
                    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    results TEXT NOT NULL,
                    UNIQUE(file_path, file_hash, analysis_type)
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS security_issues (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    line_number INTEGER,
                    message TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    resolved BOOLEAN DEFAULT FALSE,
                    resolved_at TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS quality_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL,
                    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS todo_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    todo_type TEXT NOT NULL,
                    message TEXT,
                    line_number INTEGER,
                    author TEXT,
                    priority TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed BOOLEAN DEFAULT FALSE
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS analysis_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_path TEXT,
                    analysis_type TEXT NOT NULL,
                    total_files INTEGER,
                    total_issues INTEGER,
                    duration_seconds REAL,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    summary TEXT
                )
            ''')
            
            # Create indexes
            conn.execute('CREATE INDEX IF NOT EXISTS idx_file_path ON file_analysis(file_path)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_security_severity ON security_issues(severity)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_todo_priority ON todo_items(priority)')
            
            conn.commit()
    
    @asynccontextmanager
    async def get_connection(self):
        """Get database connection."""
        loop = asyncio.get_event_loop()
        
        def create_connection():
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            return conn
        
        conn = await loop.run_in_executor(None, create_connection)
        try:
            yield conn
        finally:
            await loop.run_in_executor(None, conn.close)
    
    async def save_analysis(
        self,
        file_path: str,
        file_hash: str,
        analysis_type: str,
        results: Dict[str, Any]
    ) -> int:
        """Save analysis results."""
        async with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Upsert analysis results
            cursor.execute('''
                INSERT OR REPLACE INTO file_analysis 
                (file_path, file_hash, analysis_type, results)
                VALUES (?, ?, ?, ?)
            ''', (file_path, file_hash, analysis_type, json.dumps(results)))
            
            conn.commit()
            return cursor.lastrowid
    
    async def get_analysis(
        self,
        file_path: str,
        file_hash: str,
        analysis_type: str
    ) -> Optional[Dict[str, Any]]:
        """Get cached analysis results."""
        async with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT results, analyzed_at 
                FROM file_analysis
                WHERE file_path = ? AND file_hash = ? AND analysis_type = ?
            ''', (file_path, file_hash, analysis_type))
            
            row = cursor.fetchone()
            if row:
                return {
                    'results': json.loads(row['results']),
                    'analyzed_at': row['analyzed_at']
                }
            return None
    
    async def save_security_issues(
        self,
        issues: List[Dict[str, Any]]
    ) -> None:
        """Save security issues."""
        async with self.get_connection() as conn:
            cursor = conn.cursor()
            
            for issue in issues:
                cursor.execute('''
                    INSERT INTO security_issues
                    (file_path, rule_id, severity, line_number, message)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    issue['location']['file'],
                    issue['rule_id'],
                    issue['severity'],
                    issue['location']['line'],
                    issue['message']
                ))
            
            conn.commit()
    
    async def save_quality_metrics(
        self,
        file_path: str,
        metrics: Dict[str, float]
    ) -> None:
        """Save quality metrics."""
        async with self.get_connection() as conn:
            cursor = conn.cursor()
            
            for metric_name, metric_value in metrics.items():
                cursor.execute('''
                    INSERT INTO quality_metrics
                    (file_path, metric_name, metric_value)
                    VALUES (?, ?, ?)
                ''', (file_path, metric_name, metric_value))
            
            conn.commit()
    
    async def save_todo_items(
        self,
        todos: List[Dict[str, Any]]
    ) -> None:
        """Save TODO items."""
        async with self.get_connection() as conn:
            cursor = conn.cursor()
            
            for todo in todos:
                cursor.execute('''
                    INSERT INTO todo_items
                    (file_path, todo_type, message, line_number, author, priority)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    todo['location']['file'],
                    todo['type'],
                    todo['message'],
                    todo['location']['line'],
                    todo.get('metadata', {}).get('author'),
                    todo.get('metadata', {}).get('priority', 'medium')
                ))
            
            conn.commit()
    
    async def get_project_history(
        self,
        project_path: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get analysis history for a project."""
        async with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM analysis_history
                WHERE project_path = ?
                ORDER BY completed_at DESC
                LIMIT ?
            ''', (project_path, limit))
            
            return [dict(row) for row in cursor.fetchall()]
    
    async def get_trending_issues(
        self,
        days: int = 7
    ) -> Dict[str, Any]:
        """Get trending security and quality issues."""
        async with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Top security issues
            cursor.execute('''
                SELECT rule_id, severity, COUNT(*) as count
                FROM security_issues
                WHERE detected_at > datetime('now', '-' || ? || ' days')
                GROUP BY rule_id, severity
                ORDER BY count DESC
                LIMIT 10
            ''', (days,))
            
            security_trends = [dict(row) for row in cursor.fetchall()]
            
            # Quality metrics trends
            cursor.execute('''
                SELECT metric_name, AVG(metric_value) as avg_value
                FROM quality_metrics
                WHERE recorded_at > datetime('now', '-' || ? || ' days')
                GROUP BY metric_name
            ''', (days,))
            
            quality_trends = [dict(row) for row in cursor.fetchall()]
            
            return {
                'security_trends': security_trends,
                'quality_trends': quality_trends
            }
    
    async def cleanup_old_data(self, days: int = 30) -> int:
        """Clean up old analysis data."""
        async with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Delete old analysis results
            cursor.execute('''
                DELETE FROM file_analysis
                WHERE analyzed_at < datetime('now', '-' || ? || ' days')
            ''', (days,))
            
            deleted = cursor.rowcount
            conn.commit()
            
            logger.info(f"Cleaned up {deleted} old analysis records")
            return deleted