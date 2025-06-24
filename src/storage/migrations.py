# src/storage/migrations.py
import sqlite3
import os
from pathlib import Path
from typing import List, Dict, Any
from utils.logger import logger

class MigrationManager:
    """Manage database schema migrations."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.migrations = self._get_migrations()
    
    def _get_migrations(self) -> List[Callable]:
        """Get list of migration functions."""
        return [
            self._migration_001_add_project_metadata,
            self._migration_002_add_code_duplication,
            # Add new migrations here
        ]
    
    def run_migrations(self):
        """Run all pending migrations."""
        with sqlite3.connect(self.db_path) as conn:
            # Create migrations table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Get current version
            cursor = conn.cursor()
            cursor.execute('SELECT MAX(version) FROM schema_migrations')
            current_version = cursor.fetchone()[0] or 0
            
            # Run pending migrations
            for i, migration in enumerate(self.migrations[current_version:], 
                                        start=current_version + 1):
                logger.info(f"Running migration {i}")
                migration(conn)
                
                # Record migration
                conn.execute(
                    'INSERT INTO schema_migrations (version) VALUES (?)',
                    (i,)
                )
            
            conn.commit()
    
    def _migration_001_add_project_metadata(self, conn: sqlite3.Connection):
        """Add project metadata table."""
        conn.execute('''
            CREATE TABLE IF NOT EXISTS project_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_path TEXT UNIQUE NOT NULL,
                project_name TEXT,
                description TEXT,
                language_stats TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
    
    def _migration_002_add_code_duplication(self, conn: sqlite3.Connection):
        """Add code duplication tracking."""
        conn.execute('''
            CREATE TABLE IF NOT EXISTS code_duplications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path_1 TEXT NOT NULL,
                line_start_1 INTEGER NOT NULL,
                line_end_1 INTEGER NOT NULL,
                file_path_2 TEXT NOT NULL,
                line_start_2 INTEGER NOT NULL,
                line_end_2 INTEGER NOT NULL,
                similarity_score REAL,
                code_hash TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')