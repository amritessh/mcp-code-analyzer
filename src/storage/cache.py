import json
import os
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from config import settings
from utils.logger import logger
import aiofiles

class FileCache:
    """Simple file-based cache for analysis results."""
    
    def __init__(self):
        self.cache_dir = settings.cache_dir
        self.cache_dir.mkdir(exist_ok=True)
        self.ttl = timedelta(seconds=settings.cache_ttl)
    
    def _get_file_hash(self, file_path: Path) -> str:
        """Calculate hash of file content."""
        hasher = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        
        # Include modification time for cache invalidation
        mtime = str(file_path.stat().st_mtime)
        hasher.update(mtime.encode())
        
        return hasher.hexdigest()
    
    def _get_cache_path(self, file_path: Path, analysis_type: str) -> Path:
        """Get cache file path for given file and analysis type."""
        file_hash = self._get_file_hash(file_path)
        cache_name = f"{file_hash}_{analysis_type}.json"
        return self.cache_dir / cache_name
    
    async def get(
        self, 
        file_path: Path, 
        analysis_type: str
    ) -> Optional[Dict[str, Any]]:
        """Get cached analysis result."""
        if not settings.enable_cache:
            return None
        
        cache_path = self._get_cache_path(file_path, analysis_type)
        
        if not cache_path.exists():
            return None
        
        try:
            async with aiofiles.open(cache_path, 'r') as f:
                data = json.loads(await f.read())
            
            # Check TTL
            cached_time = datetime.fromisoformat(data['cached_at'])
            if datetime.now() - cached_time > self.ttl:
                logger.debug(f"Cache expired for {file_path}")
                cache_path.unlink()
                return None
            
            logger.debug(f"Cache hit for {file_path}")
            return data['result']
            
        except Exception as e:
            logger.error(f"Error reading cache: {e}")
            return None
    
    async def set(
        self, 
        file_path: Path, 
        analysis_type: str, 
        result: Dict[str, Any]
    ) -> None:
        """Cache analysis result."""
        if not settings.enable_cache:
            return
        
        cache_path = self._get_cache_path(file_path, analysis_type)
        
        data = {
            'file_path': str(file_path),
            'analysis_type': analysis_type,
            'cached_at': datetime.now().isoformat(),
            'result': result
        }
        
        try:
            async with aiofiles.open(cache_path, 'w') as f:
                await f.write(json.dumps(data, indent=2))
            
            logger.debug(f"Cached result for {file_path}")
            
        except Exception as e:
            logger.error(f"Error writing cache: {e}")
    
    async def clear(self) -> int:
        """Clear all cache files."""
        count = 0
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()
            count += 1
        
        logger.info(f"Cleared {count} cache files")
        return count
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        cache_files = list(self.cache_dir.glob("*.json"))
        total_size = sum(f.stat().st_size for f in cache_files)
        
        return {
            'cache_files': len(cache_files),
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / 1024 / 1024, 2),
            'cache_dir': str(self.cache_dir)
        }