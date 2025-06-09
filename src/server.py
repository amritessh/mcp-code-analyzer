# src/server.py
import asyncio
from typing import Dict, Any, List
from pathlib import Path
import json

from mcp import Server
from mcp.server import stdio
from mcp.types import Tool, TextContent, ImageContent, EmbeddedResource

from .config import settings
from .utils.logger import logger
from .analyzers.basic import BasicAnalyzer

# Initialize server
server = Server(settings.server_name)
logger.info(f"Initializing {settings.server_name} MCP server")

# Initialize analyzer
analyzer = BasicAnalyzer()

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools."""
    return [
        Tool(
            name="analyze_file",
            description="Analyze a single file for basic metrics",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the file to analyze"
                    }
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="get_complexity",
            description="Get complexity metrics for a Python file",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the Python file"
                    },
                    "include_details": {
                        "type": "boolean",
                        "description": "Include detailed breakdown",
                        "default": False
                    }
                },
                "required": ["file_path"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls."""
    try:
        logger.info(f"Tool called: {name} with args: {arguments}")
        
        if name == "analyze_file":
            result = await analyze_file_handler(arguments["file_path"])
        elif name == "get_complexity":
            result = await get_complexity_handler(
                arguments["file_path"],
                arguments.get("include_details", False)
            )
        else:
            result = f"Unknown tool: {name}"
        
        return [TextContent(type="text", text=result)]
        
    except Exception as e:
        logger.error(f"Error in tool {name}: {str(e)}")
        return [TextContent(
            type="text", 
            text=f"Error: {str(e)}"
        )]

async def analyze_file_handler(file_path: str) -> str:
    """Handle file analysis requests."""
    try:
        path = Path(file_path)
        
        # Validate file
        if not path.exists():
            return f"❌ File not found: {file_path}"
        
        if not path.is_file():
            return f"❌ Not a file: {file_path}"
        
        # Check file size
        file_size = path.stat().st_size
        if file_size > settings.max_file_size:
            return f"❌ File too large: {file_size} bytes (max: {settings.max_file_size})"
        
        # Analyze file
        result = await analyzer.analyze_basic(path)
        
        # Format output
        return format_basic_analysis(result)
        
    except Exception as e:
        logger.error(f"Error analyzing {file_path}: {e}")
        return f"❌ Error analyzing file: {str(e)}"

async def get_complexity_handler(file_path: str, include_details: bool) -> str:
    """Handle complexity analysis requests."""
    try:
        path = Path(file_path)
        
        # Validate Python file
        if not path.suffix == '.py':
            return f"❌ Not a Python file: {file_path}"
        
        if not path.exists():
            return f"❌ File not found: {file_path}"
        
        # Get complexity
        result = await analyzer.analyze_complexity(path, include_details)
        
        # Format output
        return format_complexity_analysis(result)
        
    except Exception as e:
        logger.error(f"Error getting complexity for {file_path}: {e}")
        return f"❌ Error analyzing complexity: {str(e)}"

def format_basic_analysis(result: Dict[str, Any]) -> str:
    """Format basic analysis results."""
    return f"""📊 File Analysis Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 File: {result['file_path']}
📏 Size: {result['size_bytes']:,} bytes
🔤 Language: {result['language']}

📈 Basic Metrics:
  • Lines of Code: {result['metrics']['loc']}
  • Total Lines: {result['metrics']['total_lines']}
  • Blank Lines: {result['metrics']['blank_lines']}
  • Comment Lines: {result['metrics']['comment_lines']}
  
📋 Code Elements:
  • Functions: {result['metrics'].get('functions', 'N/A')}
  • Classes: {result['metrics'].get('classes', 'N/A')}
  • Imports: {result['metrics'].get('imports', 'N/A')}
"""

def format_complexity_analysis(result: Dict[str, Any]) -> str:
    """Format complexity analysis results."""
    output = f"""🧮 Complexity Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 File: {result['file_path']}

📊 Overall Metrics:
  • Average Complexity: {result['average_complexity']:.2f}
  • Max Complexity: {result['max_complexity']}
  • Total Complexity: {result['total_complexity']}
  • Risk Level: {result['risk_level']}
"""
    
    if result.get('details'):
        output += "\n🔍 Detailed Breakdown:\n"
        for item in result['details'][:10]:  # Top 10
            output += f"  • {item['name']}: {item['complexity']} "
            output += f"({item['type']}) - {item['risk_level']}\n"
        
        if len(result['details']) > 10:
            output += f"  ... and {len(result['details']) - 10} more\n"
    
    return output

async def main():
    """Main entry point."""
    logger.info("Starting MCP Code Analyzer Server")
    async with stdio.stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream)

if __name__ == "__main__":
    asyncio.run(main())