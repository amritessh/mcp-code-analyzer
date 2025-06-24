# src/server.py (updated)
from .analyzers.security import SecurityAnalyzer
from .analyzers.quality import QualityAnalyzer
from .analyzers.todo_tracker import TodoTracker
from .analyzers.dead_code import DeadCodeDetector
from .storage.database import AnalysisDatabase

# Initialize new analyzers
security_analyzer = SecurityAnalyzer()
quality_analyzer = QualityAnalyzer()
todo_tracker = TodoTracker()
dead_code_detector = DeadCodeDetector()
database = AnalysisDatabase()

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools - updated with Week 2 tools."""
    return [
        # Week 1 tools
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
        ),
        # Week 2 tools
        Tool(
            name="scan_security",
            description="Scan file for security vulnerabilities",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to scan"
                    },
                    "rules": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific rules to apply"
                    },
                    "include_info": {
                        "type": "boolean",
                        "description": "Include informational findings",
                        "default": False
                    }
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="check_quality",
            description="Check code quality and detect code smells",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to check"
                    },
                    "standards": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Quality standards to apply"
                    }
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="find_todos",
            description="Find TODO, FIXME, and other code comments",
            inputSchema={
                "type": "object",
                "properties": {
                    "directory": {
                        "type": "string",
                        "description": "Directory to search"
                    },
                    "include_patterns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Patterns to include (TODO, FIXME, etc.)"
                    }
                },
                "required": ["directory"]
            }
        ),
        Tool(
            name="detect_dead_code",
            description="Find unused code, imports, and variables",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "File to analyze"
                    }
                },
                "required": ["file_path"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls - updated with Week 2 handlers."""
    try:
        logger.info(f"Tool called: {name} with args: {arguments}")
        
        # Week 1 tools
        if name == "analyze_file":
            result = await analyze_file_handler(arguments["file_path"])
        elif name == "get_complexity":
            result = await get_complexity_handler(
                arguments["file_path"],
                arguments.get("include_details", False)
            )
        # Week 2 tools
        elif name == "scan_security":
            result = await scan_security_handler(
                arguments["file_path"],
                arguments.get("rules"),
                arguments.get("include_info", False)
            )
        elif name == "check_quality":
            result = await check_quality_handler(
                arguments["file_path"],
                arguments.get("standards")
            )
        elif name == "find_todos":
            result = await find_todos_handler(
                arguments["directory"],
                arguments.get("include_patterns")
            )
        elif name == "detect_dead_code":
            result = await detect_dead_code_handler(arguments["file_path"])
        else:
            result = f"Unknown tool: {name}"
        
        return [TextContent(type="text", text=result)]
        
    except Exception as e:
        logger.error(f"Error in tool {name}: {str(e)}")
        return [TextContent(
            type="text", 
            text=f"Error: {str(e)}"
        )]

# Week 2 handlers
async def scan_security_handler(
    file_path: str,
    rules: Optional[List[str]],
    include_info: bool
) -> str:
    """Handle security scanning requests."""
    try:
        path = Path(file_path)
        
        if not path.exists():
            return f"❌ File not found: {file_path}"
        
        # Run security scan
        result = await security_analyzer.scan_security(
            path, 
            rules, 
            include_info
        )
        
        # Save to database
        if result['issues']:
            await database.save_security_issues(result['issues'])
        
        # Format output
        return format_security_results(result)
        
    except Exception as e:
        logger.error(f"Error scanning security: {e}")
        return f"❌ Error during security scan: {str(e)}"

async def check_quality_handler(
    file_path: str,
    standards: Optional[List[str]]
) -> str:
    """Handle quality check requests."""
    try:
        path = Path(file_path)
        
        if not path.exists():
            return f"❌ File not found: {file_path}"
        
        # Run quality check
        result = await quality_analyzer.check_quality(path, standards)
        
        # Save metrics to database
        if result.get('metrics'):
            await database.save_quality_metrics(
                str(path), 
                result['metrics']
            )
        
        # Format output
        return format_quality_results(result)
        
    except Exception as e:
        logger.error(f"Error checking quality: {e}")
        return f"❌ Error during quality check: {str(e)}"

async def find_todos_handler(
    directory: str,
    include_patterns: Optional[List[str]]
) -> str:
    """Handle TODO finding requests."""
    try:
        path = Path(directory)
        
        if not path.exists():
            return f"❌ Directory not found: {directory}"
        
        # Find TODOs
        result = await todo_tracker.find_todos(
            path,
            include_patterns,
            recursive=True
        )
        
        # Save to database
        if result['items']:
            await database.save_todo_items(result['items'])
        
        # Format output
        return format_todo_results(result)
        
    except Exception as e:
        logger.error(f"Error finding TODOs: {e}")
        return f"❌ Error during TODO search: {str(e)}"

async def detect_dead_code_handler(file_path: str) -> str:
    """Handle dead code detection requests."""
    try:
        path = Path(file_path)
        
        if not path.exists():
            return f"❌ File not found: {file_path}"
        
        # Detect dead code
        result = await dead_code_detector.detect_dead_code(path)
        
        # Format output
        return format_dead_code_results(result)
        
    except Exception as e:
        logger.error(f"Error detecting dead code: {e}")
        return f"❌ Error during dead code detection: {str(e)}"

# Formatting functions
def format_security_results(result: Dict[str, Any]) -> str:
    """Format security scan results."""
    output = f"""🔒 Security Scan Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 File: {result['file_path']}
📊 Total Issues: {result['total_issues']}
⚠️  Risk Score: {result['risk_score']}/100

🎯 Severity Breakdown:
  • Critical: {result['severity_counts']['critical']}
  • High: {result['severity_counts']['high']}
  • Medium: {result['severity_counts']['medium']}
  • Low: {result['severity_counts']['low']}
"""
    
    if result['issues']:
        output += "\n🚨 Top Security Issues:\n"
        for issue in result['issues'][:5]:
            output += f"\n  [{issue['severity']}] {issue['rule_id']}\n"
            output += f"  📍 Line {issue['location']['line']}: {issue['message']}\n"
            if issue.get('cwe'):
                output += f"  🔗 CWE: {issue['cwe']}\n"
    else:
        output += "\n✅ No security issues found!"
    
    return output

def format_quality_results(result: Dict[str, Any]) -> str:
    """Format quality check results."""
    output = f"""📏 Code Quality Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 File: {result['file_path']}
🏆 Quality Score: {result['quality_score']}/100
📊 Total Issues: {result['total_issues']}

📈 Issue Severity:
  • High: {result['issues_by_severity']['high']}
  • Medium: {result['issues_by_severity']['medium']}
  • Low: {result['issues_by_severity']['low']}
"""
    
    if result.get('metrics'):
        output += "\n📊 Code Metrics:\n"
        metrics = result['metrics']
        if 'max_function_length' in metrics:
            output += f"  • Longest Function: {metrics['max_function_length']} lines\n"
        if 'max_nesting_depth' in metrics:
            output += f"  • Max Nesting: {metrics['max_nesting_depth']} levels\n"
        if 'docstring_coverage' in metrics:
            output += f"  • Documentation: {metrics['docstring_coverage']*100:.0f}%\n"
    
    if result['issues']:
        output += "\n🔍 Top Quality Issues:\n"
        for issue in result['issues'][:5]:
            output += f"  • {issue['type']}: {issue['message']} (Line {issue['location']['line']})\n"
    
    return output

def format_todo_results(result: Dict[str, Any]) -> str:
    """Format TODO findings."""
    output = f"""📝 TODO/FIXME Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Total Items: {result['total_todos']}

📌 By Type:
"""
    for todo_type, count in result['by_type'].items():
        output += f"  • {todo_type}: {count}\n"
    
    output += "\n⚡ By Priority:\n"
    for priority, count in result['by_priority'].items():
        output += f"  • {priority}: {count}\n"
    
    if result['summary']['high_priority_count'] > 0:
        output += f"\n🚨 High Priority Items: {result['summary']['high_priority_count']}\n"
    
    if result['summary']['old_todos_count'] > 0:
        output += f"\n⏰ Old TODOs (>3 months): {result['summary']['old_todos_count']}\n"
    
    if result['summary']['recommendations']:
        output += "\n💡 Recommendations:\n"
        for rec in result['summary']['recommendations']:
            output += f"  • {rec}\n"
    
    return output

def format_dead_code_results(result: Dict[str, Any]) -> str:
    """Format dead code detection results."""
    output = f"""🧹 Dead Code Detection
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 File: {result['file_path']}
🗑️  Total Dead Code: {result['total_dead_code']}

📊 By Type:
"""
    for code_type, count in result['by_type'].items():
        output += f"  • {code_type}: {count}\n"
    
    if result['items']:
        output += "\n🔍 Dead Code Items:\n"
        for item in result['items'][:10]:
            output += f"  • Line {item['line']}: {item['message']}\n"
    
    return output