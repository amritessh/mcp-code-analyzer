# interactive_test.py
import asyncio
from src.server import *

async def interactive_test():
    """Interactive testing interface"""
    
    while True:
        print("\n" + "="*50)
        print("MCP Code Analyzer - Interactive Tester")
        print("="*50)
        print("\n1. Analyze GitHub Repository")
        print("2. Security Scan GitHub Repo")
        print("3. Compare Multiple Repos")
        print("4. Analyze Local File")
        print("5. Full Project Analysis")
        print("6. Exit")
        
        choice = input("\nSelect option (1-6): ").strip()
        
        if choice == "1":
            url = input("Enter GitHub URL: ").strip()
            mode = input("Analysis mode (quick/full) [quick]: ").strip() or "quick"
            
            print("\n🔍 Analyzing...")
            result = await analyze_github_repo_handler(url, "main", mode, None)
            print(result[:1500])
            
        elif choice == "2":
            url = input("Enter GitHub URL: ").strip()
            
            print("\n🔒 Scanning security...")
            result = await github_security_scan_handler(url, None)
            print(result[:1500])
            
        elif choice == "3":
            urls = []
            print("Enter repository URLs (empty line to finish):")
            while True:
                url = input(f"Repo {len(urls)+1}: ").strip()
                if not url:
                    break
                urls.append(url)
            
            if len(urls) >= 2:
                print("\n📊 Comparing repositories...")
                result = await compare_github_repos_handler(
                    urls,
                    ["quality", "security", "activity"]
                )
                print(result)
            else:
                print("Need at least 2 repos to compare!")
                
        elif choice == "4":
            path = input("Enter file path: ").strip()
            
            print("\n📄 Analyzing file...")
            basic = await analyze_file_handler(path)
            print(basic)
            
            if path.endswith('.py'):
                complexity = await get_complexity_handler(path, True)
                print(complexity)
                
        elif choice == "5":
            path = input("Enter project directory: ").strip()
            
            print("\n🚀 Running full project analysis...")
            result = await analyze_project_handler(path, None)
            print(result[:2000])
            
        elif choice == "6":
            print("\n👋 Goodbye!")
            break
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    asyncio.run(interactive_test())