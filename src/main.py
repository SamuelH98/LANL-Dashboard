"""
Simplified Main entry point for the Active Directory Red Team Analysis Dashboard
"""

from ui import create_gradio_interface

def main():
    """
    Main function to start the AD Red Team Analysis Dashboard.
    """
    print("🔒 Starting AD Red Team Analysis Dashboard...")
    print("📋 System Requirements:")
    print("   • Neo4j database running (bolt://localhost:7687)")
    print("   • Ollama service running (http://127.0.0.1:11434)")
    print("   • .env file configured with database credentials")
    print("🚀 Launching dashboard on http://localhost:7860")
    
    app = create_gradio_interface()
    app.launch(
        server_name="0.0.0.0", 
        server_port=7860
    )

if __name__ == "__main__":
    main()