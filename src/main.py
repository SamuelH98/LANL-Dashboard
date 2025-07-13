"""
Main entry point for the Active Directory Red Team Analysis Dashboard
"""

import asyncio
from ui import create_gradio_interface

def main():
    print("Starting AD Red Team Analysis Dashboard...")
    print("Please ensure your Neo4j database and Ollama (with gemma3 model) are running.")
    print("Verify your .env file is configured with NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD.")
    
    app = create_gradio_interface()
    app.launch(server_name="0.0.0.0", server_port=7860)

if __name__ == "__main__":
    main()