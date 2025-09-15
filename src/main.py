"""
Simplified Main entry point for the Active Directory Red Team Analysis Dashboard
"""

from database import Neo4jDatabase
from agent import AnalysisAgent
from ui import create_gradio_interface
import os


def main():
    """
    Main function to start the LANL Dashboard.
    """
    print("🔒 Starting LANL Dashboard...")

    db = Neo4jDatabase()
    agent = AnalysisAgent(db)
    print("🚀 Launching dashboard on http://localhost:7860")
    app = create_gradio_interface(agent)
    app.launch(server_name="0.0.0.0", server_port=7860)


if __name__ == "__main__":
    main()