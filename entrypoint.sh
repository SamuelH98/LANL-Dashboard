#!/bin/bash

# Start Ollama in the background
echo "Starting Ollama..."
ollama serve &
OLLAMA_PID=$!

# Wait for Ollama to be ready
echo "Waiting for Ollama to start..."
sleep 10

# Pull the Gemma model in the background
echo "Pulling Gemma 3 1B model..."
ollama pull gemma3:1b &

set -e

# Start Neo4j in the background
echo "Starting Neo4j..."
/startup/docker-entrypoint.sh neo4j &

# Wait a bit for Neo4j to initialize
sleep 10

# Run the import script in the background
echo "Starting import process..."
/var/lib/neo4j/wait_and_import.sh &

# Wait a bit more for Neo4j to be fully ready
sleep 15

# Start the Python application
echo "Starting Python application..."
cd /src
# Option 1: If you have a main.py file
# python3 main.py &

# Option 2: If you're using Gradio (based on your requirements.txt)
# python3 -c "import gradio as gr; gr.Interface(...).launch(server_name='0.0.0.0', server_port=8000)" &

# Option 3: If you have a specific app structure
# python3 -m app.main &

# Option 4: Generic Python app starter - replace with your actual command
python3 src/main.py &

# Store Python app PID for cleanup
PYTHON_PID=$!

# Function to handle cleanup
cleanup() {
    echo "Shutting down services..."
    kill $OLLAMA_PID 2>/dev/null || true
    kill $PYTHON_PID 2>/dev/null || true
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

# Keep the main process running (Neo4j)
wait