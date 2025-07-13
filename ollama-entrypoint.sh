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

# Start Neo4j (this will run in the foreground)
echo "Starting Neo4j..."
exec /docker-entrypoint.sh