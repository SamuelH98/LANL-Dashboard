#!/bin/bash
set -e

# Start Neo4j in the background
echo "Starting Neo4j..."
/startup/docker-entrypoint.sh neo4j &

# Wait a bit for Neo4j to initialize
sleep 10

# Run the import script in the background
echo "Starting import process..."
/var/lib/neo4j/wait_and_import.sh &

# Keep the main process running (Neo4j)
wait
