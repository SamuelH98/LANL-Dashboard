#!/bin/bash

echo "Waiting for Neo4j to be ready..."

# Wait for Neo4j to be ready
while ! cypher-shell -u neo4j -p password123 "RETURN 1" > /dev/null 2>&1; do
    echo "Neo4j not ready yet, waiting 5 seconds..."
    sleep 5
done

echo "Neo4j is ready! Starting data import..."

# Check if CSV file exists
if [ ! -f "/var/lib/neo4j/import/output.csv" ]; then
    echo "Warning: /var/lib/neo4j/import/output.csv not found!"
    echo "Please make sure your CSV file is mounted to the container."
    echo "Example: docker run -v /path/to/your/output.csv:/var/lib/neo4j/import/output.csv ..."
    exit 1
fi

echo "CSV file found, starting import process..."

# Run the import script
cypher-shell -u neo4j -p password123 -f /var/lib/neo4j/import/import_data.cypher

if [ $? -eq 0 ]; then
    echo "Data import completed successfully!"
    
    # Show some statistics
    echo "Getting import statistics..."
    cypher-shell -u neo4j -p password123 "MATCH (s:ImportStats) RETURN s.total_events as TotalEvents, s.redteam_events as RedTeamEvents, s.benign_events as BenignEvents, s.unique_timestamps as UniqueTimestamps, s.import_date as ImportDate"
    
    echo "Sample queries you can run:"
    echo "1. Count events by type: MATCH (a:AuthEvent) RETURN a.auth_type, count(*) ORDER BY count(*) DESC"
    echo "2. Find red team events: MATCH (a:AuthEvent) WHERE a.is_redteam = 1 RETURN a LIMIT 10"
    echo "3. User authentication patterns: MATCH (u:User)-[:AUTHENTICATED_FROM]->(c:Computer) RETURN u.name, count(c) as computer_count ORDER BY computer_count DESC LIMIT 10"
    
else
    echo "Data import failed!"
    exit 1
fi
