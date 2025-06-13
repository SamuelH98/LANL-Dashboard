# AD-Analysis

This Docker setup automatically imports your processed authentication CSV data into Neo4j for graph analysis.


## Quick Start

1. **Build and run with Docker Compose:**
```bash
# Make sure your output.csv file is in the same directory
docker-compose up --build
```

2. **Or build and run with Docker directly:**
```bash
# Build the image
docker build -t neo4j-auth .

# Run the container
docker run -d \
  --name neo4j-auth-data \
  -p 7474:7474 -p 7687:7687 \
  -v $(pwd)/output.csv:/var/lib/neo4j/import/output.csv:ro \
  neo4j-auth
```

## Access Neo4j

- **Web Interface:** http://localhost:7474
- **Username:** neo4j
- **Password:** password123

## Data Model

The import creates the following graph structure:

### Nodes:
- `User`: Represents users in authentication events
- `Computer`: Represents computers/hosts
- `AuthEvent`: Individual authentication events
- `RedTeamActivity`: Groups red team events
- `ImportStats`: Contains import statistics

### Relationships:
- `(User)-[:AUTHENTICATED_FROM]->(Computer)`
- `(User)-[:AUTHENTICATED_TO]->(Computer)`
- `(AuthEvent)-[:SOURCE_USER]->(User)`
- `(AuthEvent)-[:DEST_USER]->(User)`
- `(AuthEvent)-[:SOURCE_COMPUTER]->(Computer)`
- `(AuthEvent)-[:DEST_COMPUTER]->(Computer)`
- `(AuthEvent)-[:PART_OF]->(RedTeamActivity)` (for red team events)

## Sample Queries

### Basic Statistics
```cypher
// Get overall statistics
MATCH (s:ImportStats) 
RETURN s.total_events, s.redteam_events, s.benign_events

// Count events by authentication type
MATCH (a:AuthEvent) 
RETURN a.auth_type, count(*) as count 
ORDER BY count DESC
```

### Red Team Analysis
```cypher
// Find all red team events
MATCH (a:AuthEvent) 
WHERE a.is_redteam = 1 
RETURN a.time, a.auth_type, a.success 
ORDER BY a.time

// Red team user activity
MATCH (a:AuthEvent)-[:SOURCE_USER]->(u:User)
WHERE a.is_redteam = 1
RETURN u.name, count(*) as activity_count
ORDER BY activity_count DESC
```

### Network Analysis
```cypher
// Find users with most computer connections
MATCH (u:User)-[:AUTHENTICATED_FROM]->(c:Computer)
RETURN u.name, count(DISTINCT c) as computer_count
ORDER BY computer_count DESC LIMIT 10

// Find computers with most authentication events
MATCH (a:AuthEvent)-[:DEST_COMPUTER]->(c:Computer)
RETURN c.name, count(a) as auth_count
ORDER BY auth_count DESC LIMIT 10
```

### Temporal Analysis
```cypher
// Events by hour of day
MATCH (a:AuthEvent)
RETURN a.timestamp.hour as hour, count(*) as event_count
ORDER BY hour

// Find authentication patterns around red team events
MATCH (rt:AuthEvent {is_redteam: 1})
MATCH (other:AuthEvent)
WHERE abs(other.time - rt.time) <= 300 // Within 5 minutes
RETURN rt.time, count(other) as nearby_events
ORDER BY nearby_events DESC
```

## Configuration

### Memory Settings
The container is configured with:
- Initial heap: 512MB
- Max heap: 2GB
- Page cache: 1GB

Adjust these in the docker-compose.yml if needed for your data size.

### Security
- Default password is `password123`
- Change this in production by modifying `NEO4J_AUTH` environment variable

## Troubleshooting

### CSV File Not Found
Make sure your `output.csv` file is in the same directory and properly mounted:
```bash
ls -la output.csv  # Should show your file
```

### Memory Issues
If you have a large dataset, increase memory settings:
```yaml
environment:
  - NEO4J_dbms_memory_heap_max__size=4G
  - NEO4J_dbms_memory_pagecache_size=2G
```

### Connection Issues
Check if Neo4j is running:
```bash
docker logs neo4j-auth-data
```

## Data Cleanup

To reset and reimport data:
```bash
docker-compose down -v  # Removes volumes
docker-compose up --build
```

## Performance Tips

1. **Indexes**: The import script creates indexes on commonly queried fields
2. **Batch Size**: For very large datasets, consider splitting the CSV
3. **Memory**: Allocate sufficient heap and page cache memory
4. **Constraints**: Unique constraints prevent duplicate nodes

## Advanced Queries

### Anomaly Detection
```cypher
// Find users with unusual authentication patterns
MATCH (u:User)-[:AUTHENTICATED_FROM]->(c:Computer)
WITH u, count(DISTINCT c) as computer_count
WHERE computer_count > 10
RETURN u.name, computer_count
ORDER BY computer_count DESC
```

### Graph Algorithms (requires Graph Data Science plugin)
```cypher
// PageRank on user-computer network
CALL gds.pageRank.stream('user-computer-graph')
YIELD nodeId, score
RETURN gds.util.asNode(nodeId).name, score
ORDER BY score DESC
```
