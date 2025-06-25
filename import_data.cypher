// Optimized Neo4j Cypher Import Script for Authentication Data
// ==========================================================

// Step 1: Create constraints and indexes FIRST (before any data import)
CREATE CONSTRAINT user_id IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE;
CREATE CONSTRAINT computer_id IF NOT EXISTS FOR (c:Computer) REQUIRE c.name IS UNIQUE;
CREATE INDEX auth_time_idx IF NOT EXISTS FOR (a:AuthEvent) ON (a.time);
CREATE INDEX auth_success_idx IF NOT EXISTS FOR (a:AuthEvent) ON (a.success);
CREATE INDEX auth_redteam_idx IF NOT EXISTS FOR (a:AuthEvent) ON (a.is_redteam);
CREATE INDEX user_name_idx IF NOT EXISTS FOR (u:User) ON (u.name);
CREATE INDEX computer_name_idx IF NOT EXISTS FOR (c:Computer) ON (c.name);

// Step 2: Import in batches with modern transaction syntax
// Replace 'file:///output.csv' with your actual file path
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.time IS NOT NULL AND trim(row.time) <> ''
CALL {
  WITH row
  // Create/merge nodes efficiently (fewer MERGE operations)
  MERGE (source_user:User {name: trim(row.`source user@domain`)})
  MERGE (dest_user:User {name: trim(row.`destination user@domain`)})
  MERGE (source_comp:Computer {name: trim(row.`source computer`)})
  MERGE (dest_comp:Computer {name: trim(row.`destination computer`)})

  // Create AuthEvent with relationships in one go
  CREATE (auth:AuthEvent {
      time: toInteger(row.time),
      auth_type: trim(row.`authentication type`),
      logon_type: trim(row.`logon type`),
      auth_orientation: trim(row.`authentication orientation`),
      success: trim(row.`success/failure`),
      is_redteam: toBoolean(toInteger(row.label)),
      timestamp: datetime({epochSeconds: toInteger(row.time)})
  })

  // Simplified relationship model (fewer relationships per event)
  CREATE (source_user)-[:AUTHENTICATED {event_time: toInteger(row.time)}]->(dest_comp)
  CREATE (auth)-[:FROM_USER]->(source_user)
  CREATE (auth)-[:TO_USER]->(dest_user)
  CREATE (auth)-[:FROM_COMPUTER]->(source_comp)
  CREATE (auth)-[:TO_COMPUTER]->(dest_comp)
} IN TRANSACTIONS OF 1000 ROWS;

// Alternative approach for very large datasets: Split into multiple transactions
// ===========================================================================

// Step 2a: Create Users first
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.time IS NOT NULL
CALL {
  WITH row
  MERGE (source_user:User {name: trim(row.`source user@domain`)})
  MERGE (dest_user:User {name: trim(row.`destination user@domain`)})
} IN TRANSACTIONS OF 1000 ROWS;

// Step 2b: Create Computers
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.time IS NOT NULL
CALL {
  WITH row
  MERGE (source_comp:Computer {name: trim(row.`source computer`)})
  MERGE (dest_comp:Computer {name: trim(row.`destination computer`)})
} IN TRANSACTIONS OF 1000 ROWS;

// Step 2c: Create AuthEvents and relationships
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.time IS NOT NULL
CALL {
  WITH row
  MATCH (source_user:User {name: trim(row.`source user@domain`)})
  MATCH (dest_user:User {name: trim(row.`destination user@domain`)})
  MATCH (source_comp:Computer {name: trim(row.`source computer`)})
  MATCH (dest_comp:Computer {name: trim(row.`destination computer`)})

  CREATE (auth:AuthEvent {
      time: toInteger(row.time),
      auth_type: trim(row.`authentication type`),
      logon_type: trim(row.`logon type`),
      auth_orientation: trim(row.`authentication orientation`),
      success: trim(row.`success/failure`),
      is_redteam: toBoolean(toInteger(row.label)),
      timestamp: datetime({epochSeconds: toInteger(row.time)})
  })

  CREATE (source_user)-[:AUTHENTICATED {event_time: toInteger(row.time)}]->(dest_comp)
  CREATE (auth)-[:FROM_USER]->(source_user)
  CREATE (auth)-[:TO_USER]->(dest_user)
  CREATE (auth)-[:FROM_COMPUTER]->(source_comp)
  CREATE (auth)-[:TO_COMPUTER]->(dest_comp)
} IN TRANSACTIONS OF 1000 ROWS;

// Memory and performance optimization notes
// ========================================
// Neo4j memory settings should be configured in neo4j.conf file:
// - dbms.memory.heap.max_size=8G
// - dbms.memory.pagecache.size=4G
// - dbms.memory.transaction.global_max_size=1G

// Check memory usage during import (if available)
// CALL dbms.queryJmx('java.lang:type=Memory') YIELD attributes
// RETURN attributes.HeapMemoryUsage;

// Optimized Analysis Queries
// =========================

// Query 1: Overall statistics (optimized)
MATCH (a:AuthEvent)
RETURN 
    count(a) as total_events,
    sum(CASE WHEN a.is_redteam THEN 1 ELSE 0 END) as redteam_events,
    sum(CASE WHEN NOT a.is_redteam THEN 1 ELSE 0 END) as benign_events;

// Query 2: Authentication types (with index usage)
MATCH (a:AuthEvent)
WHERE a.auth_type IS NOT NULL
RETURN a.auth_type, count(*) as count
ORDER BY count DESC;

// Query 3: Red team events (uses index)
MATCH (a:AuthEvent)
WHERE a.is_redteam = true
RETURN a.time, a.auth_type, a.success
ORDER BY a.time
LIMIT 1000;

// Query 4: Red team user activity (optimized with relationship traversal)
MATCH (a:AuthEvent)-[:FROM_USER]->(u:User)
WHERE a.is_redteam = true
RETURN u.name, count(*) as activity_count
ORDER BY activity_count DESC
LIMIT 50;

// Query 5: User computer connections (simplified)
MATCH (u:User)-[r:AUTHENTICATED]->(c:Computer)
RETURN u.name, count(DISTINCT c) as computer_count
ORDER BY computer_count DESC 
LIMIT 10;

// Query 6: Most targeted computers
MATCH (a:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
RETURN c.name, count(a) as auth_count
ORDER BY auth_count DESC 
LIMIT 10;

// Query 7: Events by hour (optimized)
MATCH (a:AuthEvent)
WHERE a.timestamp IS NOT NULL
RETURN a.timestamp.hour as hour, count(*) as event_count
ORDER BY hour;

// Query 8: Lateral movement detection (optimized with time window)
MATCH (u:User)<-[:FROM_USER]-(a1:AuthEvent)-[:TO_COMPUTER]->(c1:Computer)
MATCH (u)<-[:FROM_USER]-(a2:AuthEvent)-[:FROM_COMPUTER]->(c1)
MATCH (a2)-[:TO_COMPUTER]->(c2:Computer)
WHERE a2.time > a1.time 
  AND a2.time - a1.time <= 3600
  AND c1 <> c2
RETURN u.name, c1.name as intermediate, c2.name as target,
       a1.time as first_auth, a2.time as second_auth,
       (a2.time - a1.time) as time_diff
ORDER BY time_diff
LIMIT 100;

// Query 9: Failed authentication patterns
MATCH (a:AuthEvent)-[:FROM_USER]->(u:User)
MATCH (a)-[:TO_COMPUTER]->(c:Computer)
WHERE a.success = 'Failure'
RETURN u.name, c.name, count(*) as failed_attempts
ORDER BY failed_attempts DESC 
LIMIT 20;

// Query 10: Red team timeline (limited results)
MATCH (a:AuthEvent)-[:FROM_USER]->(u:User)
MATCH (a)-[:FROM_COMPUTER]->(sc:Computer)
MATCH (a)-[:TO_COMPUTER]->(dc:Computer)
WHERE a.is_redteam = true
RETURN a.time, u.name as user, sc.name as source, dc.name as dest, a.success
ORDER BY a.time
LIMIT 1000;

// Performance monitoring queries
// =============================

// Check query performance
PROFILE MATCH (a:AuthEvent) WHERE a.is_redteam = true RETURN count(a);

// Monitor active queries (if available)
// CALL dbms.listQueries() YIELD query, elapsedTimeMillis, status
// WHERE elapsedTimeMillis > 1000
// RETURN query, elapsedTimeMillis, status;

// Check database size and node counts
MATCH (n) RETURN labels(n), count(n);

// Check relationship counts
MATCH ()-[r]->() RETURN type(r), count(r);

// Simple memory status check
CALL dbms.listConfig() YIELD name, value 
WHERE name CONTAINS 'memory' 
RETURN name, value;