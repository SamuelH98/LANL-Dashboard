// Optimized Neo4j Cypher Import Script for Authentication Data
// ==========================================================

// Step 1: Create constraints and indexes FIRST (before any data import)
// Constraints automatically create an index on the constrained property.
CREATE CONSTRAINT user_unique_name IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE;
CREATE CONSTRAINT computer_unique_name IF NOT EXISTS FOR (c:Computer) REQUIRE c.name IS UNIQUE;

// Indexes for AuthEvent properties
CREATE INDEX auth_time_idx IF NOT EXISTS FOR (a:AuthEvent) ON (a.time);
CREATE INDEX auth_timestamp_idx IF NOT EXISTS FOR (a:AuthEvent) ON (a.timestamp); // Added for datetime
CREATE INDEX auth_success_idx IF NOT EXISTS FOR (a:AuthEvent) ON (a.success);
CREATE INDEX auth_redteam_idx IF NOT EXISTS FOR (a:AuthEvent) ON (a.is_redteam);
CREATE INDEX auth_type_idx IF NOT EXISTS FOR (a:AuthEvent) ON (a.auth_type); // Good for Query 2

// Note: user_name_idx and computer_name_idx are redundant if constraints on name exist,
// but having them explicitly doesn't hurt and can be a reminder.
// If you want to be minimal, you can remove the next two:
CREATE INDEX user_name_idx IF NOT EXISTS FOR (u:User) ON (u.name);
CREATE INDEX computer_name_idx IF NOT EXISTS FOR (c:Computer) ON (c.name);


// Step 2: Import in batches with modern transaction syntax
// Replace 'file:///output.csv' with your actual file path
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.time IS NOT NULL AND trim(row.time) <> '' AND row.`source user@domain` IS NOT NULL AND trim(row.`source user@domain`) <> '' AND row.`destination computer` IS NOT NULL AND trim(row.`destination computer`) <> ''
CALL {
  WITH row
  // Create/merge nodes efficiently
  MERGE (source_user:User {name: trim(row.`source user@domain`)})
  MERGE (dest_user:User {name: trim(row.`destination user@domain`)}) // Ensure dest_user is also handled if it can be empty/null
  MERGE (source_comp:Computer {name: trim(row.`source computer`)})
  MERGE (dest_comp:Computer {name: trim(row.`destination computer`)})

  // Create AuthEvent with relationships in one go
  CREATE (auth:AuthEvent {
      time: toInteger(row.time), // Keep for original compatibility if needed
      auth_type: trim(row.`authentication type`),
      logon_type: trim(row.`logon type`),
      auth_orientation: trim(row.`authentication orientation`),
      success: trim(row.`success/failure`),
      is_redteam: toBoolean(toInteger(row.label)), // Assumes row.label is '0' or '1'
      timestamp: datetime({epochSeconds: toInteger(row.time)}) // Use datetime for better time functions
  })

  // Relationships centered around the AuthEvent
  CREATE (auth)-[:FROM_USER]->(source_user)
  CREATE (auth)-[:TO_USER]->(dest_user) // Make sure dest_user is always present or handle conditional creation
  CREATE (auth)-[:FROM_COMPUTER]->(source_comp)
  CREATE (auth)-[:TO_COMPUTER]->(dest_comp)

  // REMOVED: The direct relationship that caused performance issues
  // CREATE (source_user)-[:AUTHENTICATED {event_time: toInteger(row.time)}]->(dest_comp)
  // This information is now derived: (source_user)<-[:FROM_USER]-(auth:AuthEvent)-[:TO_COMPUTER]->(dest_comp)

} IN TRANSACTIONS OF 1000 ROWS; // Consider 1k-10k. Test for your data/hardware.

// ===========================================================================
// Alternative approach for very large datasets (Splitting Node/Rel Creation)
// This remains a valid strategy. The key change is to NOT create the direct
// :AUTHENTICATED relationship in Step 2c.
// ===========================================================================

// Step 2a: Create Users first
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.time IS NOT NULL AND trim(row.time) <> ''
CALL {
  WITH row
  // Ensure names are not null or empty before MERGE to avoid creating nodes with empty names
  WITH row WHERE row.`source user@domain` IS NOT NULL AND trim(row.`source user@domain`) <> ''
  MERGE (source_user:User {name: trim(row.`source user@domain`)})

  WITH row WHERE row.`destination user@domain` IS NOT NULL AND trim(row.`destination user@domain`) <> ''
  MERGE (dest_user:User {name: trim(row.`destination user@domain`)})
} IN TRANSACTIONS OF 10000 ROWS; // Larger batches can be okay for node-only creation

// Step 2b: Create Computers
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.time IS NOT NULL AND trim(row.time) <> ''
CALL {
  WITH row
  WITH row WHERE row.`source computer` IS NOT NULL AND trim(row.`source computer`) <> ''
  MERGE (source_comp:Computer {name: trim(row.`source computer`)})

  WITH row WHERE row.`destination computer` IS NOT NULL AND trim(row.`destination computer`) <> ''
  MERGE (dest_comp:Computer {name: trim(row.`destination computer`)})
} IN TRANSACTIONS OF 10000 ROWS;

// Step 2c: Create AuthEvents and relationships (EVENT-CENTRIC MODEL)
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.time IS NOT NULL AND trim(row.time) <> ''
CALL {
  WITH row
  // Match existing nodes (constraints/indexes are crucial here for performance)
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

  // Event-centric relationships
  CREATE (auth)-[:FROM_USER]->(source_user)
  CREATE (auth)-[:TO_USER]->(dest_user)
  CREATE (auth)-[:FROM_COMPUTER]->(source_comp)
  CREATE (auth)-[:TO_COMPUTER]->(dest_comp)

  // AGAIN, DO NOT CREATE THE DIRECT :AUTHENTICATED relationship here
  // CREATE (source_user)-[:AUTHENTICATED {event_time: toInteger(row.time)}]->(dest_comp)

} IN TRANSACTIONS OF 1000 ROWS; // Smaller batches for complex operations (MATCH + CREATE)

// Memory and performance optimization notes
// ========================================
// Neo4j memory settings should be configured in neo4j.conf file:
// - dbms.memory.heap.initial_size and dbms.memory.heap.max_size (e.g., 8G or more for large imports)
// - dbms.memory.pagecache.size (e.g., 4G or more, depends on graph size and available RAM)
// - dbms.tx_state.memory_allocation=ON_HEAP (can sometimes help with large transactions, default is OFF_HEAP)
// - dbms.memory.transaction.global_max_size (e.g., 1G or 2G, ensure transactions fit)

// Check memory usage during import (if available)
// CALL dbms.queryJmx('java.lang:type=Memory') YIELD attributes
// RETURN attributes.HeapMemoryUsage.committed as committedHeap, attributes.HeapMemoryUsage.used as usedHeap;

// Optimized Analysis Queries (Query 5 is updated)
// =========================

// Query 1: Overall statistics (optimized)
MATCH (a:AuthEvent)
RETURN
    count(a) as total_events,
    sum(CASE WHEN a.is_redteam THEN 1 ELSE 0 END) as redteam_events,
    sum(CASE WHEN NOT a.is_redteam THEN 1 ELSE 0 END) as benign_events;

// Query 2: Authentication types (with index usage)
MATCH (a:AuthEvent)
WHERE a.auth_type IS NOT NULL // Index on auth_type helps
RETURN a.auth_type, count(*) as count
ORDER BY count DESC;

// Query 3: Red team events (uses index)
MATCH (a:AuthEvent)
WHERE a.is_redteam = true // Index on is_redteam helps
RETURN a.timestamp, a.auth_type, a.success // Using timestamp for better readability
ORDER BY a.timestamp
LIMIT 1000;

// Query 4: Red team user activity (optimized with relationship traversal)
MATCH (u:User)<-[:FROM_USER]-(a:AuthEvent) // or (a:AuthEvent)-[:FROM_USER]->(u:User)
WHERE a.is_redteam = true
RETURN u.name, count(a) as activity_count // count(a) instead of count(*) if you want to be explicit
ORDER BY activity_count DESC
LIMIT 50;

// Query 5: User computer connections (REVISED to use AuthEvent)
MATCH (u:User)<-[:FROM_USER]-(evt:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
WHERE u.name IS NOT NULL AND c.name IS NOT NULL // Ensure nodes are valid
RETURN u.name AS user_name, c.name AS computer_name, count(evt) AS connection_events
ORDER BY connection_events DESC
LIMIT 20;
// If you want distinct computers per user:
// MATCH (u:User)<-[:FROM_USER]-(:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
// RETURN u.name, count(DISTINCT c) as distinct_computer_count
// ORDER BY distinct_computer_count DESC
// LIMIT 10;


// Query 6: Most targeted computers
MATCH (c:Computer)<-[:TO_COMPUTER]-(a:AuthEvent) // or (a:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
RETURN c.name, count(a) as auth_count
ORDER BY auth_count DESC
LIMIT 10;

// Query 7: Events by hour (optimized using datetime property)
MATCH (a:AuthEvent)
WHERE a.timestamp IS NOT NULL // Index on timestamp helps
RETURN a.timestamp.hour as hour, count(*) as event_count
ORDER BY hour;

// Query 8: Lateral movement detection (optimized with time window)
// User u logs into c1, then from c1 logs into c2
MATCH (u:User)<-[:FROM_USER]-(a1:AuthEvent)-[:TO_COMPUTER]->(c1:Computer)
WHERE u.name IS NOT NULL AND c1.name IS NOT NULL // Ensure valid start
MATCH (c1)<-[:FROM_COMPUTER]-(a2:AuthEvent)-[:TO_COMPUTER]->(c2:Computer)
WHERE c2.name IS NOT NULL AND a2.time > a1.time AND (a2.time - a1.time) <= 3600 // Time window in seconds (1 hour)
  AND id(c1) <> id(c2) // Ensure c1 and c2 are different computers
  AND (a2)-[:FROM_USER]->(u) // Ensure the same user performed both actions
RETURN u.name, c1.name as intermediate_computer, c2.name as target_computer,
       a1.timestamp as first_auth_time, a2.timestamp as second_auth_time,
       duration({seconds: (a2.time - a1.time)}) as time_difference
ORDER BY time_difference
LIMIT 100;

// Query 9: Failed authentication patterns
MATCH (u:User)<-[:FROM_USER]-(a:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
WHERE a.success = 'Failure' // Index on success helps
RETURN u.name, c.name, count(a) as failed_attempts
ORDER BY failed_attempts DESC
LIMIT 20;

// Query 10: Red team timeline (limited results)
MATCH (a:AuthEvent)-[:FROM_USER]->(u:User),
      (a)-[:FROM_COMPUTER]->(sc:Computer),
      (a)-[:TO_COMPUTER]->(dc:Computer)
WHERE a.is_redteam = true // Index on is_redteam helps
RETURN a.timestamp, u.name as user, sc.name as source_computer, dc.name as dest_computer, a.success
ORDER BY a.timestamp
LIMIT 1000;

// Performance monitoring queries
// =============================

// Check query performance (prefix with PROFILE or EXPLAIN)
// PROFILE MATCH (a:AuthEvent) WHERE a.is_redteam = true RETURN count(a);
// EXPLAIN MATCH (u:User)<-[:FROM_USER]-(evt:AuthEvent)-[:TO_COMPUTER]->(c:Computer) RETURN u.name, c.name, count(evt) LIMIT 10;

// Monitor active queries (Neo4j 4.x and later)
// CALL dbms.listQueries() YIELD queryId, query, username, elapsedTime, status
// WHERE status = 'running' AND elapsedTimeMillis > 1000 // Example: running longer than 1 sec
// RETURN queryId, query, username, elapsedTime, status;

// Check database size and node counts
// CALL db.schema() // For a visual overview in Neo4j Browser
MATCH (n) RETURN labels(n) AS Label, count(n) AS Count ORDER BY Count DESC;

// Check relationship counts
MATCH ()-[r]->() RETURN type(r) AS Type, count(r) AS Count ORDER BY Count DESC;

// Simple memory status check
// CALL dbms.listConfig() YIELD name, value
// WHERE name STARTS WITH 'dbms.memory.' OR name STARTS WITH 'memory.'
// RETURN name, value;
// More detailed:
// CALL dbms.metrics.list() YIELD name, value WHERE name STARTS WITH 'vm.' OR name STARTS WITH 'neo4j.page_cache.' RETURN name, value;