// Neo4j Cypher Import Script for Authentication Data with Chunking
// ==============================================================

// First, create constraints and indexes for better performance
CREATE CONSTRAINT user_id IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE;
CREATE CONSTRAINT computer_id IF NOT EXISTS FOR (c:Computer) REQUIRE c.name IS UNIQUE;
CREATE INDEX auth_time_idx IF NOT EXISTS FOR (a:AuthEvent) ON (a.time);
CREATE INDEX auth_success_idx IF NOT EXISTS FOR (a:AuthEvent) ON (a.success);
CREATE INDEX auth_redteam_idx IF NOT EXISTS FOR (a:AuthEvent) ON (a.is_redteam);

// Configuration: Adjust chunk size based on your system's memory and performance
// Typical values: 1000-10000 for moderate systems, 10000-50000 for high-end systems
:param chunk_size => 5000;

// Method 1: Basic Chunking with CALL IN TRANSACTIONS
// ================================================

// Get total row count first (optional, for progress tracking)
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.time IS NOT NULL
RETURN count(*) as total_rows;

// Import data in chunks using CALL IN TRANSACTIONS (Neo4j 4.4+)
CALL {
    LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
    WITH row WHERE row.time IS NOT NULL
    
    // Create or merge User nodes
    MERGE (source_user:User {name: row.`source user@domain`})
    MERGE (dest_user:User {name: row.`destination user@domain`})
    
    // Create or merge Computer nodes
    MERGE (source_comp:Computer {name: row.`source computer`})
    MERGE (dest_comp:Computer {name: row.`destination computer`})
    
    // Create AuthEvent node with all properties
    CREATE (auth:AuthEvent {
        time: toInteger(row.time),
        auth_type: row.`authentication type`,
        logon_type: row.`logon type`,
        auth_orientation: row.`authentication orientation`,
        success: row.`success/failure`,
        is_redteam: toBoolean(toInteger(row.label)),
        timestamp: datetime({epochSeconds: toInteger(row.time)})
    })
    
    // Create relationships
    CREATE (source_user)-[:AUTHENTICATED_FROM]->(source_comp)
    CREATE (source_user)-[:AUTHENTICATED_TO]->(dest_comp)
    CREATE (source_comp)-[:AUTH_SOURCE]->(auth)
    CREATE (dest_comp)-[:AUTH_DEST]->(auth)
    CREATE (source_user)-[:INITIATED]->(auth)
    CREATE (dest_user)-[:RECEIVED]->(auth)
    
} IN TRANSACTIONS OF 5000 ROWS;

// Method 2: Manual Chunking with SKIP and LIMIT (Universal Approach)
// =================================================================

// Step 1: Process first chunk (rows 0-4999)
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.time IS NOT NULL
WITH row, toInteger(row.time) as time_int
ORDER BY time_int
SKIP 0 LIMIT 5000

// Create or merge User nodes
MERGE (source_user:User {name: row.`source user@domain`})
MERGE (dest_user:User {name: row.`destination user@domain`})

// Create or merge Computer nodes
MERGE (source_comp:Computer {name: row.`source computer`})
MERGE (dest_comp:Computer {name: row.`destination computer`})

// Create AuthEvent node with all properties
CREATE (auth:AuthEvent {
    time: time_int,
    auth_type: row.`authentication type`,
    logon_type: row.`logon type`,
    auth_orientation: row.`authentication orientation`,
    success: row.`success/failure`,
    is_redteam: toBoolean(toInteger(row.label)),
    timestamp: datetime({epochSeconds: time_int})
})

// Create relationships
CREATE (source_user)-[:AUTHENTICATED_FROM]->(source_comp)
CREATE (source_user)-[:AUTHENTICATED_TO]->(dest_comp)
CREATE (source_comp)-[:AUTH_SOURCE]->(auth)
CREATE (dest_comp)-[:AUTH_DEST]->(auth)
CREATE (source_user)-[:INITIATED]->(auth)
CREATE (dest_user)-[:RECEIVED]->(auth);

// Step 2: Process second chunk (rows 5000-9999)
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.time IS NOT NULL
WITH row, toInteger(row.time) as time_int
ORDER BY time_int
SKIP 5000 LIMIT 5000

// Create or merge User nodes
MERGE (source_user:User {name: row.`source user@domain`})
MERGE (dest_user:User {name: row.`destination user@domain`})

// Create or merge Computer nodes
MERGE (source_comp:Computer {name: row.`source computer`})
MERGE (dest_comp:Computer {name: row.`destination computer`})

// Create AuthEvent node with all properties
CREATE (auth:AuthEvent {
    time: time_int,
    auth_type: row.`authentication type`,
    logon_type: row.`logon type`,
    auth_orientation: row.`authentication orientation`,
    success: row.`success/failure`,
    is_redteam: toBoolean(toInteger(row.label)),
    timestamp: datetime({epochSeconds: time_int})
})

// Create relationships
CREATE (source_user)-[:AUTHENTICATED_FROM]->(source_comp)
CREATE (source_user)-[:AUTHENTICATED_TO]->(dest_comp)
CREATE (source_comp)-[:AUTH_SOURCE]->(auth)
CREATE (dest_comp)-[:AUTH_DEST]->(auth)
CREATE (source_user)-[:INITIATED]->(auth)
CREATE (dest_user)-[:RECEIVED]->(auth);

// Continue with additional chunks as needed...
// Step 3: SKIP 10000 LIMIT 5000
// Step 4: SKIP 15000 LIMIT 5000
// etc.

// Method 3: Simple Batch Processing (Works in all Neo4j versions)
// =============================================================

// Create a simple counter to track progress
CREATE (counter:ProcessingCounter {processed: 0, chunk_size: 5000});

// Process data in batches - you'll need to run this multiple times
// changing the SKIP value each time: 0, 5000, 10000, 15000, etc.

MATCH (counter:ProcessingCounter)
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row, counter WHERE row.time IS NOT NULL
WITH row, counter, toInteger(row.time) as time_int
ORDER BY time_int
SKIP 0 LIMIT 5000  // Change this for each batch: 0, 5000, 10000, etc.

// Create or merge User nodes
MERGE (source_user:User {name: row.`source user@domain`})
MERGE (dest_user:User {name: row.`destination user@domain`})

// Create or merge Computer nodes  
MERGE (source_comp:Computer {name: row.`source computer`})
MERGE (dest_comp:Computer {name: row.`destination computer`})

// Create AuthEvent node with all properties
CREATE (auth:AuthEvent {
    time: time_int,
    auth_type: row.`authentication type`,
    logon_type: row.`logon type`,
    auth_orientation: row.`authentication orientation`,
    success: row.`success/failure`,
    is_redteam: toBoolean(toInteger(row.label)),
    timestamp: datetime({epochSeconds: time_int})
})

// Create relationships
CREATE (source_user)-[:AUTHENTICATED_FROM]->(source_comp)
CREATE (source_user)-[:AUTHENTICATED_TO]->(dest_comp)
CREATE (source_comp)-[:AUTH_SOURCE]->(auth)
CREATE (dest_comp)-[:AUTH_DEST]->(auth)
CREATE (source_user)-[:INITIATED]->(auth)
CREATE (dest_user)-[:RECEIVED]->(auth)

WITH counter, count(*) as batch_count
SET counter.processed = counter.processed + batch_count
RETURN counter.processed as total_processed, batch_count;

// Method 4: Optimized Chunking with Batch Operations
// =================================================

// Configuration
:param batch_size => 1000;  // Smaller batches for node creation
:param chunk_size => 5000;  // Larger chunks for relationship creation

// Step 1: Create all User nodes in batches
CALL {
    LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
    WITH row WHERE row.time IS NOT NULL
    WITH DISTINCT row.`source user@domain` as user_name
    WHERE user_name IS NOT NULL
    
    CALL {
        WITH user_name
        MERGE (u:User {name: user_name})
    } IN TRANSACTIONS OF 1000 ROWS
}

CALL {
    LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
    WITH row WHERE row.time IS NOT NULL
    WITH DISTINCT row.`destination user@domain` as user_name
    WHERE user_name IS NOT NULL
    
    CALL {
        WITH user_name
        MERGE (u:User {name: user_name})
    } IN TRANSACTIONS OF 1000 ROWS
}

// Step 2: Create all Computer nodes in batches
CALL {
    LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
    WITH row WHERE row.time IS NOT NULL
    WITH DISTINCT row.`source computer` as comp_name
    WHERE comp_name IS NOT NULL
    
    CALL {
        WITH comp_name
        MERGE (c:Computer {name: comp_name})
    } IN TRANSACTIONS OF 1000 ROWS
}

CALL {
    LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
    WITH row WHERE row.time IS NOT NULL
    WITH DISTINCT row.`destination computer` as comp_name
    WHERE comp_name IS NOT NULL
    
    CALL {
        WITH comp_name
        MERGE (c:Computer {name: comp_name})
    } IN TRANSACTIONS OF 1000 ROWS
}

// Step 3: Create AuthEvent nodes and relationships in chunks
CALL {
    LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
    WITH row WHERE row.time IS NOT NULL
    
    CALL {
        WITH row
        // Match existing nodes
        MATCH (source_user:User {name: row.`source user@domain`})
        MATCH (dest_user:User {name: row.`destination user@domain`})
        MATCH (source_comp:Computer {name: row.`source computer`})
        MATCH (dest_comp:Computer {name: row.`destination computer`})
        
        // Create AuthEvent node
        CREATE (auth:AuthEvent {
            time: toInteger(row.time),
            auth_type: row.`authentication type`,
            logon_type: row.`logon type`,
            auth_orientation: row.`authentication orientation`,
            success: row.`success/failure`,
            is_redteam: toBoolean(toInteger(row.label)),
            timestamp: datetime({epochSeconds: toInteger(row.time)})
        })
        
        // Create relationships
        CREATE (source_user)-[:AUTHENTICATED_FROM]->(source_comp)
        CREATE (source_user)-[:AUTHENTICATED_TO]->(dest_comp)
        CREATE (source_comp)-[:AUTH_SOURCE]->(auth)
        CREATE (dest_comp)-[:AUTH_DEST]->(auth)
        CREATE (source_user)-[:INITIATED]->(auth)
        CREATE (dest_user)-[:RECEIVED]->(auth)
        
    } IN TRANSACTIONS OF 2000 ROWS
}

// Method 5: Shell Script Approach for Very Large Files
// ===================================================
// For extremely large files, consider using a shell script to split the CSV first:

/*
# Split CSV into chunks (run this in your shell before importing)
split -l 10000 output.csv chunk_
for file in chunk_*; do
  mv "$file" "$file.csv"
done

# Then import each chunk separately:
# chunk_aa.csv, chunk_ab.csv, etc.
*/

// Import individual chunk files
LOAD CSV WITH HEADERS FROM 'file:///chunk_aa.csv' AS row
WITH row WHERE row.time IS NOT NULL
// ... same import logic as above

// Monitoring and Progress Queries
// ==============================

// Check current import progress
MATCH (counter:ProcessingCounter)
RETURN counter.processed as total_processed, counter.chunk_size;

// Monitor transaction log size during import
CALL dbms.queryJmx("org.neo4j:instance=kernel#0,name=Transactions") 
YIELD attributes
RETURN attributes.NumberOfOpenTransactions, attributes.PeakNumberOfConcurrentTransactions;

// Check memory usage
CALL dbms.queryJmx("java.lang:type=Memory") 
YIELD attributes
RETURN attributes.HeapMemoryUsage, attributes.NonHeapMemoryUsage;

// Verify chunk processing completion
MATCH (a:AuthEvent)
RETURN count(a) as total_events,
       min(a.time) as earliest_event,
       max(a.time) as latest_event;

// Performance Tuning Settings (add to neo4j.conf)
// ==============================================
/*
# Increase memory allocation
dbms.memory.heap.initial_size=2G
dbms.memory.heap.max_size=4G
dbms.memory.pagecache.size=2G

# Optimize for write performance
dbms.transaction.concurrent.maximum=1000
dbms.memory.transaction.global_max_size=1G
dbms.memory.transaction.max_size=10M

# Disable unnecessary features during import
dbms.security.auth_enabled=false  # Temporarily, re-enable after import
dbms.logs.query.enabled=false     # Disable query logging during import
*/

// Cleanup and Optimization After Import
// ====================================

// Cleanup after chunked import
// ============================

// Remove processing counter
MATCH (counter:ProcessingCounter) DELETE counter;

// Update statistics for query planner
CALL db.stats.collect();

// Additional useful queries for analysis (same as original)
// =======================================================

// Query 1: Get overall statistics
MATCH (a:AuthEvent)
RETURN 
    count(a) as total_events,
    sum(CASE WHEN a.is_redteam THEN 1 ELSE 0 END) as redteam_events,
    sum(CASE WHEN NOT a.is_redteam THEN 1 ELSE 0 END) as benign_events;

// Query 2: Count events by authentication type
MATCH (a:AuthEvent)
RETURN a.auth_type, count(*) as count
ORDER BY count DESC;

// Query 3: Find all red team events
MATCH (a:AuthEvent)
WHERE a.is_redteam = true
RETURN a.time, a.auth_type, a.success
ORDER BY a.time;

// Query 4: Red team user activity
MATCH (a:AuthEvent)<-[:INITIATED]-(u:User)
WHERE a.is_redteam = true
RETURN u.name, count(*) as activity_count
ORDER BY activity_count DESC;

// Query 5: Find users with most computer connections
MATCH (u:User)-[:AUTHENTICATED_FROM]->(c:Computer)
RETURN u.name, count(DISTINCT c) as computer_count
ORDER BY computer_count DESC LIMIT 10;

// Query 6: Find computers with most authentication events
MATCH (a:AuthEvent)-[:AUTH_DEST]->(c:Computer)
RETURN c.name, count(a) as auth_count
ORDER BY auth_count DESC LIMIT 10;

// Query 7: Events by hour of day
MATCH (a:AuthEvent)
RETURN a.timestamp.hour as hour, count(*) as event_count
ORDER BY hour;

// Query 8: Find authentication patterns around red team events
MATCH (rt:AuthEvent {is_redteam: true})
MATCH (other:AuthEvent)
WHERE abs(other.time - rt.time) <= 300  // Within 5 minutes
AND other <> rt
RETURN rt.time, count(other) as nearby_events
ORDER BY nearby_events DESC;

// Query 9: Network analysis - find critical computers
MATCH (c:Computer)
OPTIONAL MATCH (c)<-[:AUTH_SOURCE]-(a1:AuthEvent)
OPTIONAL MATCH (c)<-[:AUTH_DEST]-(a2:AuthEvent)
RETURN c.name, 
       count(DISTINCT a1) as outgoing_auths,
       count(DISTINCT a2) as incoming_auths,
       count(DISTINCT a1) + count(DISTINCT a2) as total_auths
ORDER BY total_auths DESC LIMIT 20;

// Query 10: Lateral movement detection
MATCH (u:User)-[:INITIATED]->(a1:AuthEvent)-[:AUTH_DEST]->(c1:Computer)
MATCH (u)-[:INITIATED]->(a2:AuthEvent)-[:AUTH_SOURCE]->(c1)
MATCH (a2)-[:AUTH_DEST]->(c2:Computer)
WHERE a2.time > a1.time 
AND a2.time - a1.time <= 3600  // Within 1 hour
AND c1 <> c2
RETURN u.name, c1.name as intermediate_computer, c2.name as target_computer,
       a1.time as first_auth, a2.time as second_auth,
       (a2.time - a1.time) as time_diff_seconds
ORDER BY time_diff_seconds;

// Query 11: Failed authentication analysis
MATCH (a:AuthEvent)
WHERE a.success = 'Failure'
MATCH (a)<-[:INITIATED]-(u:User)
MATCH (a)-[:AUTH_DEST]->(c:Computer)
RETURN u.name, c.name, count(*) as failed_attempts
ORDER BY failed_attempts DESC LIMIT 20;

// Query 12: Red team timeline analysis
MATCH (a:AuthEvent {is_redteam: true})
MATCH (a)<-[:INITIATED]-(u:User)
MATCH (a)-[:AUTH_SOURCE]->(sc:Computer)
MATCH (a)-[:AUTH_DEST]->(dc:Computer)
RETURN a.time, u.name as user, sc.name as source, dc.name as dest, a.success
ORDER BY a.time;

// Query 13: Authentication type patterns for red team vs benign
MATCH (a:AuthEvent)
RETURN a.auth_type, a.is_redteam,
       count(*) as count,
       avg(toFloat(a.time)) as avg_time
ORDER BY a.auth_type, a.is_redteam;

// Query 14: Find computers involved in both red team and benign activities
MATCH (rt:AuthEvent {is_redteam: true})-[:AUTH_DEST]->(c:Computer)
MATCH (benign:AuthEvent {is_redteam: false})-[:AUTH_DEST]->(c)
RETURN c.name,
       count(DISTINCT rt) as redteam_events,
       count(DISTINCT benign) as benign_events
ORDER BY redteam_events DESC, benign_events DESC;

// Query 15: Time-based clustering of authentication events
MATCH (a:AuthEvent)
WITH a.time - (a.time % 3600) as hour_bucket, a.is_redteam, count(*) as events
RETURN hour_bucket, 
       sum(CASE WHEN a.is_redteam THEN events ELSE 0 END) as redteam_in_hour,
       sum(CASE WHEN NOT a.is_redteam THEN events ELSE 0 END) as benign_in_hour
ORDER BY hour_bucket;

// Performance optimization queries
// ===============================

// Create additional indexes if needed for better query performance
CREATE INDEX user_auth_idx IF NOT EXISTS FOR ()-[r:INITIATED]-() ON (r);
CREATE INDEX comp_auth_idx IF NOT EXISTS FOR ()-[r:AUTH_DEST]-() ON (r);

// Query to check database statistics
CALL db.stats.retrieve('GRAPH COUNTS');

// Query to show constraint and index information
SHOW CONSTRAINTS;
SHOW INDEXES;
