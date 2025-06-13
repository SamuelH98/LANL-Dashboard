// ========================================
// PART 1: Create constraints and indexes
// ========================================
CREATE CONSTRAINT user_name_unique IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE;
CREATE CONSTRAINT computer_name_unique IF NOT EXISTS FOR (c:Computer) REQUIRE c.name IS UNIQUE;
CREATE INDEX auth_time_index IF NOT EXISTS FOR (a:AuthEvent) ON (a.time);
CREATE INDEX auth_success_index IF NOT EXISTS FOR (a:AuthEvent) ON (a.success);
CREATE INDEX auth_type_index IF NOT EXISTS FOR (a:AuthEvent) ON (a.auth_type);
CREATE INDEX redteam_label_index IF NOT EXISTS FOR (a:AuthEvent) ON (a.is_redteam);

// ========================================
// PART 2: Memory-optimized import (Neo4j 5.x+ syntax)
// ========================================

// RECOMMENDED APPROACH: Use the two-step process from PART 3 below
// This part is kept for reference but PART 3 is the preferred method

// ========================================
// PART 3: Alternative approach - Split into smaller batches
// ========================================

// Step 1: Pre-create all users and computers to avoid repeated MERGE operations
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.features IS NOT NULL AND row.label IS NOT NULL
WITH row, 
     split(replace(replace(row.features, '"', ''), '\n', ''), ',') AS features
WHERE size(features) = 9
WITH DISTINCT trim(features[1]) AS source_user, trim(features[2]) AS dest_user,
     trim(features[3]) AS source_computer, trim(features[4]) AS dest_computer
UNWIND [source_user, dest_user] AS user_name
WITH COLLECT(DISTINCT user_name) AS users, 
     COLLECT(DISTINCT source_computer) + COLLECT(DISTINCT dest_computer) AS computers
UNWIND users AS user_name
MERGE (u:User {name: user_name})
WITH computers
UNWIND computers AS computer_name  
MERGE (c:Computer {name: computer_name});

// Step 2: Import authentication events in smaller batches
CALL {
    LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
    WITH row WHERE row.features IS NOT NULL AND row.label IS NOT NULL
    WITH row, 
         split(replace(replace(row.features, '"', ''), '\n', ''), ',') AS features
    WHERE size(features) = 9
    WITH row,
         toInteger(features[0]) AS event_time,
         trim(features[1]) AS source_user,
         trim(features[2]) AS dest_user, 
         trim(features[3]) AS source_computer,
         trim(features[4]) AS dest_computer,
         trim(features[5]) AS auth_type,
         trim(features[6]) AS logon_type,
         trim(features[7]) AS auth_orientation,
         trim(features[8]) AS success,
         toInteger(row.label) AS is_redteam
    
    // Find existing nodes
    MATCH (su:User {name: source_user})
    MATCH (du:User {name: dest_user})
    MATCH (sc:Computer {name: source_computer})
    MATCH (dc:Computer {name: dest_computer})
    
    // Create authentication event
    CREATE (auth:AuthEvent {
        time: event_time,
        auth_type: auth_type,
        logon_type: logon_type,
        auth_orientation: auth_orientation,
        success: success,
        is_redteam: is_redteam,
        timestamp: datetime({epochSeconds: event_time})
    })
    
    // Create relationships
    CREATE (su)-[:AUTHENTICATED_FROM]->(sc)
    CREATE (du)-[:AUTHENTICATED_TO]->(dc)
    CREATE (auth)-[:SOURCE_USER]->(su)
    CREATE (auth)-[:DEST_USER]->(du)
    CREATE (auth)-[:SOURCE_COMPUTER]->(sc)
    CREATE (auth)-[:DEST_COMPUTER]->(dc)
    
    // Handle red team events
    FOREACH (ignore IN CASE WHEN is_redteam = 1 THEN [1] ELSE [] END |
        SET auth:RedTeamEvent
    )
    
    RETURN count(*) AS processed
} IN TRANSACTIONS OF 500 ROWS;

// ========================================
// PART 4: Create red team activity node and relationships
// ========================================
MERGE (rt:RedTeamActivity {name: "Red Team Campaign"});

MATCH (auth:RedTeamEvent), (rt:RedTeamActivity {name: "Red Team Campaign"})
WITH auth, rt
CALL {
    WITH auth, rt
    CREATE (auth)-[:PART_OF]->(rt)
} IN TRANSACTIONS OF 1000 ROWS;

// ========================================
// PART 5: Create summary statistics
// ========================================
MATCH (a:AuthEvent)
WITH count(a) as total_events, 
     sum(CASE WHEN a.is_redteam = 1 THEN 1 ELSE 0 END) as redteam_events,
     count(DISTINCT a.time) as unique_timestamps
CREATE (stats:ImportStats {
    total_events: total_events,
    redteam_events: redteam_events,
    benign_events: total_events - redteam_events,
    unique_timestamps: unique_timestamps,
    import_date: datetime()
});

// ========================================
// PART 6: Validation queries
// ========================================

// Show import statistics
MATCH (stats:ImportStats)
RETURN stats.total_events AS TotalEvents,
       stats.redteam_events AS RedTeamEvents,
       stats.benign_events AS BenignEvents,
       stats.unique_timestamps AS UniqueTimestamps,
       stats.import_date AS ImportDate;

// Show sample of imported data
MATCH (a:AuthEvent)
RETURN a.time, a.auth_type, a.success, a.is_redteam
ORDER BY a.time
LIMIT 10;

// Show node counts
MATCH (u:User) WITH count(u) AS users
MATCH (c:Computer) WITH users, count(c) AS computers  
MATCH (a:AuthEvent) WITH users, computers, count(a) AS auth_events
MATCH (rt:RedTeamEvent) WITH users, computers, auth_events, count(rt) AS redteam_events
RETURN users, computers, auth_events, redteam_events;
