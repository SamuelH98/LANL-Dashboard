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
// PART 2: Pre-create all users and computers
// ========================================

// Step 1: Create all unique users
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.features IS NOT NULL AND row.label IS NOT NULL
WITH row, 
     split(replace(replace(row.features, '"', ''), '\n', ''), ',') AS features
WHERE size(features) = 9
WITH DISTINCT trim(features[1]) AS source_user, trim(features[2]) AS dest_user
UNWIND [source_user, dest_user] AS user_name
WITH DISTINCT user_name
MERGE (u:User {name: user_name});

// Step 2: Create all unique computers
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.features IS NOT NULL AND row.label IS NOT NULL
WITH row, 
     split(replace(replace(row.features, '"', ''), '\n', ''), ',') AS features
WHERE size(features) = 9
WITH DISTINCT trim(features[3]) AS source_computer, trim(features[4]) AS dest_computer
UNWIND [source_computer, dest_computer] AS computer_name
WITH DISTINCT computer_name
MERGE (c:Computer {name: computer_name});

// ========================================
// PART 3: Import authentication events using APOC (if available)
// ========================================

// Option 3A: Using APOC periodic iterate (recommended if APOC is available)
// CALL apoc.periodic.iterate(
//   "LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
//    WITH row WHERE row.features IS NOT NULL AND row.label IS NOT NULL
//    WITH row, split(replace(replace(row.features, '\"', ''), '\n', ''), ',') AS features
//    WHERE size(features) = 9
//    RETURN row, features",
//   "WITH row, features,
//          toInteger(features[0]) AS event_time,
//          trim(features[1]) AS source_user,
//          trim(features[2]) AS dest_user, 
//          trim(features[3]) AS source_computer,
//          trim(features[4]) AS dest_computer,
//          trim(features[5]) AS auth_type,
//          trim(features[6]) AS logon_type,
//          trim(features[7]) AS auth_orientation,
//          trim(features[8]) AS success,
//          toInteger(row.label) AS is_redteam
//    
//    MATCH (su:User {name: source_user})
//    MATCH (du:User {name: dest_user})
//    MATCH (sc:Computer {name: source_computer})
//    MATCH (dc:Computer {name: dest_computer})
//    
//    CREATE (auth:AuthEvent {
//        time: event_time,
//        auth_type: auth_type,
//        logon_type: logon_type,
//        auth_orientation: auth_orientation,
//        success: success,
//        is_redteam: is_redteam,
//        timestamp: datetime({epochSeconds: event_time})
//    })
//    
//    CREATE (su)-[:AUTHENTICATED_FROM]->(sc)
//    CREATE (du)-[:AUTHENTICATED_TO]->(dc)
//    CREATE (auth)-[:SOURCE_USER]->(su)
//    CREATE (auth)-[:DEST_USER]->(du)
//    CREATE (auth)-[:SOURCE_COMPUTER]->(sc)
//    CREATE (auth)-[:DEST_COMPUTER]->(dc)
//    
//    FOREACH (ignore IN CASE WHEN is_redteam = 1 THEN [1] ELSE [] END |
//        SET auth:RedTeamEvent
//    )",
//   {batchSize: 500, parallel: false}
// );

// ========================================
// PART 3B: Alternative without APOC - Standard approach
// ========================================

// Import authentication events (run this query multiple times if needed for large datasets)
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
CREATE (su)-[:AUTHENTICATED_FROM]->(sc),
       (du)-[:AUTHENTICATED_TO]->(dc),
       (auth)-[:SOURCE_USER]->(su),
       (auth)-[:DEST_USER]->(du),
       (auth)-[:SOURCE_COMPUTER]->(sc),
       (auth)-[:DEST_COMPUTER]->(dc)

// Handle red team events
FOREACH (ignore IN CASE WHEN is_redteam = 1 THEN [1] ELSE [] END |
    SET auth:RedTeamEvent
);

// ========================================
// PART 4: Create red team activity node and relationships
// ========================================
MERGE (rt:RedTeamActivity {name: "Red Team Campaign"});

// Link red team events to the campaign
MATCH (auth:RedTeamEvent), (rt:RedTeamActivity {name: "Red Team Campaign"})
CREATE (auth)-[:PART_OF]->(rt);

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

// ========================================
// OPTIONAL: Memory management for large datasets
// ========================================

// If you're dealing with very large datasets, you can split the main import into chunks
// by adding a LIMIT clause and running multiple times with SKIP:

// Example for chunked processing:
// LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
// WITH row WHERE row.features IS NOT NULL AND row.label IS NOT NULL
// SKIP 0 LIMIT 1000  // Adjust SKIP value for subsequent runs
// ... rest of import logic

// ========================================
// TROUBLESHOOTING NOTES
// ========================================

// 1. If you get memory errors, reduce batch sizes or use the chunked approach above
// 2. If APOC is available, uncomment and use Option 3A for better performance
// 3. For very large datasets, consider using neo4j-admin import tool instead
// 4. Monitor heap usage during import and adjust Neo4j memory settings if needed
