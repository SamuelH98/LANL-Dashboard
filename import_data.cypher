// CORRECTED VERSION - Matches your actual CSV format
// Your CSV has: features (column A) and label (column B)
// Features contain: time,source_user,dest_user,source_computer,dest_computer,auth_type,logon_type,auth_orientation,success

// Step 1: Create constraints FIRST
CREATE CONSTRAINT user_name_unique IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE;
CREATE CONSTRAINT computer_name_unique IF NOT EXISTS FOR (c:Computer) REQUIRE c.name IS UNIQUE;

// Step 2: Pre-create all unique users
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.features IS NOT NULL AND trim(row.features) <> ''
WITH split(row.features, ',') AS features
WHERE size(features) >= 9
WITH DISTINCT trim(features[1]) AS source_user, trim(features[2]) AS dest_user
UNWIND [source_user, dest_user] AS user_name
WITH DISTINCT user_name WHERE user_name <> '' AND user_name IS NOT NULL
MERGE (u:User {name: user_name});

// Step 3: Pre-create all unique computers
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.features IS NOT NULL AND trim(row.features) <> ''
WITH split(row.features, ',') AS features
WHERE size(features) >= 9
WITH DISTINCT trim(features[3]) AS source_computer, trim(features[4]) AS dest_computer
UNWIND [source_computer, dest_computer] AS computer_name
WITH DISTINCT computer_name WHERE computer_name <> '' AND computer_name IS NOT NULL
MERGE (c:Computer {name: computer_name});

// Step 4: Create indexes AFTER nodes are created
CREATE INDEX auth_time_index IF NOT EXISTS FOR (a:AuthEvent) ON (a.time);
CREATE INDEX auth_success_index IF NOT EXISTS FOR (a:AuthEvent) ON (a.success);
CREATE INDEX auth_type_index IF NOT EXISTS FOR (a:AuthEvent) ON (a.auth_type);
CREATE INDEX redteam_label_index IF NOT EXISTS FOR (a:AuthEvent) ON (a.is_redteam);

// Step 5: Import main data with transaction batching
CALL {
    LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
    WITH row WHERE row.features IS NOT NULL AND row.label IS NOT NULL 
                AND trim(row.features) <> '' AND trim(row.label) <> ''
    WITH row, split(row.features, ',') AS features
    WHERE size(features) >= 9
    WITH row,
         // Parse the features - your format: time,source_user,dest_user,source_computer,dest_computer,auth_type,logon_type,auth_orientation,success
         toInteger(trim(features[0])) AS event_time,
         trim(features[1]) AS source_user,
         trim(features[2]) AS dest_user, 
         trim(features[3]) AS source_computer,
         trim(features[4]) AS dest_computer,
         trim(features[5]) AS auth_type,
         trim(features[6]) AS logon_type,
         trim(features[7]) AS auth_orientation,
         trim(features[8]) AS success,
         toInteger(trim(row.label)) AS is_redteam
    
    // Skip rows with empty critical fields
    WHERE source_user <> '' AND dest_user <> '' AND source_computer <> '' AND dest_computer <> ''
    
    // Find existing nodes (faster than MERGE since they already exist)
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
    
    // Create all relationships
    CREATE (su)-[:AUTHENTICATED_FROM]->(sc)
    CREATE (du)-[:AUTHENTICATED_TO]->(dc)
    CREATE (auth)-[:SOURCE_USER]->(su)
    CREATE (auth)-[:DEST_USER]->(du)
    CREATE (auth)-[:SOURCE_COMPUTER]->(sc)
    CREATE (auth)-[:DEST_COMPUTER]->(dc)
    
    // Add red team label if applicable
    WITH auth, is_redteam
    WHERE is_redteam = 1
    SET auth:RedTeamEvent
    
    RETURN count(*) AS processed
} IN TRANSACTIONS OF 1000 ROWS;

// Step 6: Create red team activity node and connect red team events
MERGE (rt:RedTeamActivity {name: "Red Team Campaign"});

CALL {
    MATCH (auth:RedTeamEvent)
    MATCH (rt:RedTeamActivity {name: "Red Team Campaign"})
    CREATE (auth)-[:PART_OF]->(rt)
    RETURN count(*) AS connected
} IN TRANSACTIONS OF 5000 ROWS;

// Step 7: Create summary statistics
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

// Step 8: Validation queries
MATCH (a:AuthEvent)
RETURN a.time, a.auth_type, a.success, a.is_redteam
ORDER BY a.time
LIMIT 10;

// Additional validation - check data distribution
MATCH (u:User) RETURN count(u) AS total_users;
MATCH (c:Computer) RETURN count(c) AS total_computers;
MATCH (a:AuthEvent) RETURN count(a) AS total_events;
MATCH (a:AuthEvent) WHERE a.is_redteam = 1 RETURN count(a) AS redteam_events;

// DEBUGGING VERSION - Use this first to test with a small sample
/*
// Test with first 10 rows to debug
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.features IS NOT NULL AND row.label IS NOT NULL 
WITH row, split(row.features, ',') AS features
WHERE size(features) >= 9
WITH row,
     toInteger(trim(features[0])) AS event_time,
     trim(features[1]) AS source_user,
     trim(features[2]) AS dest_user, 
     trim(features[3]) AS source_computer,
     trim(features[4]) AS dest_computer,
     trim(features[5]) AS auth_type,
     trim(features[6]) AS logon_type,
     trim(features[7]) AS auth_orientation,
     trim(features[8]) AS success,
     toInteger(trim(row.label)) AS is_redteam
RETURN event_time, source_user, dest_user, source_computer, dest_computer, 
       auth_type, logon_type, auth_orientation, success, is_redteam
LIMIT 10;
*/
