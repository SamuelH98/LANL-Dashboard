// ========================================
// PART 0: Initialize logging
// ========================================
CREATE (log:ImportLog {
    import_id: randomUUID(),
    start_time: datetime(),
    status: "STARTING",
    current_step: "INITIALIZATION"
});

// ========================================
// PART 1: Create constraints and indexes
// ========================================
MATCH (log:ImportLog) WHERE log.status = "STARTING"
SET log.current_step = "CREATING_CONSTRAINTS_AND_INDEXES",
    log.constraints_start = datetime();

CREATE CONSTRAINT user_name_unique IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE;
CREATE CONSTRAINT computer_name_unique IF NOT EXISTS FOR (c:Computer) REQUIRE c.name IS UNIQUE;
CREATE INDEX auth_time_index IF NOT EXISTS FOR (a:AuthEvent) ON (a.time);
CREATE INDEX auth_success_index IF NOT EXISTS FOR (a:AuthEvent) ON (a.success);
CREATE INDEX auth_type_index IF NOT EXISTS FOR (a:AuthEvent) ON (a.auth_type);
CREATE INDEX redteam_label_index IF NOT EXISTS FOR (a:AuthEvent) ON (a.is_redteam);

MATCH (log:ImportLog) WHERE log.current_step = "CREATING_CONSTRAINTS_AND_INDEXES"
SET log.constraints_end = datetime(),
    log.constraints_duration = duration.between(log.constraints_start, datetime()).milliseconds;

// ========================================
// PART 2: Memory-optimized import (Neo4j 5.x+ syntax)
// ========================================

// RECOMMENDED APPROACH: Use the two-step process from PART 3 below
// This part is kept for reference but PART 3 is the preferred method

// ========================================
// PART 3: Alternative approach - Split into smaller batches
// ========================================

// Step 1: Pre-create all users and computers to avoid repeated MERGE operations
MATCH (log:ImportLog) WHERE log.current_step = "CREATING_CONSTRAINTS_AND_INDEXES"
SET log.current_step = "PRECREATING_NODES",
    log.precreate_start = datetime();

CALL {
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
    WITH users, computers, count(*) AS users_created
    UNWIND computers AS computer_name  
    MERGE (c:Computer {name: computer_name})
    RETURN users_created, count(*) AS computers_created
} IN TRANSACTIONS;

// Log node creation results
MATCH (log:ImportLog) WHERE log.current_step = "PRECREATING_NODES"
MATCH (u:User) WITH log, count(u) AS total_users
MATCH (c:Computer) WITH log, total_users, count(c) AS total_computers
SET log.users_created = total_users,
    log.computers_created = total_computers,
    log.precreate_end = datetime(),
    log.precreate_duration = duration.between(log.precreate_start, datetime()).milliseconds,
    log.current_step = "IMPORTING_AUTH_EVENTS",
    log.auth_import_start = datetime();

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
    
    // Find existing nodes with error handling
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

// Log authentication events import results
MATCH (log:ImportLog) WHERE log.current_step = "IMPORTING_AUTH_EVENTS"
MATCH (a:AuthEvent) 
WITH log, count(a) AS total_auth_events, 
     sum(CASE WHEN a.is_redteam = 1 THEN 1 ELSE 0 END) AS redteam_events
SET log.auth_events_created = total_auth_events,
    log.redteam_events_created = redteam_events,
    log.benign_events_created = total_auth_events - redteam_events,
    log.auth_import_end = datetime(),
    log.auth_import_duration = duration.between(log.auth_import_start, datetime()).milliseconds;

// ========================================
// PART 4: Create red team activity node and relationships
// ========================================
MATCH (log:ImportLog) WHERE log.current_step = "IMPORTING_AUTH_EVENTS"
SET log.current_step = "CREATING_REDTEAM_RELATIONSHIPS",
    log.redteam_rel_start = datetime();

MERGE (rt:RedTeamActivity {name: "Red Team Campaign"});

CALL {
    MATCH (auth:RedTeamEvent), (rt:RedTeamActivity {name: "Red Team Campaign"})
    WITH auth, rt
    CREATE (auth)-[:PART_OF]->(rt)
    RETURN count(*) AS relationships_created
} IN TRANSACTIONS OF 1000 ROWS;

// Log red team relationships
MATCH (log:ImportLog) WHERE log.current_step = "CREATING_REDTEAM_RELATIONSHIPS"
MATCH (rt:RedTeamActivity)-[r:PART_OF]-(auth)
WITH log, count(r) AS redteam_relationships
SET log.redteam_relationships_created = redteam_relationships,
    log.redteam_rel_end = datetime(),
    log.redteam_rel_duration = duration.between(log.redteam_rel_start, datetime()).milliseconds;

// ========================================
// PART 5: Create summary statistics
// ========================================
MATCH (log:ImportLog) WHERE log.current_step = "CREATING_REDTEAM_RELATIONSHIPS"
SET log.current_step = "CREATING_STATISTICS",
    log.stats_start = datetime();

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

// Finalize logging
MATCH (log:ImportLog) WHERE log.current_step = "CREATING_STATISTICS"
MATCH (stats:ImportStats)
SET log.current_step = "COMPLETED",
    log.status = "SUCCESS",
    log.end_time = datetime(),
    log.total_duration = duration.between(log.start_time, datetime()).milliseconds,
    log.stats_end = datetime(),
    log.stats_duration = duration.between(log.stats_start, datetime()).milliseconds,
    log.final_total_events = stats.total_events,
    log.final_redteam_events = stats.redteam_events,
    log.final_benign_events = stats.benign_events;

// ========================================
// PART 6: Validation queries with logging
// ========================================

// Show detailed import log
MATCH (log:ImportLog) WHERE log.status = "SUCCESS"
RETURN log.import_id AS ImportID,
       log.start_time AS StartTime,
       log.end_time AS EndTime,
       log.total_duration AS TotalDurationMs,
       log.users_created AS UsersCreated,
       log.computers_created AS ComputersCreated,
       log.auth_events_created AS AuthEventsCreated,
       log.redteam_events_created AS RedTeamEventsCreated,
       log.benign_events_created AS BenignEventsCreated,
       log.redteam_relationships_created AS RedTeamRelationshipsCreated,
       log.constraints_duration AS ConstraintsDurationMs,
       log.precreate_duration AS PrecreateDurationMs,
       log.auth_import_duration AS AuthImportDurationMs,
       log.redteam_rel_duration AS RedTeamRelDurationMs,
       log.stats_duration AS StatsDurationMs;

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

// Show node counts with timing
CALL {
    MATCH (u:User) RETURN count(u) AS users
} 
CALL {
    MATCH (c:Computer) RETURN count(c) AS computers
}
CALL {
    MATCH (a:AuthEvent) RETURN count(a) AS auth_events
}
CALL {
    MATCH (rt:RedTeamEvent) RETURN count(rt) AS redteam_events
}
CALL {
    MATCH ()-[r:PART_OF]->(:RedTeamActivity) RETURN count(r) AS redteam_relationships
}
RETURN users, computers, auth_events, redteam_events, redteam_relationships, datetime() AS QueryTime;

// ========================================
// PART 7: Error handling and recovery queries
// ========================================

// Check for failed imports
MATCH (log:ImportLog) WHERE log.status <> "SUCCESS"
RETURN log.import_id AS FailedImportID,
       log.current_step AS FailedAtStep,
       log.start_time AS StartTime,
       CASE WHEN log.end_time IS NULL THEN "STILL_RUNNING" ELSE log.end_time END AS EndTime;

// Clean up failed import logs (run manually if needed)
// MATCH (log:ImportLog) WHERE log.status <> "SUCCESS" DELETE log;

// Performance analysis query
MATCH (log:ImportLog) WHERE log.status = "SUCCESS"
WITH log,
     log.constraints_duration AS constraints,
     log.precreate_duration AS precreate, 
     log.auth_import_duration AS auth_import,
     log.redteam_rel_duration AS redteam_rel,
     log.stats_duration AS stats
RETURN log.import_id AS ImportID,
       constraints AS ConstraintsMs,
       precreate AS PrecreateMs,
       auth_import AS AuthImportMs,
       redteam_rel AS RedTeamRelMs,
       stats AS StatsMs,
       (constraints + precreate + auth_import + redteam_rel + stats) AS TotalStepsMs,
       log.total_duration AS TotalDurationMs,
       round((auth_import * 100.0) / log.total_duration) AS AuthImportPercent,
       round(log.auth_events_created * 1000.0 / auth_import) AS EventsPerSecond;