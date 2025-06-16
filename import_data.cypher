CALL apoc.periodic.iterate(
  'LOAD CSV WITH HEADERS FROM "https://storage.googleapis.com/datalol-988/output.csv" AS row RETURN row',
  '
  WITH row 
  WHERE row.`source user@domain` IS NOT NULL AND row.`source user@domain` <> ""
  
  MERGE (srcUser:User {id: split(row.`source user@domain`, "@")[0]})
  SET srcUser.domain = split(row.`source user@domain`, "@")[1]
  
  MERGE (dstUser:User {id: split(row.`destination user@domain`, "@")[0]})
  ON CREATE SET dstUser.domain = split(row.`destination user@domain`, "@")[1]
  
  MERGE (srcComp:Computer {id: row.`source computer`})
  MERGE (dstComp:Computer {id: row.`destination computer`})
  
  CREATE (event:AuthEvent {
    timestamp: toInteger(row.time),
    auth_type: row.`authentication type`,
    logon_type: row.`logon type`,
    orientation: row.`authentication orientation`,
    success: row.`success/failure` = "Success"
  })
  
  CREATE (srcUser)-[:AUTHENTICATED_FROM]->(srcComp)
  CREATE (srcUser)-[:AUTHENTICATED_TO]->(dstComp)
  
  CREATE (event)-[:SOURCE_USER]->(srcUser)
  CREATE (event)-[:DEST_USER]->(dstUser)
  CREATE (event)-[:SOURCE_COMPUTER]->(srcComp)
  CREATE (event)-[:DEST_COMPUTER]->(dstComp)
  
  FOREACH (_ IN CASE WHEN toInteger(row.label) = 1 THEN [1] ELSE [] END |
    MERGE (red:RedTeamActivity {id: "red_team_events"})
    CREATE (event)-[:PART_OF]->(red)
  )
  ',
  {batchSize: 10000, parallel: false}
)
