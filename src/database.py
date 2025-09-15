"""
database.py - Combined Database Connection and Data Import Module
Provides database connection management and data import functionality
"""

import os
import pandas as pd
from typing import Dict, Any, Optional
from datetime import datetime
import traceback
from neo4j import GraphDatabase, basic_auth
from dotenv import load_dotenv

load_dotenv()

def add_debug_output(message: str):
    """Debug output function - will be overridden by UI module"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")

class Neo4jDatabase:
    _instance: Optional['Neo4jDatabase'] = None
    _driver = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Neo4jDatabase, cls).__new__(cls)
            cls._instance._connect()
        return cls._instance

    def _connect(self):
        """Establish the database connection"""
        if not self._driver:
            self._driver = GraphDatabase.driver(
                os.getenv("NEO4J_URI", "bolt://neo4j:7687"),
                auth=basic_auth(
                    os.getenv("NEO4J_USERNAME", "neo4j"),
                    os.getenv("NEO4J_PASSWORD", "password123"),
                ),
            )
            if not self.is_connected():
                print("❌ Failed to connect to Neo4j database! Is the server running?")
            else:
                print("✅ Verified connection to Neo4j database.")
    
    def is_connected(self) -> bool:
        """Check if the Neo4j connection is truly available by running a test query."""
        if not hasattr(self, 'driver') or not self.driver:
            print("Driver not initialized")
            return False
        
        try:
            self.driver.verify_connectivity()
            with self.driver.session() as session:
                result = session.run("RETURN 1 AS test")
                record = result.single()
                return record is not None and record.get("test") == 1
        except Exception as e:
            print(f"Connection check failed: {type(e).__name__}: {e}")
            return False

    @property
    def driver(self):
        """Get the Neo4j driver instance"""
        return self._driver

    def close(self):
        """Close the database connection"""
        if self._driver:
            self._driver.close()
            self._driver = None
            Neo4jDatabase._instance = None

    def execute_query(self, query: str, parameters: Dict[str, Any] = None, database: str = "authdata"):
        """Execute a Cypher query and return the results"""
        try:
            with self.driver.session(database=database) as session:
                result = session.run(query, parameters or {})
                records = [record.data() for record in result]
                return {"success": True, "records": records}
        except Exception as e:
            return {"success": False, "error": str(e)}

    
    def clear_existing_data(self) -> Dict[str, Any]:
        """Alternative method using APOC procedures if available (more efficient for large datasets)"""
       
        add_debug_output("Clearing existing data using APOC...")
        
        with self.driver.session(database="authdata") as session:
            
            # Use APOC for efficient deletion
            # Drop constraints and indexes first
            constraints = session.run("SHOW CONSTRAINTS").data()
            for c in constraints:
                try:
                    session.run(f"DROP CONSTRAINT `{c['name']}`")
                except:
                    pass
            
            indexes = session.run("SHOW INDEXES").data()
            for i in indexes:
                if not i['name'].startswith('idx_') and i['type'] != 'LOOKUP':
                    try:
                        session.run(f"DROP INDEX `{i['name']}`")
                    except:
                        pass
        
            # Use APOC to delete everything efficiently
            result = session.run("CALL apoc.periodic.iterate('MATCH ()-[r]-() RETURN r', 'DELETE r', {batchSize:10000})")
            rel_summary = result.single()
            
            result = session.run("CALL apoc.periodic.iterate('MATCH (n) RETURN n', 'DELETE n', {batchSize:10000})")
            node_summary = result.single()
            
            add_debug_output("Data cleared using APOC procedures")
            return {"success": True, "message": "All existing data cleared successfully using APOC"}
            
        
                

    def create_schema(self) -> Dict[str, Any]:
        """Create constraints and indexes"""
        try:
            add_debug_output("Creating database schema...")
            with self.driver.session(database="authdata") as session:
                schema_queries = [
                    "CREATE CONSTRAINT user_unique_name IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE",
                    "CREATE CONSTRAINT computer_unique_name IF NOT EXISTS FOR (c:Computer) REQUIRE c.name IS UNIQUE",
                    "CREATE INDEX auth_time_idx IF NOT EXISTS FOR (a:AuthEvent) ON (a.time)",
                    "CREATE INDEX auth_timestamp_idx IF NOT EXISTS FOR (a:AuthEvent) ON (a.timestamp)",
                    "CREATE INDEX auth_success_idx IF NOT EXISTS FOR (a:AuthEvent) ON (a.success)",
                    "CREATE INDEX auth_redteam_idx IF NOT EXISTS FOR (a:AuthEvent) ON (a.is_redteam)",
                    "CREATE INDEX auth_type_idx IF NOT EXISTS FOR (a:AuthEvent) ON (a.auth_type)"
                ]
                for query in schema_queries:
                    session.run(query)
                
                add_debug_output("Database schema created successfully.")
                return {"success": True, "message": "Database schema created successfully"}
                
        except Exception as e:
            add_debug_output(f"Schema creation error: {str(e)}")
            return {"success": False, "error": f"Failed to create schema: {str(e)}"}

    def validate_csv_file(self, csv_file_path: str) -> Dict[str, Any]:
        """Validate CSV file exists and has required columns"""
        try:
            if not os.path.exists(csv_file_path):
                return {"valid": False, "error": f"File not found: {csv_file_path}"}
            
            df = pd.read_csv(csv_file_path, nrows=5)
            # These column names match the LANL dataset
            required_columns = [
                'time',
                'source user@domain',
                'destination user@domain',
                'source computer',
                'destination computer',
                'authentication type',
                'logon type',
                'authentication orientation',
                'success/failure',
                'label'
            ]
            
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                return {
                    "valid": False,
                    "error": f"Missing required columns: {missing_columns}",
                    "found_columns": list(df.columns)
                }
            
            # Use a more efficient way to get total row count
            total_rows = sum(1 for row in open(csv_file_path, 'r')) - 1 # Subtract header
            return {
                "valid": True,
                "total_rows": total_rows,
                "columns": list(df.columns),
                "sample_data": df.head(3).to_dict('records')
            }
            
        except Exception as e:
            return {"valid": False, "error": f"Error reading CSV file: {str(e)}"}

    def import_csv_data(self, csv_file_path: str, clear_existing: bool = False) -> Dict[str, Any]:
        """Import CSV data into Neo4j using the LOAD CSV command."""

        print(f"Importing data from {csv_file_path}...")
        try:
            validation = self.validate_csv_file(csv_file_path)
            if not validation["valid"]:
                return {"success": False, "error": validation["error"]}
            
            add_debug_output(f"Starting import of {validation['total_rows']} rows from {csv_file_path}")
            
            if clear_existing:
                clear_result = self.clear_existing_data()
                if not clear_result["success"]:
                    return clear_result

            schema_result = self.create_schema()
            if not schema_result["success"]:
                return schema_result
            
            import shutil
            target_path = '/import/output.csv'
            try:
                shutil.copyfile(csv_file_path, target_path)
            except Exception as e:
                return {"success": False, "error": f"Failed to copy file to import directory: {str(e)}"}
            import_query = """
LOAD CSV WITH HEADERS FROM 'file:///output.csv' AS row
WITH row WHERE row.time IS NOT NULL AND trim(row.time) <> '' 
    AND row.`source user@domain` IS NOT NULL AND trim(row.`source user@domain`) <> '' 
    AND row.`destination computer` IS NOT NULL AND trim(row.`destination computer`) <> ''
CALL {
  WITH row
  MERGE (source_user:User {name: trim(row.`source user@domain`)})
  MERGE (dest_user:User {name: trim(coalesce(row.`destination user@domain`, ''))})
  MERGE (source_comp:Computer {name: trim(coalesce(row.`source computer`, ''))})
  MERGE (dest_comp:Computer {name: trim(row.`destination computer`)})
  CREATE (auth:AuthEvent {
      time: toInteger(row.time),
      auth_type: trim(coalesce(row.`authentication type`, '')),
      logon_type: trim(coalesce(row.`logon type`, '')),
      auth_orientation: trim(coalesce(row.`authentication orientation`, '')),
      success: trim(coalesce(row.`success/failure`, '')),
      is_redteam: toBoolean(toInteger(coalesce(row.label, '0'))),
      timestamp: datetime({epochSeconds: toInteger(row.time)})
  })
  CREATE (auth)-[:FROM_USER]->(source_user)
  CREATE (auth)-[:TO_COMPUTER]->(dest_comp)
  CREATE (auth)-[:FROM_COMPUTER]->(source_comp)
} IN TRANSACTIONS OF 10000 ROWS
"""
            with self.driver.session(database="authdata") as session:
                session.run(import_query)
                add_debug_output("Bulk import query completed, gathering statistics...")
                stats_query = """
MATCH (a:AuthEvent)
RETURN
    count(a) as total_events,
    sum(CASE WHEN a.is_redteam THEN 1 ELSE 0 END) as redteam_events,
    sum(CASE WHEN NOT a.is_redteam THEN 1 ELSE 0 END) as benign_events
"""
                stats_result = session.run(stats_query).single()
                node_counts_query = "MATCH (n) RETURN labels(n)[0] as label, count(n) as count ORDER BY count DESC"
                node_counts = session.run(node_counts_query).data()
                add_debug_output("Data import completed successfully!")
                return {
                    "success": True,
                    "message": "Data import completed successfully",
                    "stats": {
                        "total_events": stats_result["total_events"],
                        "redteam_events": stats_result["redteam_events"],
                        "benign_events": stats_result["benign_events"],
                        "node_counts": node_counts
                    }
                }
        except Exception as e:
            error_msg = f"Import failed: {str(e)}"
            add_debug_output(f"ERROR: {error_msg}")
            add_debug_output(f"Full traceback: {traceback.format_exc()}")
            return {"success": False, "error": error_msg, "traceback": traceback.format_exc()}

    def get_database_stats(self) -> Dict[str, Any]:
        """Get current database statistics"""
        try:
            with self.driver.session(database="authdata") as session:
                node_query = "MATCH (n) RETURN labels(n)[0] as label, count(n) as count ORDER BY count DESC"
                node_counts = session.run(node_query).data()
                
                rel_query = "MATCH ()-[r]->() RETURN type(r) as relationship, count(r) as count ORDER BY count DESC"
                rel_counts = session.run(rel_query).data()
                
                auth_stats = {}
                if any(d.get('label') == 'AuthEvent' for d in node_counts):
                    stats_query = """
                        MATCH (a:AuthEvent)
                        RETURN
                            count(a) as total_events,
                            sum(CASE WHEN a.is_redteam THEN 1 ELSE 0 END) as redteam_events,
                            sum(CASE WHEN NOT a.is_redteam THEN 1 ELSE 0 END) as benign_events,
                            min(a.timestamp) as earliest_event,
                            max(a.timestamp) as latest_event
                    """
                    stats_data = session.run(stats_query).single()
                    if stats_data:
                        auth_stats = {k: v for k, v in stats_data.items() if v is not None}

                return {
                    "success": True,
                    "node_counts": node_counts,
                    "relationship_counts": rel_counts,
                    "auth_stats": auth_stats
                }
                
        except Exception as e:
            return {"success": False, "error": f"Failed to get database stats: {str(e)}"}

    def __del__(self):
        """Ensure connection is closed when the object is destroyed"""
        self.close()