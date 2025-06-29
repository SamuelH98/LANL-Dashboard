"""
Active Directory Red Team Analysis Agent using Pydantic AI

This agent analyzes Active Directory authentication data and red team events to:
- Detect suspicious authentication patterns
- Identify lateral movement attempts
- Analyze user and computer behavior
- Generate security insights and recommendations

Requirements:
pip install pydantic-ai neo4j python-dotenv
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import os
from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext
from neo4j import GraphDatabase, basic_auth
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

@dataclass
class ADAnalysisDependencies:
    """Dependencies for the AD analysis agent"""
    database: str = "neo4j"

class SecurityAnalysis(BaseModel):
    """Structured response for security analysis"""
    findings: List[str] = Field(description="List of security findings and observations")
    suspicious_activities: List[Dict[str, Any]] = Field(description="Suspicious activities detected")
    recommendations: List[str] = Field(description="Security recommendations")
    summary: str = Field(description="Executive summary of the analysis")
    risk_level: str = Field(description="Overall risk level: LOW, MEDIUM, HIGH, CRITICAL")

class Neo4jConnection:
    """Manages Neo4j database connection"""
    
    def __init__(self):
        self.driver = GraphDatabase.driver(
            os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            auth=basic_auth(
                "neo4j",
                "password123"
            )
        )
    
    def close(self):
        if self.driver:
            self.driver.close()
    
    def execute_query(self, query: str, parameters: Dict[str, Any] = None, database: str = "neo4j"):
        """Execute a Cypher query and return results"""
        try:
            with self.driver.session(database=database) as session:
                result = session.run(query, parameters or {})
                records = [record.data() for record in result]
                return {"success": True, "records": records, "error": None}
        except Exception as e:
            return {"success": False, "records": [], "error": str(e)}

# Initialize the AD Red Team Analysis agent
ad_agent = Agent[ADAnalysisDependencies, SecurityAnalysis](
    model="google-gla:gemini-2.5-pro-preview-05-06",
    deps_type=ADAnalysisDependencies,
    output_type=SecurityAnalysis,
    system_prompt=(
        "You are a cybersecurity expert specializing in Active Directory security analysis and red team detection. "
        "Analyze authentication events, user behavior, and computer interactions to identify potential security threats. "
        "Focus on detecting lateral movement, privilege escalation, suspicious login patterns, and other red team tactics. "
        "Provide actionable security recommendations and assess risk levels appropriately."
    ),
)

@ad_agent.tool
async def analyze_authentication_patterns(ctx: RunContext[ADAnalysisDependencies]) -> Dict[str, Any]:
    """
    Analyze authentication patterns to detect suspicious activities.
    
    Returns:
        Dictionary with authentication analysis results
    """
    connection = Neo4jConnection()
    
    try:
        # Get authentication event statistics
        auth_stats_query = """
        MATCH (ae:AuthEvent)
        RETURN 
            count(ae) as total_events,
            count(DISTINCT ae.name) as unique_users,
            ae.success as success_status,
            count(*) as event_count
        ORDER BY success_status
        """
        
        auth_stats = connection.execute_query(auth_stats_query)
        
        # Find failed login attempts
        failed_logins_query = """
        MATCH (ae:AuthEvent {success: false})
        RETURN ae.name as username, count(*) as failed_attempts
        ORDER BY failed_attempts DESC
        LIMIT 10
        """
        
        failed_logins = connection.execute_query(failed_logins_query)
        
        # Find off-hours authentication
        off_hours_query = """
        MATCH (ae:AuthEvent)
        WHERE ae.timestamp IS NOT NULL
        WITH ae, 
             toInteger(substring(ae.timestamp, 11, 2)) as hour
        WHERE hour < 6 OR hour > 22
        RETURN ae.name as username, ae.timestamp as time, count(*) as off_hours_count
        ORDER BY off_hours_count DESC
        LIMIT 10
        """
        
        off_hours = connection.execute_query(off_hours_query)
        
        return {
            "success": True,
            "records": [{
                "auth_statistics": auth_stats["records"],
                "failed_logins": failed_logins["records"],
                "off_hours_activity": off_hours["records"]
            }],
            "error": None
        }
        
    except Exception as e:
        return {"success": False, "records": [], "error": str(e)}
    finally:
        connection.close()

@ad_agent.tool
async def detect_lateral_movement(ctx: RunContext[ADAnalysisDependencies]) -> Dict[str, Any]:
    """
    Detect potential lateral movement patterns in the network.
    
    Returns:
        Dictionary with lateral movement analysis
    """
    connection = Neo4jConnection()
    
    try:
        # Find users accessing multiple computers
        multi_computer_query = """
        MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
        WITH u.name as username, collect(DISTINCT c.name) as computers, count(DISTINCT c.name) as computer_count
        WHERE computer_count > 3
        RETURN username, computers, computer_count
        ORDER BY computer_count DESC
        LIMIT 20
        """
        
        multi_computer = connection.execute_query(multi_computer_query)
        
        # Find rapid authentication across different computers
        rapid_auth_query = """
        MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
        WHERE ae.timestamp IS NOT NULL
        WITH u.name as username, ae.timestamp as timestamp, c.name as computer
        ORDER BY username, timestamp
        WITH username, collect({computer: computer, timestamp: timestamp}) as auth_sequence
        WHERE size(auth_sequence) > 5
        RETURN username, auth_sequence
        LIMIT 10
        """
        
        rapid_auth = connection.execute_query(rapid_auth_query)
        
        # Find computers with unusual authentication patterns
        unusual_computer_query = """
        MATCH (c:Computer)<-[:TO_COMPUTER]-(ae:AuthEvent)<-[:FROM_USER]-(u:User)
        WITH c.name as computer, collect(DISTINCT u.name) as users, count(DISTINCT u.name) as user_count
        WHERE user_count > 10
        RETURN computer, users, user_count
        ORDER BY user_count DESC
        LIMIT 10
        """
        
        unusual_computers = connection.execute_query(unusual_computer_query)
        
        return {
            "success": True,
            "records": [{
                "multi_computer_access": multi_computer["records"],
                "rapid_authentication": rapid_auth["records"],
                "unusual_computer_activity": unusual_computers["records"]
            }],
            "error": None
        }
        
    except Exception as e:
        return {"success": False, "records": [], "error": str(e)}
    finally:
        connection.close()

@ad_agent.tool
async def analyze_user_behavior(ctx: RunContext[ADAnalysisDependencies]) -> Dict[str, Any]:
    """
    Analyze user behavior patterns for anomalies.
    
    Returns:
        Dictionary with user behavior analysis
    """
    connection = Neo4jConnection()
    
    try:
        # Find most active users
        active_users_query = """
        MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)
        RETURN u.name as username, count(ae) as total_events,
               sum(CASE WHEN ae.success = true THEN 1 ELSE 0 END) as successful_auths,
               sum(CASE WHEN ae.success = false THEN 1 ELSE 0 END) as failed_auths
        ORDER BY total_events DESC
        LIMIT 20
        """
        
        active_users = connection.execute_query(active_users_query)
        
        # Find users with high failure rates
        high_failure_query = """
        MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)
        WITH u.name as username, 
             count(ae) as total_events,
             sum(CASE WHEN ae.success = false THEN 1 ELSE 0 END) as failed_events
        WHERE total_events > 10
        WITH username, total_events, failed_events, 
             round(toFloat(failed_events) / total_events * 100, 2) as failure_rate
        WHERE failure_rate > 50
        RETURN username, total_events, failed_events, failure_rate
        ORDER BY failure_rate DESC
        LIMIT 15
        """
        
        high_failure = connection.execute_query(high_failure_query)
        
        # Find authentication type patterns
        auth_type_query = """
        MATCH (ae:AuthEvent)
        WHERE ae.auth_type IS NOT NULL
        RETURN ae.auth_type as auth_type, count(*) as usage_count,
               sum(CASE WHEN ae.success = true THEN 1 ELSE 0 END) as successful_count
        ORDER BY usage_count DESC
        """
        
        auth_types = connection.execute_query(auth_type_query)
        
        return {
            "success": True,
            "records": [{
                "most_active_users": active_users["records"],
                "high_failure_rate_users": high_failure["records"],
                "authentication_types": auth_types["records"]
            }],
            "error": None
        }
        
    except Exception as e:
        return {"success": False, "records": [], "error": str(e)}
    finally:
        connection.close()

@ad_agent.tool
async def get_timeline_analysis(ctx: RunContext[ADAnalysisDependencies], hours_back: int = 24) -> Dict[str, Any]:
    """
    Analyze authentication events over a specific time period.
    
    Args:
        hours_back: Number of hours to look back from current time
    
    Returns:
        Dictionary with timeline analysis
    """
    connection = Neo4jConnection()
    
    try:
        # Get recent authentication events
        timeline_query = f"""
        MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
        WHERE ae.timestamp IS NOT NULL
        RETURN ae.timestamp as timestamp, u.name as username, c.name as computer, 
               ae.success as success, ae.logon_type as logon_type
        ORDER BY ae.timestamp DESC
        LIMIT 100
        """
        
        timeline = connection.execute_query(timeline_query)
        
        # Get hourly activity distribution
        hourly_query = """
        MATCH (ae:AuthEvent)
        WHERE ae.timestamp IS NOT NULL
        WITH toInteger(substring(ae.timestamp, 11, 2)) as hour, count(*) as event_count
        RETURN hour, event_count
        ORDER BY hour
        """
        
        hourly = connection.execute_query(hourly_query)
        
        return {
            "success": True,
            "records": [{
                "recent_events": timeline["records"],
                "hourly_distribution": hourly["records"]
            }],
            "error": None
        }
        
    except Exception as e:
        return {"success": False, "records": [], "error": str(e)}
    finally:
        connection.close()

@ad_agent.tool
async def get_network_overview(ctx: RunContext[ADAnalysisDependencies]) -> Dict[str, Any]:
    """
    Get an overview of the Active Directory network structure.
    
    Returns:
        Dictionary with network overview
    """
    connection = Neo4jConnection()
    
    try:
        # Get basic statistics
        stats_query = """
        MATCH (n)
        RETURN labels(n) as node_type, count(*) as count
        ORDER BY count DESC
        """
        
        stats = connection.execute_query(stats_query)
        
        # Get relationship statistics
        rel_stats_query = """
        MATCH ()-[r]->()
        RETURN type(r) as relationship_type, count(*) as count
        ORDER BY count DESC
        """
        
        rel_stats = connection.execute_query(rel_stats_query)
        
        return {
            "success": True,
            "records": [{
                "node_statistics": stats["records"],
                "relationship_statistics": rel_stats["records"]
            }],
            "error": None
        }
        
    except Exception as e:
        return {"success": False, "records": [], "error": str(e)}
    finally:
        connection.close()

async def main():
    """Example usage of the AD Red Team Analysis agent"""
    
    deps = ADAnalysisDependencies(database="neo4j")
    
    print("=== Active Directory Red Team Analysis ===\n")
    
    # General security analysis
    print("Performing comprehensive security analysis...")
    result = await ad_agent.run(
        "Analyze my Active Directory authentication data for security threats and red team activities. "
        "Look for suspicious patterns, lateral movement, and potential compromises.",
        deps=deps
    )
    print(f"Security Analysis:\n{result.output}\n")
    
    # Specific lateral movement analysis
    print("Analyzing lateral movement patterns...")
    result = await ad_agent.run(
        "Focus on detecting lateral movement attempts. Which users are accessing multiple computers? "
        "Are there any rapid authentication sequences that suggest automated tools?",
        deps=deps
    )
    print(f"Lateral Movement Analysis:\n{result.output}\n")
    
    # User behavior analysis
    print("Analyzing user behavior anomalies...")
    result = await ad_agent.run(
        "Identify users with suspicious authentication patterns. Who has high failure rates? "
        "Any off-hours activity or unusual authentication types?",
        deps=deps
    )
    print(f"User Behavior Analysis:\n{result.output}\n")

if __name__ == "__main__":
    import asyncio
    
    # Create .env file with your Neo4j credentials:
    # NEO4J_URI=bolt://localhost:7687
    # NEO4J_USERNAME=neo4j
    # NEO4J_PASSWORD=your_password
    
    asyncio.run(main())