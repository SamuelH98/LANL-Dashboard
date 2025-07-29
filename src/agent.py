"""
Active Directory Red Team Analysis Agent
Handles LLM integration, database operations, ML analysis, and analysis logic
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Tuple, Optional
import os
import json
import asyncio
import aiohttp
import requests
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import logging

from pydantic import BaseModel, Field
from neo4j import GraphDatabase, basic_auth
from dotenv import load_dotenv
import litellm
from litellm import completion

# ML and statistical libraries
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from scipy import stats
import networkx as nx

# Load environment variables
load_dotenv()
litellm._turn_on_debug()

# Global debug state
DEBUG_MODE = False

def set_debug_mode(enabled: bool):
    """Set global debug mode"""
    global DEBUG_MODE
    DEBUG_MODE = enabled
    
def get_debug_mode() -> bool:
    """Get current debug mode state"""
    return DEBUG_MODE

def debug_log(message: str, data: Any = None):
    """Log debug information if debug mode is enabled"""
    if DEBUG_MODE:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[DEBUG {timestamp}] {message}")
        if data:
            print(f"[DEBUG DATA] {json.dumps(data, indent=2, default=str)}")

@dataclass
class ADAnalysisDependencies:
    """Dependencies for the AD analysis agent"""
    database: str = "neo4j"

class SecurityAnalysis(BaseModel):
    """Structured response for security analysis"""
    findings: List[str] = Field(description="List of security findings and observations")
    suspicious_activities: List[str] = Field(description="Suspicious activities detected as text descriptions")
    recommendations: List[str] = Field(description="Security recommendations")
    summary: str = Field(description="Executive summary of the analysis")
    risk_level: str = Field(description="Overall risk level: LOW, MEDIUM, HIGH, CRITICAL")
    ml_insights: List[str] = Field(default=[], description="Machine learning derived insights")
    anomaly_scores: Dict[str, float] = Field(default={}, description="Anomaly detection scores")

class MLAnalysisResults(BaseModel):
    """Results from ML analysis functions"""
    outliers: List[Dict[str, Any]] = Field(default=[], description="Detected outliers")
    clusters: List[Dict[str, Any]] = Field(default=[], description="Identified clusters")
    anomalies: List[Dict[str, Any]] = Field(default=[], description="Statistical anomalies")
    patterns: List[Dict[str, Any]] = Field(default=[], description="Behavioral patterns")
    risk_scores: Dict[str, float] = Field(default={}, description="Risk scores by entity")

class Neo4jConnection:
    """Manages Neo4j database connection"""

    def __init__(self):
        self.driver = GraphDatabase.driver(
            os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            auth=basic_auth(
                os.getenv("NEO4J_USERNAME", "neo4j"),
                os.getenv("NEO4J_PASSWORD", "password123")
            )
        )

    def close(self):
        if self.driver:
            self.driver.close()

    def execute_query(self, query: str, parameters: Dict[str, Any] = None, database: str = "neo4j"):
        """Execute a Cypher query and return results"""
        try:
            debug_log(f"Executing Neo4j query: {query}", parameters)
            with self.driver.session(database=database) as session:
                result = session.run(query, parameters or {})
                records = [record.data() for record in result]
                debug_log(f"Query returned {len(records)} records")
                return {"success": True, "records": records, "error": None}
        except Exception as e:
            debug_log(f"Neo4j query error: {str(e)}")
            return {"success": False, "records": [], "error": str(e)}

class OllamaModelManager:
    """Manages Ollama models - pull, list, and select"""
    
    def __init__(self, ollama_url: str = os.getenv("OLLAMA_API_BASE", "http://127.0.0.1:11434")):
        self.ollama_url = ollama_url
        self.available_models = []
    
    async def get_available_models(self) -> List[str]:
        """Get list of available models from Ollama"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.ollama_url}/api/tags") as response:
                    if response.status == 200:
                        data = await response.json()
                        models = [model["name"] for model in data.get("models", [])]
                        self.available_models = models
                        debug_log(f"Available models: {models}")
                        return models
                    else:
                        return []
        except Exception as e:
            debug_log(f"Error getting available models: {e}")
            return []

    async def check_ollama_status(self) -> bool:
        """Check if Ollama service is running"""
        try:
            async with aiohttp.ClientSession() as session:
                debug_log(f"Checking Ollama status at: {self.ollama_url}/api/tags")
                async with session.get(f"{self.ollama_url}/api/tags", timeout=5) as response:
                    return response.status == 200
        except Exception:
            return False
        
    async def pull_model(self, model_name: str) -> Dict[str, Any]:
        """Pull a model from Ollama with proper NDJSON streaming handling"""
        try:
            debug_log(f"Pulling model: {model_name}")
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.ollama_url}/api/pull",
                    json={"name": model_name}
                ) as response:
                    
                    if response.status != 200:
                        error_text = await response.text()
                        debug_log(f"Model pull failed with status {response.status}: {error_text}")
                        return {
                            "success": False,
                            "message": f"Failed to pull model (HTTP {response.status}): {error_text}"
                        }

                    # Process streaming NDJSON response
                    progress_updates = []
                    async for line in response.content:
                        if line.strip():  # Skip empty lines
                            try:
                                update = json.loads(line.decode())
                                progress_updates.append(update)
                                debug_log(f"Model pull progress: {update}")
                            except json.JSONDecodeError:
                                continue

                    debug_log(f"Model '{model_name}' pull completed")
                    return {
                        "success": True,
                        "message": f"Model '{model_name}' pulled successfully",
                        "updates": progress_updates  # All progress updates
                    }

        except aiohttp.ClientError as e:
            debug_log(f"Network error during model pull: {str(e)}")
            return {
                "success": False,
                "message": f"Network error: {str(e)}"
            }
        except Exception as e:
            debug_log(f"Unexpected error during model pull: {str(e)}")
            return {
                "success": False,
                "message": f"Unexpected error: {str(e)}"
            }
    
    def get_recommended_models(self) -> List[str]:
        """Get list of recommended models for security analysis"""
        return [
            "gemma3:4b",
            "gemma3:1b",
            "deepseek-r1:1.5b",
            "deepseek-r1:7b",
            "deepseek-r1:8b",
            "qwen3:0.6b",
        ]

class MLAnalyzer:
    """Machine Learning analysis component for AD security data"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        
    def detect_anomalous_login_patterns(self, auth_data: List[Dict]) -> MLAnalysisResults:
        """Detect anomalous login patterns using ML"""
        try:
            if not auth_data:
                return MLAnalysisResults()
                
            debug_log("Starting anomalous login pattern detection")
            
            # Convert to DataFrame for easier manipulation
            df = pd.DataFrame(auth_data)
            
            # Feature engineering for login patterns
            features = []
            user_stats = defaultdict(lambda: {
                'total_logins': 0, 'failed_logins': 0, 'unique_computers': set(),
                'login_hours': [], 'login_days': []
            })
            
            # Aggregate user statistics
            for record in auth_data:
                user = record.get('username', 'unknown')
                success = record.get('success_status', True)
                computer = record.get('computer_name', 'unknown')
                timestamp = record.get('timestamp', '')
                
                user_stats[user]['total_logins'] += 1
                if not success:
                    user_stats[user]['failed_logins'] += 1
                user_stats[user]['unique_computers'].add(computer)
                
                # Extract time features if timestamp available
                if timestamp:
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        user_stats[user]['login_hours'].append(dt.hour)
                        user_stats[user]['login_days'].append(dt.weekday())
                    except:
                        pass
            
            # Create feature vectors
            for user, stats in user_stats.items():
                failure_rate = stats['failed_logins'] / max(stats['total_logins'], 1)
                unique_computers = len(stats['unique_computers'])
                
                hour_entropy = self._calculate_entropy(stats['login_hours']) if stats['login_hours'] else 0
                day_entropy = self._calculate_entropy(stats['login_days']) if stats['login_days'] else 0
                
                features.append({
                    'user': user,
                    'total_logins': stats['total_logins'],
                    'failure_rate': failure_rate,
                    'unique_computers': unique_computers,
                    'hour_entropy': hour_entropy,
                    'day_entropy': day_entropy
                })
            
            if not features:
                return MLAnalysisResults()
            
            # Prepare data for ML
            feature_df = pd.DataFrame(features)
            feature_columns = ['total_logins', 'failure_rate', 'unique_computers', 'hour_entropy', 'day_entropy']
            X = feature_df[feature_columns].fillna(0)
            
            # Anomaly detection
            X_scaled = self.scaler.fit_transform(X)
            anomaly_scores = self.isolation_forest.fit_predict(X_scaled)
            anomaly_scores_prob = self.isolation_forest.score_samples(X_scaled)
            
            # Clustering
            clusters = self.dbscan.fit_predict(X_scaled)
            
            # Identify outliers and clusters
            outliers = []
            for i, (score, prob_score) in enumerate(zip(anomaly_scores, anomaly_scores_prob)):
                if score == -1:  # Anomaly
                    user_data = features[i]
                    user_data['anomaly_score'] = float(prob_score)
                    outliers.append(user_data)
            
            cluster_info = []
            for cluster_id in set(clusters):
                if cluster_id != -1:  # Not noise
                    cluster_users = [features[i]['user'] for i, c in enumerate(clusters) if c == cluster_id]
                    cluster_info.append({
                        'cluster_id': int(cluster_id),
                        'users': cluster_users,
                        'size': len(cluster_users)
                    })
            
            # Calculate risk scores
            risk_scores = {}
            for i, user_data in enumerate(features):
                user = user_data['user']
                risk_score = (
                    user_data['failure_rate'] * 0.4 +
                    min(user_data['unique_computers'] / 10, 1) * 0.3 +
                    (1 - user_data['hour_entropy']) * 0.15 +
                    (1 - user_data['day_entropy']) * 0.15
                )
                risk_scores[user] = float(risk_score)
            
            debug_log(f"ML analysis completed: {len(outliers)} outliers, {len(cluster_info)} clusters")
            
            return MLAnalysisResults(
                outliers=outliers,
                clusters=cluster_info,
                risk_scores=risk_scores
            )
            
        except Exception as e:
            debug_log(f"Error in ML analysis: {str(e)}")
            return MLAnalysisResults()
    
    def analyze_network_topology(self, graph_data: List[Dict]) -> MLAnalysisResults:
        """Analyze network topology for suspicious patterns"""
        try:
            if not graph_data:
                return MLAnalysisResults()
                
            debug_log("Starting network topology analysis")
            
            # Build NetworkX graph
            G = nx.Graph()
            for record in graph_data:
                user = record.get('u', {})
                computer = record.get('c', {})
                auth_event = record.get('ae', {})
                
                user_id = user.get('name', f"user_{user.get('id', 'unknown')}")
                computer_id = computer.get('name', f"computer_{computer.get('id', 'unknown')}")
                
                G.add_node(user_id, type='user')
                G.add_node(computer_id, type='computer')
                G.add_edge(user_id, computer_id)
            
            # Calculate network metrics
            patterns = []
            
            # Centrality measures
            degree_centrality = nx.degree_centrality(G)
            betweenness_centrality = nx.betweenness_centrality(G)
            closeness_centrality = nx.closeness_centrality(G)
            
            # Identify high-centrality nodes (potential pivot points)
            high_centrality_threshold = 0.8
            high_centrality_nodes = [
                node for node, centrality in degree_centrality.items() 
                if centrality > high_centrality_threshold
            ]
            
            if high_centrality_nodes:
                patterns.append({
                    'pattern_type': 'high_centrality_nodes',
                    'description': 'Nodes with unusually high network centrality',
                    'nodes': high_centrality_nodes,
                    'risk_level': 'HIGH'
                })
            
            # Community detection
            try:
                communities = list(nx.community.greedy_modularity_communities(G))
                large_communities = [list(community) for community in communities if len(community) > 5]
                
                if large_communities:
                    patterns.append({
                        'pattern_type': 'large_communities',
                        'description': 'Large network communities detected',
                        'communities': large_communities,
                        'risk_level': 'MEDIUM'
                    })
            except:
                pass  # Community detection might fail on some graphs
            
            # Calculate risk scores based on network position
            risk_scores = {}
            for node in G.nodes():
                risk_score = (
                    degree_centrality.get(node, 0) * 0.4 +
                    betweenness_centrality.get(node, 0) * 0.4 +
                    closeness_centrality.get(node, 0) * 0.2
                )
                risk_scores[node] = float(risk_score)
            
            debug_log(f"Network topology analysis completed: {len(patterns)} patterns identified")
            
            return MLAnalysisResults(
                patterns=patterns,
                risk_scores=risk_scores
            )
            
        except Exception as e:
            debug_log(f"Error in network topology analysis: {str(e)}")
            return MLAnalysisResults()
    
    def _calculate_entropy(self, data: List) -> float:
        """Calculate entropy of a data series"""
        if not data:
            return 0
        
        value_counts = Counter(data)
        probabilities = [count / len(data) for count in value_counts.values()]
        entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
        
        # Normalize by maximum possible entropy
        max_entropy = np.log2(len(value_counts)) if len(value_counts) > 1 else 1
        return entropy / max_entropy if max_entropy > 0 else 0

class ADAnalysisAgent:
    """Lightweight AD analysis agent using LiteLLM with configurable Ollama models"""

    def __init__(self):
        self.model = "ollama/gemma3:1b"  # Default model
        self.model_manager = OllamaModelManager()
        self.ml_analyzer = MLAnalyzer()
        self.system_prompt = (
            "You are a cybersecurity expert specializing in Active Directory security analysis and red team detection. "
            "Analyze authentication events, user behavior, and computer interactions to identify potential security threats. "
            "Focus on detecting lateral movement, privilege escalation, suspicious login patterns, and other red team tactics. "
            "You will receive both raw data and machine learning analysis results including anomaly scores and behavioral patterns. "
            "Provide actionable security recommendations and assess risk levels appropriately. "
            "Be specific about which users and authentication events you find suspicious and why. "
            "Incorporate ML insights into your analysis but apply human expert judgment. "
            "Be concise but thorough in your analysis. Format your response as a valid JSON object following this structure: "
            '{"findings": [], "suspicious_activities": [], "recommendations": [], "summary": "", "risk_level": "", "ml_insights": [], "anomaly_scores": {}}'
        )

    def set_model(self, model_name: str):
        """Set the current model for analysis"""
        if not model_name.startswith("ollama/"):
            model_name = f"ollama/{model_name}"
        self.model = model_name
        debug_log(f"Model switched to: {self.model}")

    def get_current_model(self) -> str:
        """Get the current model name"""
        return self.model.replace("ollama/", "")

    async def analyze(self, query: str, data: Dict[str, Any] = None, ml_results: MLAnalysisResults = None) -> Dict[str, Any]:
        """Analyze security data using the selected model with ML insights"""
        try:
            context_parts = []
            
            if data:
                context_parts.append(f"Raw Data:\n{json.dumps(data, indent=2, default=str)}")
            
            if ml_results:
                ml_data = {
                    "ml_outliers": ml_results.outliers,
                    "ml_clusters": ml_results.clusters,
                    "ml_patterns": ml_results.patterns,
                    "ml_risk_scores": ml_results.risk_scores
                }
                context_parts.append(f"ML Analysis Results:\n{json.dumps(ml_data, indent=2, default=str)}")
            
            context = f"\n\nAnalysis Context:\n{chr(10).join(context_parts)}" if context_parts else ""
            full_prompt = f"{query}{context}"
            
            debug_log("Sending prompt to LLM", {
                "model": self.model,
                "prompt_length": len(full_prompt),
                "has_ml_results": ml_results is not None,
                "full_prompt": full_prompt if DEBUG_MODE else "DEBUG_MODE disabled"
            })

            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": full_prompt}
                ],
                temperature=0.3, 
                max_tokens=2000, 
                response_format={"type": "json_object"}
            )
            
            content = response.choices[0].message.content
            if content.strip().startswith("```json"):
                content = content.strip()[7:-4]
            
            result = json.loads(content)
            debug_log("LLM response received", result)
            
            return result
            
        except Exception as e:
            error_msg = f"Analysis error: {str(e)}"
            debug_log(error_msg)
            return {
                "findings": [error_msg], 
                "suspicious_activities": [],
                "recommendations": ["Check LiteLLM/Ollama configuration and model availability."],
                "summary": f"Analysis failed: {str(e)}", 
                "risk_level": "UNKNOWN",
                "ml_insights": [],
                "anomaly_scores": {}
            }

# Global agent instance
ad_agent = ADAnalysisAgent()

# System Status Check Functions
def check_neo4j_status() -> bool:
    """Check if Neo4j database is accessible"""
    try:
        with GraphDatabase.driver(os.getenv("NEO4J_URI"), auth=basic_auth(os.getenv("NEO4J_USERNAME"), os.getenv("NEO4J_PASSWORD"))) as driver:
            driver.verify_connectivity()
        debug_log("Neo4j connection successful")
        return True
    except Exception as e:
        debug_log(f"Neo4j connection failed: {str(e)}")
        return False

async def check_llm_status() -> bool:
    """Check if LLM model is available"""
    try:
        await litellm.acompletion(model=ad_agent.model, messages=[{"role": "user", "content": "ping"}], max_tokens=5, timeout=10)
        debug_log("LLM status check successful")
        return True
    except Exception as e:
        debug_log(f"LLM status check failed: {str(e)}")
        return False

# Model management functions
async def get_available_models() -> List[str]:
    """Get list of available models from Ollama"""
    return await ad_agent.model_manager.get_available_models()

async def pull_model(model_name: str) -> Dict[str, Any]:
    """Pull a model from Ollama registry"""
    return await ad_agent.model_manager.pull_model(model_name)

def get_recommended_models() -> List[str]:
    """Get recommended models for security analysis"""
    return ad_agent.model_manager.get_recommended_models()

def set_current_model(model_name: str):
    """Set the current model for analysis"""
    ad_agent.set_model(model_name)

def get_current_model() -> str:
    """Get the current model name"""
    return ad_agent.get_current_model()

# Enhanced Data collection functions with ML analysis
async def get_graph_for_visualization():
    """Fetch graph data for visualization with ML analysis"""
    connection = Neo4jConnection()
    try:
        query = """
        MATCH (u:User)-[r:FROM_USER]->(ae:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
        RETURN u, r, ae, c
        LIMIT 100
        """
        graph_data = connection.execute_query(query)
        
        # Run ML analysis on graph data
        ml_results = ad_agent.ml_analyzer.analyze_network_topology(graph_data["records"])
        
        return {
            "success": True, 
            "data": graph_data["records"],
            "ml_analysis": ml_results
        }
    finally:
        connection.close()

async def analyze_authentication_patterns():
    """Analyze authentication success/failure patterns with ML insights"""
    connection = Neo4jConnection()
    try:
        # Get detailed authentication data
        auth_query = """
        MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
        RETURN u.name as username, ae.success as success_status, 
               c.name as computer_name, ae.timestamp as timestamp,
               ae.logon_type as logon_type, ae.process_name as process_name
        LIMIT 1000
        """
        
        auth_data = connection.execute_query(auth_query)
        auth_stats = connection.execute_query("""
            MATCH (ae:AuthEvent) 
            RETURN ae.success as success_status, count(*) as event_count
        """)
        
        # Run ML analysis on authentication patterns
        ml_results = ad_agent.ml_analyzer.detect_anomalous_login_patterns(auth_data["records"])
        
        # Time-based analysis
        hourly_stats = connection.execute_query("""
            MATCH (ae:AuthEvent) 
            WHERE ae.timestamp IS NOT NULL 
            WITH toInteger(substring(ae.timestamp, 11, 2)) as hour, count(*) as event_count 
            RETURN hour, event_count ORDER BY hour
        """)
        
        # Failed login analysis
        failed_logins = connection.execute_query("""
            MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)
            WHERE ae.success = false
            RETURN u.name as username, count(ae) as failed_count
            ORDER BY failed_count DESC LIMIT 20
        """)
        
        return {
            "success": True, 
            "data": {
                "auth_statistics": auth_stats["records"],
                "detailed_auth_data": auth_data["records"],
                "hourly_statistics": hourly_stats["records"],
                "failed_logins": failed_logins["records"]
            },
            "ml_analysis": ml_results
        }
    finally:
        connection.close()

async def detect_lateral_movement():
    """Detect potential lateral movement patterns with ML enhancement"""
    connection = Neo4jConnection()
    try:
        # Multi-computer access analysis
        multi_computer = connection.execute_query("""
            MATCH (u:User)-[:FROM_USER]->(:AuthEvent)-[:TO_COMPUTER]->(c:Computer) 
            WITH u.name as username, collect(DISTINCT c.name) as computers, count(DISTINCT c.name) as computer_count 
            WHERE computer_count > 2 
            RETURN username, computers, computer_count 
            ORDER BY computer_count DESC LIMIT 20
        """)
        
        # Time-based lateral movement detection
        time_based_movement = connection.execute_query("""
            MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
            WHERE ae.timestamp IS NOT NULL
            WITH u.name as username, c.name as computer, ae.timestamp as timestamp
            ORDER BY username, timestamp
            WITH username, collect({computer: computer, timestamp: timestamp}) as timeline
            WHERE size(timeline) > 3
            RETURN username, timeline LIMIT 15
        """)
        
        # Unusual access patterns
        unusual_access = connection.execute_query("""
            MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
            WHERE ae.logon_type IS NOT NULL
            WITH u.name as username, c.name as computer, ae.logon_type as logon_type, count(*) as access_count
            WHERE access_count > 5 AND logon_type IN ['3', '10']  // Network and RemoteInteractive logons
            RETURN username, computer, logon_type, access_count
            ORDER BY access_count DESC LIMIT 25
        """)
        
        # Combine all data for ML analysis
        all_data = []
        for record in multi_computer["records"]:
            all_data.append({
                "type": "multi_computer_access",
                "username": record["username"],
                "computer_count": record["computer_count"],
                "computers": record["computers"]
            })
        
        # Run ML analysis for pattern detection
        ml_results = ad_agent.ml_analyzer.detect_anomalous_login_patterns(all_data)
        
        return {
            "success": True, 
            "data": {
                "multi_computer_access": multi_computer["records"],
                "time_based_movement": time_based_movement["records"],
                "unusual_access_patterns": unusual_access["records"]
            },
            "ml_analysis": ml_results
        }
    finally:
        connection.close()

async def analyze_user_behavior():
    """Analyze user activity patterns with behavioral ML analysis"""
    connection = Neo4jConnection()
    try:
        # Active users analysis
        active_users = connection.execute_query("""
            MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent) 
            RETURN u.name as username, count(ae) as total_events,
                   count(CASE WHEN ae.success = true THEN 1 END) as successful_events,
                   count(CASE WHEN ae.success = false THEN 1 END) as failed_events
            ORDER BY total_events DESC LIMIT 50
        """)
        
        # Privilege escalation indicators
        privilege_escalation = connection.execute_query("""
            MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)
            WHERE ae.process_name IS NOT NULL AND 
                  (ae.process_name CONTAINS 'runas' OR 
                   ae.process_name CONTAINS 'powershell' OR 
                   ae.process_name CONTAINS 'cmd')
            RETURN u.name as username, ae.process_name as process, count(*) as usage_count
            ORDER BY usage_count DESC LIMIT 20
        """)
        
        # Off-hours activity
        off_hours_activity = connection.execute_query("""
            MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)
            WHERE ae.timestamp IS NOT NULL
            WITH u.name as username, toInteger(substring(ae.timestamp, 11, 2)) as hour
            WHERE hour < 6 OR hour > 20  // Off-hours: before 6 AM or after 8 PM
            RETURN username, hour, count(*) as activity_count
            ORDER BY activity_count DESC LIMIT 25
        """)
        
        # Service account analysis
        service_accounts = connection.execute_query("""
            MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)
            WHERE u.name CONTAINS '$' OR u.name CONTAINS 'svc' OR u.name CONTAINS 'service'
            RETURN u.name as username, count(ae) as total_events,
                   collect(DISTINCT ae.logon_type) as logon_types
            ORDER BY total_events DESC LIMIT 15
        """)
        
        # Prepare data for ML analysis
        behavior_data = []
        for record in active_users["records"]:
            behavior_data.append({
                "username": record["username"],
                "total_events": record["total_events"],
                "successful_events": record["successful_events"],
                "failed_events": record["failed_events"],
                "success_rate": record["successful_events"] / max(record["total_events"], 1)
            })
        
        # Run ML analysis on user behavior
        ml_results = ad_agent.ml_analyzer.detect_anomalous_login_patterns(behavior_data)
        
        return {
            "success": True, 
            "data": {
                "most_active_users": active_users["records"],
                "privilege_escalation_indicators": privilege_escalation["records"],
                "off_hours_activity": off_hours_activity["records"],
                "service_accounts": service_accounts["records"]
            },
            "ml_analysis": ml_results
        }
    finally:
        connection.close()

async def analyze_network_segmentation():
    """Analyze network segmentation and identify potential security boundaries"""
    connection = Neo4jConnection()
    try:
        # Computer-to-computer communication patterns
        computer_connections = connection.execute_query("""
            MATCH (c1:Computer)<-[:TO_COMPUTER]-(:AuthEvent)<-[:FROM_USER]-(u:User)
            -[:FROM_USER]->(:AuthEvent)-[:TO_COMPUTER]->(c2:Computer)
            WHERE c1 <> c2
            RETURN c1.name as source_computer, c2.name as target_computer, 
                   u.name as username, count(*) as connection_count
            ORDER BY connection_count DESC LIMIT 100
        """)
        
        # Subnet analysis (if computer names contain IP or subnet info)
        subnet_analysis = connection.execute_query("""
            MATCH (c:Computer)<-[:TO_COMPUTER]-(:AuthEvent)<-[:FROM_USER]-(u:User)
            RETURN c.name as computer, u.name as username, count(*) as access_count
            ORDER BY access_count DESC LIMIT 50
        """)
        
        return {
            "success": True,
            "data": {
                "computer_connections": computer_connections["records"],
                "subnet_analysis": subnet_analysis["records"]
            }
        }
    finally:
        connection.close()

async def detect_privilege_escalation():
    """Detect potential privilege escalation attempts"""
    connection = Neo4jConnection()
    try:
        # Unusual process executions
        suspicious_processes = connection.execute_query("""
            MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)
            WHERE ae.process_name IS NOT NULL AND 
                  (ae.process_name CONTAINS 'powershell' OR 
                   ae.process_name CONTAINS 'cmd' OR 
                   ae.process_name CONTAINS 'wmic' OR 
                   ae.process_name CONTAINS 'net' OR
                   ae.process_name CONTAINS 'runas')
            RETURN u.name as username, ae.process_name as process, 
                   count(*) as execution_count, collect(DISTINCT ae.timestamp)[0..5] as sample_timestamps
            ORDER BY execution_count DESC LIMIT 30
        """)
        
        # Administrative logon types
        admin_logons = connection.execute_query("""
            MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)
            WHERE ae.logon_type IN ['2', '4', '5']  // Interactive, Batch, Service logons
            RETURN u.name as username, ae.logon_type as logon_type, 
                   count(*) as logon_count
            ORDER BY logon_count DESC LIMIT 25
        """)
        
        # Users with multiple logon types (potential indicator of compromise)
        multi_logon_types = connection.execute_query("""
            MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)
            WHERE ae.logon_type IS NOT NULL
            WITH u.name as username, collect(DISTINCT ae.logon_type) as logon_types
            WHERE size(logon_types) > 2
            RETURN username, logon_types, size(logon_types) as type_count
            ORDER BY type_count DESC LIMIT 20
        """)
        
        return {
            "success": True,
            "data": {
                "suspicious_processes": suspicious_processes["records"],
                "administrative_logons": admin_logons["records"],
                "multi_logon_types": multi_logon_types["records"]
            }
        }
    finally:
        connection.close()

async def get_hourly_data():
    """Get hourly authentication activity data with pattern analysis"""
    connection = Neo4jConnection()
    try:
        hourly = connection.execute_query("""
            MATCH (ae:AuthEvent) 
            WHERE ae.timestamp IS NOT NULL 
            WITH toInteger(substring(ae.timestamp, 11, 2)) as hour, count(*) as event_count 
            RETURN hour, event_count ORDER BY hour
        """)
        
        # Daily pattern analysis
        daily = connection.execute_query("""
            MATCH (ae:AuthEvent) 
            WHERE ae.timestamp IS NOT NULL 
            WITH toInteger(substring(ae.timestamp, 8, 2)) as day, count(*) as event_count 
            RETURN day, event_count ORDER BY day
        """)
        
        return {
            "success": True,
            "data": {
                "hourly_data": hourly["records"],
                "daily_data": daily["records"]
            }
        }
    finally:
        connection.close()

async def analyze_account_usage_patterns():
    """Analyze account usage patterns for dormant and suspicious accounts"""
    connection = Neo4jConnection()
    try:
        # Account activity timeline
        account_timeline = connection.execute_query("""
            MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)
            WHERE ae.timestamp IS NOT NULL
            WITH u.name as username, 
                 min(ae.timestamp) as first_seen,
                 max(ae.timestamp) as last_seen,
                 count(ae) as total_events
            RETURN username, first_seen, last_seen, total_events,
                   duration.between(datetime(first_seen), datetime(last_seen)).days as active_days
            ORDER BY total_events DESC LIMIT 100
        """)
        
        # Dormant accounts (no activity in recent period)
        dormant_accounts = connection.execute_query("""
            MATCH (u:User)
            WHERE NOT (u)-[:FROM_USER]->(:AuthEvent)
            RETURN u.name as username, 'No authentication events' as status
            LIMIT 50
        """)
        
        # High-frequency burst activity
        burst_activity = connection.execute_query("""
            MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)
            WHERE ae.timestamp IS NOT NULL
            WITH u.name as username, substring(ae.timestamp, 0, 10) as date, count(ae) as daily_events
            WHERE daily_events > 100
            RETURN username, date, daily_events
            ORDER BY daily_events DESC LIMIT 30
        """)
        
        return {
            "success": True,
            "data": {
                "account_timeline": account_timeline["records"],
                "dormant_accounts": dormant_accounts["records"],
                "burst_activity": burst_activity["records"]
            }
        }
    finally:
        connection.close()

async def detect_credential_stuffing():
    """Detect potential credential stuffing and brute force attacks"""
    connection = Neo4jConnection()
    try:
        # Failed login patterns
        failed_login_patterns = connection.execute_query("""
            MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
            WHERE ae.success = false AND ae.timestamp IS NOT NULL
            WITH u.name as username, c.name as computer, 
                 substring(ae.timestamp, 0, 13) as hour_window,
                 count(ae) as failed_attempts
            WHERE failed_attempts > 5
            RETURN username, computer, hour_window, failed_attempts
            ORDER BY failed_attempts DESC LIMIT 50
        """)
        
        # Multiple source IPs for same user (if available)
        multiple_sources = connection.execute_query("""
            MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
            WITH u.name as username, collect(DISTINCT c.name) as computers
            WHERE size(computers) > 5
            RETURN username, computers, size(computers) as computer_count
            ORDER BY computer_count DESC LIMIT 20
        """)
        
        # Rapid-fire authentication attempts
        rapid_fire = connection.execute_query("""
            MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)
            WHERE ae.timestamp IS NOT NULL
            WITH u.name as username, substring(ae.timestamp, 0, 16) as minute_window, count(ae) as attempts
            WHERE attempts > 10
            RETURN username, minute_window, attempts
            ORDER BY attempts DESC LIMIT 25
        """)
        
        return {
            "success": True,
            "data": {
                "failed_login_patterns": failed_login_patterns["records"],
                "multiple_source_access": multiple_sources["records"],
                "rapid_fire_attempts": rapid_fire["records"]
            }
        }
    finally:
        connection.close()

# Analysis helper functions
async def run_analysis(analysis_func, query, *data_funcs):
    """Run security analysis with given data functions and ML enhancement"""
    try:
        debug_log(f"Starting analysis: {query}")
        
        # Collect data from all functions
        data_results = await asyncio.gather(*[f() for f in data_funcs])
        combined_data = {}
        combined_ml_results = MLAnalysisResults()
        
        # Combine results and ML analyses
        for func, res in zip(data_funcs, data_results):
            func_name = func.__name__
            combined_data[func_name] = res.get("data", {})
            
            # Merge ML results if available
            if "ml_analysis" in res:
                ml_res = res["ml_analysis"]
                combined_ml_results.outliers.extend(ml_res.outliers)
                combined_ml_results.clusters.extend(ml_res.clusters)
                combined_ml_results.patterns.extend(ml_res.patterns)
                combined_ml_results.risk_scores.update(ml_res.risk_scores)
        
        # Run LLM analysis with both raw data and ML results
        result = await ad_agent.analyze(query, combined_data, combined_ml_results)
        formatted_result = format_analysis_result(result)
        
        debug_log("Analysis completed successfully")
        return formatted_result
        
    except Exception as e:
        error_msg = f"Analysis failed: {str(e)}"
        debug_log(error_msg)
        return f"❌ {error_msg}"

def format_analysis_result(result: Dict[str, Any]) -> str:
    """Format analysis results for display with ML insights"""
    try:
        risk_level = result.get("risk_level", "UNKNOWN").upper()
        risk_emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(risk_level, "⚪️")
        
        output = [
            f"## {risk_emoji} Risk Level: {risk_level}\n",
            f"### 📋 Executive Summary\n{result.get('summary', 'N/A')}\n"
        ]
        
        if result.get("findings"):
            output.append("### 🔍 Key Findings")
            output.extend([f"- {finding}" for finding in result["findings"]])
            output.append("")
        
        if result.get("suspicious_activities"):
            output.append("### ⚠️ Suspicious Activities")
            output.extend([f"- {activity}" for activity in result["suspicious_activities"]])
            output.append("")
        
        if result.get("ml_insights"):
            output.append("### 🤖 Machine Learning Insights")
            output.extend([f"- {insight}" for insight in result["ml_insights"]])
            output.append("")
        
        if result.get("anomaly_scores"):
            output.append("### 📊 Anomaly Scores")
            for entity, score in result["anomaly_scores"].items():
                output.append(f"- **{entity}**: {score:.3f}")
            output.append("")
        
        if result.get("recommendations"):
            output.append("### 💡 Recommendations")
            output.extend([f"- {rec}" for rec in result["recommendations"]])
        
        return "\n".join(output)
        
    except Exception as e:
        debug_log(f"Error formatting results: {str(e)}")
        return f"❌ Error formatting results: {str(e)}\n\nRaw: {result}"