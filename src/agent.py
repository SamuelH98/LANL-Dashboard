"""
Simplified Active Directory Analysis Agent
Two main tools: analyze_with_ml_and_graph and summarize
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import os
import json
import asyncio
import aiohttp
import numpy as np
import pandas as pd
from datetime import datetime
import logging

from pydantic import BaseModel, Field
from neo4j import GraphDatabase, basic_auth
from dotenv import load_dotenv
import litellm

# Import ML module
from ml import MLAnalyzer, MLAnalysisResults, analyze_comprehensive_ml

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


class SecurityAnalysis(BaseModel):
    """Structured response for security analysis"""
    findings: List[str] = Field(description="List of security findings and observations")
    suspicious_activities: List[str] = Field(description="Suspicious activities detected")
    recommendations: List[str] = Field(description="Security recommendations")
    summary: str = Field(description="Executive summary of the analysis")
    risk_level: str = Field(description="Overall risk level: LOW, MEDIUM, HIGH, CRITICAL")
    ml_insights: List[str] = Field(default=[], description="Machine learning insights")
    anomaly_scores: Dict[str, float] = Field(default={}, description="Anomaly scores")


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

    def execute_query(self, query: str, parameters: Dict[str, Any] = None, database: str = "authdata"):
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
    """Manages Ollama models"""
    
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
                async with session.get(f"{self.ollama_url}/api/tags", timeout=5) as response:
                    return response.status == 200
        except Exception:
            return False
        
    async def pull_model(self, model_name: str) -> Dict[str, Any]:
        """Pull a model from Ollama"""
        try:
            debug_log(f"Pulling model: {model_name}")
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.ollama_url}/api/pull",
                    json={"name": model_name}
                ) as response:
                    
                    if response.status != 200:
                        error_text = await response.text()
                        debug_log(f"Model pull failed: {error_text}")
                        return {"success": False, "message": f"Failed to pull model: {error_text}"}

                    # Process streaming response
                    progress_updates = []
                    async for line in response.content:
                        if line.strip():
                            try:
                                update = json.loads(line.decode())
                                progress_updates.append(update)
                                debug_log(f"Model pull progress: {update}")
                            except json.JSONDecodeError:
                                continue

                    return {"success": True, "message": f"Model '{model_name}' pulled successfully"}

        except Exception as e:
            debug_log(f"Error during model pull: {str(e)}")
            return {"success": False, "message": f"Error: {str(e)}"}
    
    def get_recommended_models(self) -> List[str]:
        """Get recommended models for security analysis"""
        return [
            "gemma3:4b",
            "gemma3:1b", 
            "deepseek-r1:1.5b",
            "qwen3:0.6b",
        ]


class ADAnalysisAgent:
    """Simplified AD analysis agent with two main tools"""

    def __init__(self):
        self.model = "ollama/gemma3:1b"
        self.model_manager = OllamaModelManager()
        self.ml_analyzer = MLAnalyzer()
        self.connection = Neo4jConnection()
        
        self.system_prompt = (
            "You are a cybersecurity expert specializing in Active Directory security analysis. "
            "You have access to raw authentication data, graph topology data, and machine learning analysis results. "
            "Analyze the data to identify security threats, suspicious activities, and provide actionable recommendations. "
            "Focus on lateral movement, privilege escalation, anomalous user behavior, and network topology issues. "
            "Format your response as valid JSON following this structure: "
            '{"findings": [], "suspicious_activities": [], "recommendations": [], "summary": "", "risk_level": "", "ml_insights": [], "anomaly_scores": {}}'
        )

    def set_model(self, model_name: str):
        """Set the current model"""
        if not model_name.startswith("ollama/"):
            model_name = f"ollama/{model_name}"
        self.model = model_name
        debug_log(f"Model switched to: {self.model}")

    def get_current_model(self) -> str:
        """Get current model name"""
        return self.model.replace("ollama/", "")

    async def analyze_with_ml_and_graph(self, analysis_focus: str = "comprehensive") -> Dict[str, Any]:
        """
        Tool 1: Comprehensive analysis with ML and graph data
        Collects data from Neo4j, runs ML analysis, and provides AI analysis
        """
        try:
            debug_log(f"Starting analyze_with_ml_and_graph: {analysis_focus}")
            
            # Collect authentication data
            auth_query = """
            MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
            RETURN u.name as username, ae.success as success_status, 
                   c.name as computer_name, ae.timestamp as timestamp,
                   ae.logon_type as logon_type, ae.process_name as process_name
            LIMIT 1000
            """
            auth_result = self.connection.execute_query(auth_query)
            
            # Collect graph data
            graph_query = """
            MATCH (u:User)-[r:FROM_USER]->(ae:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
            RETURN u, r, ae, c
            LIMIT 500
            """
            graph_result = self.connection.execute_query(graph_query)
            
            if not auth_result["success"] or not graph_result["success"]:
                return {
                    "findings": ["Database connection failed"],
                    "suspicious_activities": [],
                    "recommendations": ["Check Neo4j connection"],
                    "summary": "Analysis failed due to database issues",
                    "risk_level": "UNKNOWN",
                    "ml_insights": [],
                    "anomaly_scores": {}
                }
            
            # Run ML analysis
            debug_log("Running ML analysis...")
            ml_results = analyze_comprehensive_ml(auth_result["records"], graph_result["records"])
            
            # Prepare data for LLM
            analysis_data = {
                "authentication_data": auth_result["records"][:50],  # Sample for LLM
                "graph_topology": graph_result["records"][:50],
                "ml_analysis": {
                    "outliers": ml_results.outliers,
                    "clusters": ml_results.clusters,
                    "anomalies": ml_results.anomalies,
                    "patterns": ml_results.patterns,
                    "risk_scores": ml_results.risk_scores
                },
                "data_stats": {
                    "total_auth_events": len(auth_result["records"]),
                    "total_graph_nodes": len(graph_result["records"]),
                    "ml_outliers_found": len(ml_results.outliers),
                    "high_risk_entities": len([k for k, v in ml_results.risk_scores.items() if v > 0.7])
                }
            }
            
            # Run LLM analysis
            prompt = f"""
            Analyze this Active Directory security data with focus on: {analysis_focus}
            
            Data Summary:
            - Authentication Events: {analysis_data['data_stats']['total_auth_events']}
            - Graph Relationships: {analysis_data['data_stats']['total_graph_nodes']}
            - ML Outliers Detected: {analysis_data['data_stats']['ml_outliers_found']}
            - High Risk Entities: {analysis_data['data_stats']['high_risk_entities']}
            
            Raw Data and ML Analysis:
            {json.dumps(analysis_data, indent=2, default=str)}
            """
            
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2000,
                response_format={"type": "json_object"}
            )
            
            content = response.choices[0].message.content
            if content.strip().startswith("```json"):
                content = content.strip()[7:-4]
            
            result = json.loads(content)
            debug_log("ML and graph analysis completed")
            return result
            
        except Exception as e:
            error_msg = f"Analysis error: {str(e)}"
            debug_log(error_msg)
            return {
                "findings": [error_msg],
                "suspicious_activities": [],
                "recommendations": ["Check system configuration"],
                "summary": f"Analysis failed: {str(e)}",
                "risk_level": "UNKNOWN",
                "ml_insights": [],
                "anomaly_scores": {}
            }

    async def summarize(self, data: Dict[str, Any], summary_type: str = "executive") -> str:
        """
        Tool 2: Summarize analysis results or raw data
        Creates executive summaries, technical reports, or specific insights
        """
        try:
            debug_log(f"Starting summarize: {summary_type}")
            
            if summary_type == "executive":
                prompt = "Create an executive summary of this security analysis for senior management. Focus on key risks, business impact, and high-level recommendations."
            elif summary_type == "technical":
                prompt = "Create a detailed technical report of this security analysis for the security team. Include specific findings, technical details, and implementation steps."
            elif summary_type == "incident":
                prompt = "Create an incident response summary focusing on immediate threats and urgent actions required."
            else:
                prompt = f"Create a {summary_type} summary of this security analysis."
            
            full_prompt = f"""
            {prompt}
            
            Analysis Data:
            {json.dumps(data, indent=2, default=str)}
            """
            
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert creating clear, actionable summaries of security analysis results."},
                    {"role": "user", "content": full_prompt}
                ],
                temperature=0.2,
                max_tokens=1500
            )
            
            summary = response.choices[0].message.content
            debug_log("Summary completed")
            return summary
            
        except Exception as e:
            debug_log(f"Summarize error: {str(e)}")
            return f"Summary generation failed: {str(e)}"

    def close(self):
        """Clean up resources"""
        if self.connection:
            self.connection.close()


# Global agent instance
ad_agent = ADAnalysisAgent()

# System Status Check Functions
def check_neo4j_status() -> bool:
    """Check if Neo4j database is accessible"""
    try:
        connection = Neo4jConnection()
        connection.driver.verify_connectivity()
        connection.close()
        debug_log("Neo4j connection successful")
        return True
    except Exception as e:
        debug_log(f"Neo4j connection failed: {str(e)}")
        return False

async def check_llm_status() -> bool:
    """Check if LLM model is available"""
    try:
        await litellm.acompletion(
            model=ad_agent.model, 
            messages=[{"role": "user", "content": "ping"}], 
            max_tokens=5, 
            timeout=10
        )
        debug_log("LLM status check successful")
        return True
    except Exception as e:
        debug_log(f"LLM status check failed: {str(e)}")
        return False

# Model management functions
async def get_available_models() -> List[str]:
    """Get list of available models"""
    return await ad_agent.model_manager.get_available_models()

async def pull_model(model_name: str) -> Dict[str, Any]:
    """Pull a model from Ollama"""
    return await ad_agent.model_manager.pull_model(model_name)

def get_recommended_models() -> List[str]:
    """Get recommended models"""
    return ad_agent.model_manager.get_recommended_models()

def set_current_model(model_name: str):
    """Set current model"""
    ad_agent.set_model(model_name)

def get_current_model() -> str:
    """Get current model"""
    return ad_agent.get_current_model()

# Main analysis functions using the two tools
async def run_comprehensive_analysis() -> str:
    """Run comprehensive security analysis using Tool 1"""
    result = await ad_agent.analyze_with_ml_and_graph("comprehensive")
    return format_analysis_result(result)

async def run_lateral_movement_analysis() -> str:
    """Run lateral movement focused analysis"""
    result = await ad_agent.analyze_with_ml_and_graph("lateral_movement")
    return format_analysis_result(result)

async def run_user_behavior_analysis() -> str:
    """Run user behavior focused analysis"""
    result = await ad_agent.analyze_with_ml_and_graph("user_behavior")
    return format_analysis_result(result)

async def run_credential_analysis() -> str:
    """Run credential attack focused analysis"""
    result = await ad_agent.analyze_with_ml_and_graph("credential_attacks")
    return format_analysis_result(result)

async def run_network_analysis() -> str:
    """Run network topology focused analysis"""
    result = await ad_agent.analyze_with_ml_and_graph("network_topology")
    return format_analysis_result(result)

async def create_executive_summary(analysis_result: Dict[str, Any]) -> str:
    """Create executive summary using Tool 2"""
    return await ad_agent.summarize(analysis_result, "executive")

async def create_technical_report(analysis_result: Dict[str, Any]) -> str:
    """Create technical report using Tool 2"""
    return await ad_agent.summarize(analysis_result, "technical")

async def create_incident_summary(analysis_result: Dict[str, Any]) -> str:
    """Create incident response summary using Tool 2"""
    return await ad_agent.summarize(analysis_result, "incident")

def format_analysis_result(result: Dict[str, Any]) -> str:
    """Format analysis results for display"""
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


# Visualization data functions (simplified)
async def get_graph_for_visualization():
    """Get graph data for visualization"""
    connection = Neo4jConnection()
    try:
        query = """
        MATCH (u:User)-[r:FROM_USER]->(ae:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
        RETURN u, r, ae, c
        LIMIT 100
        """
        result = connection.execute_query(query)
        
        if result["success"]:
            # Run ML analysis on graph data
            ml_results = ad_agent.ml_analyzer.analyze_network_topology(result["records"])
            return {
                "success": True,
                "data": result["records"],
                "ml_analysis": ml_results
            }
        return {"success": False, "data": [], "ml_analysis": None}
    finally:
        connection.close()

async def get_hourly_data():
    """Get hourly authentication data"""
    connection = Neo4jConnection()
    try:
        hourly = connection.execute_query("""
            MATCH (ae:AuthEvent) 
            WHERE ae.timestamp IS NOT NULL 
            WITH toInteger(substring(ae.timestamp, 11, 2)) as hour, count(*) as event_count 
            RETURN hour, event_count ORDER BY hour
        """)
        
        daily = connection.execute_query("""
            MATCH (ae:AuthEvent) 
            WHERE ae.timestamp IS NOT NULL 
            WITH toInteger(substring(ae.timestamp, 8, 2)) as day, count(*) as event_count 
            RETURN day, event_count ORDER BY day
        """)
        
        return {
            "success": True,
            "data": {
                "hourly_data": hourly["records"] if hourly["success"] else [],
                "daily_data": daily["records"] if daily["success"] else []
            }
        }
    finally:
        connection.close()

async def get_user_behavior_data():
    """Get user behavior data for analysis"""
    connection = Neo4jConnection()
    try:
        query = """
        MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent) 
        RETURN u.name as username, count(ae) as total_events,
               count(CASE WHEN ae.success = true THEN 1 END) as successful_events,
               count(CASE WHEN ae.success = false THEN 1 END) as failed_events
        ORDER BY total_events DESC LIMIT 50
        """
        result = connection.execute_query(query)
        
        if result["success"]:
            # Run ML analysis on behavior data
            behavior_data = []
            for record in result["records"]:
                behavior_data.append({
                    "username": record["username"],
                    "total_events": record["total_events"],
                    "successful_events": record["successful_events"],
                    "failed_events": record["failed_events"],
                    "success_rate": record["successful_events"] / max(record["total_events"], 1)
                })
            
            ml_results = ad_agent.ml_analyzer.detect_anomalous_login_patterns(behavior_data)
            return {
                "success": True,
                "data": result["records"],
                "ml_analysis": ml_results
            }
        return {"success": False, "data": [], "ml_analysis": None}
    finally:
        connection.close()