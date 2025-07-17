"""
Active Directory Red Team Analysis Agent
Handles LLM integration, database operations, and analysis logic
"""

from dataclasses import dataclass
from typing import List, Dict, Any
import os
import json
import asyncio
import aiohttp
import requests

from pydantic import BaseModel, Field
from neo4j import GraphDatabase, basic_auth
from dotenv import load_dotenv
import litellm
from litellm import completion

# Load environment variables
load_dotenv()
litellm._turn_on_debug()

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
            with self.driver.session(database=database) as session:
                result = session.run(query, parameters or {})
                records = [record.data() for record in result]
                return {"success": True, "records": records, "error": None}
        except Exception as e:
            return {"success": False, "records": [], "error": str(e)}

class OllamaModelManager:
    """Manages Ollama models - pull, list, and select"""
    
    def __init__(self, ollama_url: str = "http://host.docker.internal:11434"):
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
                        return models
                    else:
                        return []
        except Exception as e:
            print(f"Error getting available models: {e}")
            return []
    
    async def pull_model(self, model_name: str) -> Dict[str, Any]:
        """Pull a model from Ollama"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.ollama_url}/api/pull",
                    json={"name": model_name}
                ) as response:
                    if response.status == 200:
                        return {"success": True, "message": f"Model {model_name} pulled successfully"}
                    else:
                        error_text = await response.text()
                        return {"success": False, "message": f"Failed to pull model: {error_text}"}
        except Exception as e:
            return {"success": False, "message": f"Error pulling model: {str(e)}"}
    
    def get_recommended_models(self) -> List[str]:
        """Get list of recommended models for security analysis"""
        return [
            "gemma3:1b"
        ]

class ADAnalysisAgent:
    """Lightweight AD analysis agent using LiteLLM with configurable Ollama models"""

    def __init__(self):
        self.model = "ollama/gemma3:1b"  # Default model
        self.model_manager = OllamaModelManager()
        self.system_prompt = (
            "You are a cybersecurity expert specializing in Active Directory security analysis and red team detection. "
            "Analyze authentication events, user behavior, and computer interactions to identify potential security threats. "
            "Focus on detecting lateral movement, privilege escalation, suspicious login patterns, and other red team tactics. "
            "Provide actionable security recommendations and assess risk levels appropriately. "
            "Be concise but thorough in your analysis. Format your response as a valid JSON object following this structure: "
            '{"findings": [], "suspicious_activities": [], "recommendations": [], "summary": "", "risk_level": ""}'
        )

    def set_model(self, model_name: str):
        """Set the current model for analysis"""
        if not model_name.startswith("ollama/"):
            model_name = f"ollama/{model_name}"
        self.model = model_name
        print(f"Model switched to: {self.model}")

    def get_current_model(self) -> str:
        """Get the current model name"""
        return self.model.replace("ollama/", "")

    async def analyze(self, query: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze security data using the selected model"""
        try:
            context = f"\n\nData Context:\n{json.dumps(data, indent=2)}" if data else ""
            full_prompt = f"{query}{context}"

            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": full_prompt}
                ],
                temperature=0.3, max_tokens=1500, response_format={"type": "json_object"}
            )
            content = response.choices[0].message.content
            if content.strip().startswith("```json"):
                content = content.strip()[7:-4]
            return json.loads(content)
        except Exception as e:
            return {
                "findings": [f"Analysis error: {str(e)}"], "suspicious_activities": [],
                "recommendations": ["Check LiteLLM/Ollama configuration and model availability."],
                "summary": f"Analysis failed: {str(e)}", "risk_level": "UNKNOWN"
            }

# Global agent instance
ad_agent = ADAnalysisAgent()

# System Status Check Functions
def check_neo4j_status() -> bool:
    """Check if Neo4j database is accessible"""
    try:
        with GraphDatabase.driver(os.getenv("NEO4J_URI"), auth=basic_auth(os.getenv("NEO4J_USERNAME"), os.getenv("NEO4J_PASSWORD"))) as driver:
            driver.verify_connectivity()
        return True
    except Exception:
        return False

async def check_llm_status() -> bool:
    """Check if LLM model is available"""
    try:
        await litellm.acompletion(model=ad_agent.model, messages=[{"role": "user", "content": "ping"}], max_tokens=5, timeout=10)
        return True
    except Exception:
        return False

async def check_ollama_status() -> bool:
    """Check if Ollama service is running"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("http://host.docker.internal:11434/api/tags", timeout=5) as response:
                return response.status == 200
    except Exception:
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

# Data collection functions
async def get_graph_for_visualization():
    """Fetch graph data for visualization"""
    connection = Neo4jConnection()
    try:
        query = """
        MATCH (u:User)-[r:FROM_USER]->(ae:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
        RETURN u, r, ae, c
        LIMIT 100
        """
        graph_data = connection.execute_query(query)
        return {"success": True, "data": graph_data["records"]}
    finally:
        connection.close()


async def analyze_authentication_patterns():
    """Analyze authentication success/failure patterns"""
    connection = Neo4jConnection()
    try:
        auth_stats = connection.execute_query("""MATCH (ae:AuthEvent) RETURN ae.success as success_status, count(*) as event_count""")
        return {"success": True, "data": {"auth_statistics": auth_stats["records"]}}
    finally:
        connection.close()

async def detect_lateral_movement():
    """Detect potential lateral movement patterns"""
    connection = Neo4jConnection()
    try:
        multi_computer = connection.execute_query("""MATCH (u:User)-[:FROM_USER]->(:AuthEvent)-[:TO_COMPUTER]->(c:Computer) WITH u.name as username, count(DISTINCT c.name) as computer_count WHERE computer_count > 3 RETURN username, computer_count ORDER BY computer_count DESC LIMIT 20""")
        return {"success": True, "data": {"multi_computer_access": multi_computer["records"]}}
    finally:
        connection.close()

async def analyze_user_behavior():
    """Analyze user activity patterns"""
    connection = Neo4jConnection()
    try:
        active_users = connection.execute_query("""MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent) RETURN u.name as username, count(ae) as total_events ORDER BY total_events DESC LIMIT 20""")
        return {"success": True, "data": {"most_active_users": active_users["records"]}}
    finally:
        connection.close()

async def get_hourly_data():
    """Get hourly authentication activity data"""
    connection = Neo4jConnection()
    try:
        hourly = connection.execute_query("""MATCH (ae:AuthEvent) WHERE ae.timestamp IS NOT NULL WITH toInteger(substring(ae.timestamp, 11, 2)) as hour, count(*) as event_count RETURN hour, event_count ORDER BY hour""")
        return hourly
    finally:
        connection.close()

# Analysis helper functions
async def run_analysis(analysis_func, query, *data_funcs):
    """Run security analysis with given data functions"""
    try:
        data_results = await asyncio.gather(*[f() for f in data_funcs])
        combined_data = {func.__name__: res.get("data") for func, res in zip(data_funcs, data_results)}
        result = await ad_agent.analyze(query, combined_data)
        return format_analysis_result(result)
    except Exception as e:
        return f"❌ Analysis failed: {str(e)}"

def format_analysis_result(result: Dict[str, Any]) -> str:
    """Format analysis results for display"""
    try:
        risk_level = result.get("risk_level", "UNKNOWN").upper()
        risk_emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(risk_level, "⚪️")
        output = [f"## {risk_emoji} Risk Level: {risk_level}\n", f"### 📋 Executive Summary\n{result.get('summary', 'N/A')}\n"]
        
        if result.get("findings"):
            output.append("### 🔍 Key Findings")
            output.extend([f"- {finding}" for finding in result["findings"]])
        
        if result.get("suspicious_activities"):
            output.append("\n### ⚠️ Suspicious Activities")
            output.extend([f"- {activity}" for activity in result["suspicious_activities"]])
        
        if result.get("recommendations"):
            output.append("\n### 💡 Recommendations")
            output.extend([f"- {rec}" for rec in result["recommendations"]])
        
        return "\n".join(output)
    except Exception as e:
        return f"❌ Error formatting results: {str(e)}\n\nRaw: {result}"