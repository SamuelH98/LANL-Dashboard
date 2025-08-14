"""
agent.py - Enhanced version with graph explanation and research conclusion capabilities
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import os
import json
import asyncio
import aiohttp
import pandas as pd
from datetime import datetime
import logging
import traceback
import tiktoken
from collections import Counter

from pydantic import BaseModel, Field
from neo4j import GraphDatabase, basic_auth
from dotenv import load_dotenv
import litellm

# --- Boilerplate and Helpers ---
load_dotenv()
DEBUG_MODE = False
TOKEN_ENCODER = None


def get_token_encoder():
    global TOKEN_ENCODER
    if TOKEN_ENCODER is None:
        TOKEN_ENCODER = tiktoken.get_encoding("cl100k_base")
    return TOKEN_ENCODER


def count_tokens(text: str) -> int:
    if not text:
        return 0
    return len(get_token_encoder().encode(text))


def set_debug_mode(enabled: bool):
    global DEBUG_MODE
    DEBUG_MODE = enabled


def get_debug_mode() -> bool:
    return DEBUG_MODE


def debug_log(message: str, data: Any = None):
    if DEBUG_MODE:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[DEBUG {timestamp}] {message}")
        if data:
            print(f"[DEBUG DATA] {json.dumps(data, indent=2, default=str)}")


def add_debug_output(message: str):
    debug_log(message)


# --- Enhanced Pydantic Models ---
class SecurityAnalysis(BaseModel):
    findings: List[str] = Field(description="List of security findings")
    suspicious_activities: List[str] = Field(description="Suspicious activities detected")
    recommendations: List[str] = Field(description="Security recommendations")
    summary: str = Field(description="Executive summary of the analysis")
    risk_level: str = Field(description="Overall risk level: LOW, MEDIUM, HIGH, CRITICAL")
    anomaly_scores: Dict[str, float] = Field(
        default={}, description="Anomaly scores for high-risk users"
    )


class GraphAnalysis(BaseModel):
    network_insights: List[str] = Field(description="Network topology insights")
    risk_patterns: List[str] = Field(description="Risk heatmap patterns identified")
    temporal_findings: List[str] = Field(description="Time series analysis findings")
    graph_summary: str = Field(description="Overall graph analysis summary")
    key_metrics: Dict[str, Any] = Field(default={}, description="Key quantitative metrics")


class ResearchConclusion(BaseModel):
    methodology_summary: str = Field(description="Summary of analytical methodology")
    key_findings: List[str] = Field(description="Primary research findings")
    statistical_insights: List[str] = Field(description="Statistical analysis results")
    limitations: List[str] = Field(description="Study limitations")
    future_research: List[str] = Field(description="Recommendations for future research")
    conclusion: str = Field(description="Overall research conclusion")


class Neo4jConnection:
    def __init__(self):
        self.driver = GraphDatabase.driver(
            os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            auth=basic_auth(
                os.getenv("NEO4J_USERNAME", "neo4j"),
                os.getenv("NEO4J_PASSWORD", "password123"),
            ),
        )

    def close(self):
        if self.driver:
            self.driver.close()

    def execute_query(
        self, query: str, parameters: Dict[str, Any] = None, database: str = "authdata"
    ):
        try:
            with self.driver.session(database=database) as session:
                result = session.run(query, parameters or {})
                records = [record.data() for record in result]
                debug_log(
                    f"Query returned {len(records)} records",
                    {"query": query.split("\n", 1)[0]},
                )
                return {"success": True, "records": records, "error": None}
        except Exception as e:
            debug_log(f"Neo4j query error: {str(e)}", {"query": query})
            return {"success": False, "records": [], "error": str(e)}


class OllamaModelManager:
    def __init__(
        self, ollama_url: str = os.getenv("OLLAMA_API_BASE", "http://127.0.0.1:11434")
    ):
        self.ollama_url = ollama_url

    async def get_available_models(self) -> List[str]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.ollama_url}/api/tags") as resp:
                    if resp.status == 200:
                        return [m["name"] for m in (await resp.json()).get("models", [])]
            return []
        except Exception as e:
            debug_log(f"Error getting models: {e}")
            return []

    async def check_ollama_status(self) -> bool:
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(f"{self.ollama_url}/api/tags", timeout=5) as r:
                    return r.status == 200
        except Exception:
            return False

    async def pull_model(self, model_name: str) -> Dict[str, Any]:
        try:
            debug_log(f"Pulling model: {model_name}")
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.ollama_url}/api/pull", json={"name": model_name}
                ) as response:

                    if response.status != 200:
                        error_text = await response.text()
                        debug_log(f"Model pull failed: {error_text}")
                        return {
                            "success": False,
                            "message": f"Failed to pull model: {error_text}",
                        }

                    progress_updates = []
                    async for line in response.content:
                        if line.strip():
                            try:
                                update = json.loads(line.decode())
                                progress_updates.append(update)
                                debug_log(f"Model pull progress: {update}")
                            except json.JSONDecodeError:
                                continue

                    return {
                        "success": True,
                        "message": f"Model '{model_name}' pulled successfully",
                    }

        except Exception as e:
            debug_log(f"Error during model pull: {str(e)}")
            return {"success": False, "message": f"Error: {str(e)}"}

    def get_recommended_models(self) -> List[str]:
        return ["gemma3:4b", "gemma3:1b", "deepseek-r1:1.5b", "qwen3:0.6b"]


# --- Enhanced Core Agent Logic ---
class ADAnalysisAgent:
    def __init__(self):
        self.model = "ollama/gemma3:1b"
        self.model_manager = OllamaModelManager()
        self.connection = Neo4jConnection()
        self.max_prompt_tokens = 3800
        
        # Enhanced system prompts for different analysis types
        self.security_prompt = (
            "You are a cybersecurity expert. Analyze the provided JSON summary of Active Directory authentication data. "
            "Focus on interpreting the `stats` and `anomaly_summary` to identify threats like lateral movement, red team activity, and high-risk users. "
            "Your response must be a valid JSON object containing the following keys: 'findings' (list of strings), "
            "'suspicious_activities' (list of strings), 'recommendations' (list of strings), "
            "'summary' (a concise executive summary string), and 'risk_level' (string: LOW, MEDIUM, HIGH, CRITICAL). "
            "Ensure 'summary' is always present and a non-empty string."
        )
        
        self.graph_analysis_prompt = (
            "You are a data analyst specializing in graph analysis and network security visualization. "
            "Analyze the provided graph data including network topology, risk patterns, and temporal data. "
            "Explain what each type of visualization reveals about the security posture. "
            "Your response must be a valid JSON object with: 'network_insights' (list), 'risk_patterns' (list), "
            "'temporal_findings' (list), 'graph_summary' (string), and 'key_metrics' (dict)."
        )
        
        self.research_prompt = (
            "You are a cybersecurity researcher writing conclusions for an academic paper on the security breach security analysis. "
            "Based on the provided analysis data, generate research conclusions including methodology, findings, and implications. "
            "Your response must be a valid JSON object with: 'methodology_summary' (string), 'key_findings' (list), "
            "'statistical_insights' (list), 'limitations' (list), 'future_research' (list), and 'conclusion' (string)."
        )

    def set_model(self, model_name: str):
        if not model_name.startswith("ollama/"):
            model_name = f"ollama/{model_name}"
        self.model = model_name

    def get_current_model(self) -> str:
        return self.model.replace("ollama/", "")

    async def analyze_with_graph(self, scan_type: str = "quick") -> Dict[str, Any]:
        try:
            limit = 2000 if scan_type == "full" else 500

            events_query = f"MATCH (u:User)<-[:FROM_USER]-(ae:AuthEvent)-[:TO_COMPUTER]->(c:Computer) RETURN u.name as username, c.name as computer_name, ae.success as success, ae.logon_type as logon_type, ae.auth_type as auth_type, ae.is_redteam as is_redteam, ae.timestamp as timestamp ORDER BY ae.timestamp DESC LIMIT {limit}"
            events_result = self.connection.execute_query(events_query)

            if not events_result.get("records"):
                return {
                    "summary": "Analysis failed: No valid, connected authentication data was found.",
                    "risk_level": "UNKNOWN",
                    "findings": ["No usable authentication events in the database."],
                    "recommendations": [
                        "Ensure your data import script has run successfully and created relationships."
                    ],
                }

            records = events_result["records"]
            anomaly_summary = self._create_anomaly_summary(records)

            prompt = self._build_llm_prompt(records, anomaly_summary)
            token_count = count_tokens(prompt)
            debug_log(f"Final prompt size: {token_count} tokens")
            
            if token_count > self.max_prompt_tokens:
                raise ValueError(
                    f"Prompt is too large ({token_count} tokens). The anomaly summary is too verbose."
                )

            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.security_prompt},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=2000,
                format="json",
            )

            content = response.choices[0].message.content
            try:
                if content.strip().startswith("```json"):
                    content = content.strip()[7:-4]
                result = json.loads(content)
            except json.JSONDecodeError as e:
                raise ValueError(f"AI model returned malformed JSON. Error: {e}")

            result["anomaly_scores"] = anomaly_summary.get("anomaly_scores", {})
            return result

        except Exception as e:
            error_msg = f"Analysis error: {str(e)}"
            debug_log(error_msg, {"traceback": traceback.format_exc()})
            return {
                "summary": f"A critical error occurred: {str(e)}",
                "risk_level": "UNKNOWN",
                "findings": [error_msg],
            }

    async def analyze_graphs(self) -> Dict[str, Any]:
        """Analyze visualization data and provide insights about each graph type"""
        try:
            # Get data for all visualization types
            network_data = await get_graph_for_visualization()
            risk_data = await get_user_behavior_data()
            temporal_data = await get_hourly_data()
            
            # Create analysis summary
            analysis_data = {
                "network_topology": {
                    "total_connections": len(network_data.get("data", [])),
                    "unique_entities": len(set([d.get("user_name") for d in network_data.get("data", [])] + 
                                            [d.get("computer_name") for d in network_data.get("data", [])]))
                },
                "risk_patterns": {
                    "users_analyzed": len(risk_data.get("data", [])),
                    "high_risk_users": len([u for u in risk_data.get("data", []) 
                                          if u.get("fails", 0) / max(u.get("total", 1), 1) > 0.1])
                },
                "temporal_patterns": {
                    "hours_analyzed": len(temporal_data.get("data", {}).get("hourly_data", [])),
                    "peak_hour": max(temporal_data.get("data", {}).get("hourly_data", []), 
                                   key=lambda x: x.get("event_count", 0), default={}).get("hour", "N/A")
                }
            }
            
            prompt = f"Analyze these graph visualization insights: {json.dumps(analysis_data, separators=(',', ':'))}"
            
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.graph_analysis_prompt},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
                max_tokens=1500,
                format="json",
            )

            content = response.choices[0].message.content
            if content.strip().startswith("```json"):
                content = content.strip()[7:-4]
            
            return json.loads(content)

        except Exception as e:
            debug_log(f"Graph analysis error: {str(e)}")
            return {
                "network_insights": [f"Error analyzing network: {str(e)}"],
                "risk_patterns": ["Unable to analyze risk patterns"],
                "temporal_findings": ["Unable to analyze temporal data"],
                "graph_summary": f"Graph analysis failed: {str(e)}",
                "key_metrics": {}
            }

    async def generate_research_conclusions(self, security_analysis: Dict, graph_analysis: Dict) -> Dict[str, Any]:
        """Generate research paper conclusions based on security and graph analysis"""
        try:
            research_data = {
                "security_findings": {
                    "risk_level": security_analysis.get("risk_level", "UNKNOWN"),
                    "findings_count": len(security_analysis.get("findings", [])),
                    "suspicious_activities": len(security_analysis.get("suspicious_activities", [])),
                    "anomaly_users": len(security_analysis.get("anomaly_scores", {}))
                },
                "graph_insights": {
                    "network_patterns": len(graph_analysis.get("network_insights", [])),
                    "risk_indicators": len(graph_analysis.get("risk_patterns", [])),
                    "temporal_anomalies": len(graph_analysis.get("temporal_findings", []))
                },
                "methodology": "Multi-dimensional security breach analysis using graph databases and ML"
            }
            
            prompt = f"Generate research conclusions based on this analysis: {json.dumps(research_data, separators=(',', ':'))}"
            
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.research_prompt},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.4,
                max_tokens=2000,
                format="json",
            )

            content = response.choices[0].message.content
            if content.strip().startswith("```json"):
                content = content.strip()[7:-4]
            
            return json.loads(content)

        except Exception as e:
            debug_log(f"Research conclusion error: {str(e)}")
            return {
                "methodology_summary": f"Analysis methodology encountered error: {str(e)}",
                "key_findings": ["Unable to generate findings due to processing error"],
                "statistical_insights": ["Statistical analysis unavailable"],
                "limitations": [f"Analysis limited by error: {str(e)}"],
                "future_research": ["Error recovery and system optimization needed"],
                "conclusion": f"Research analysis incomplete due to technical issues: {str(e)}"
            }

    def _create_anomaly_summary(self, records: List[Dict]) -> Dict:
        """Create compact statistical summary for analysis"""
        redteam_events = [r for r in records if r.get("is_redteam")]

        # Handle timestamp objects safely
        off_hours_events = []
        for r in records:
            timestamp = r.get("timestamp")
            if timestamp:
                try:
                    if hasattr(timestamp, "hour"):
                        hour = timestamp.hour
                    elif hasattr(timestamp, "to_native"):
                        native_dt = timestamp.to_native()
                        hour = native_dt.hour
                    elif isinstance(timestamp, str):
                        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                        hour = dt.hour
                    else:
                        continue

                    if hour >= 22 or hour <= 6:
                        off_hours_events.append(r)
                except (AttributeError, ValueError, TypeError):
                    continue

        user_failure_counts = Counter()
        user_computer_counts = Counter()
        for r in records:
            if r.get("success") == "Failure" and r.get("username"):
                user_failure_counts[r["username"]] += 1
            if r.get("username"):
                user_computer_counts[r["username"]] += 1

        high_failure_users = {
            user: count for user, count in user_failure_counts.items() if count > 10
        }
        multi_computer_users = {
            user: count for user, count in user_computer_counts.items() if count > 5
        }

        return {
            "redteam_summary": {
                "count": len(redteam_events),
                "top_users": [
                    u for u, c in Counter(
                        r.get("username") for r in redteam_events
                    ).most_common(5)
                ],
                "top_computers": [
                    c for c, c_ in Counter(
                        r.get("computer_name") for r in redteam_events
                    ).most_common(5)
                ],
            },
            "off_hours_summary": {
                "count": len(off_hours_events),
                "top_users": [
                    u for u, c in Counter(
                        r.get("username") for r in off_hours_events
                    ).most_common(5)
                ],
            },
            "high_failure_summary": {
                "count": len(high_failure_users),
                "top_offenders": dict(Counter(high_failure_users).most_common(5)),
            },
            "multiple_computer_access_summary": {
                "count": len(multi_computer_users),
                "top_users": dict(Counter(multi_computer_users).most_common(5)),
            },
            "anomaly_scores": {
                user: count for user, count in user_failure_counts.most_common(20)
            },
        }

    def _build_llm_prompt(self, records: List[Dict], anomaly_summary: Dict) -> str:
        stats = {
            "total_events_scanned": len(records),
            "failed_logins_scanned": sum(
                1 for r in records if r.get("success") == "Failure"
            ),
            "unique_users_scanned": len(
                set(r.get("username") for r in records if r.get("username"))
            ),
        }

        return (
            f"Analyze this security breach data. Focus on interpreting the `stats` and `anomaly_summary`.\n"
            f"**Stats:**\n{json.dumps(stats, separators=(',', ':'))}\n"
            f"**Anomaly Summary:**\n{json.dumps(anomaly_summary, default=str, separators=(',', ':'))}\n"
            f"Based on these summaries, identify findings, suspicious activities, and recommendations."
        )

    def close(self):
        if self.connection:
            self.connection.close()


# --- Global Instance and Interface Functions ---
ad_agent = ADAnalysisAgent()


def check_neo4j_status() -> bool:
    try:
        conn = Neo4jConnection()
        conn.driver.verify_connectivity()
        conn.close()
        return True
    except Exception:
        return False


async def check_llm_status() -> bool:
    try:
        await litellm.acompletion(
            model=ad_agent.model,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=5,
            timeout=10,
        )
        return True
    except Exception:
        return False


async def get_available_models() -> List[str]:
    return await ad_agent.model_manager.get_available_models()


def get_recommended_models() -> List[str]:
    return ad_agent.model_manager.get_recommended_models()


def set_current_model(model_name: str):
    ad_agent.set_model(model_name)


def get_current_model() -> str:
    return ad_agent.get_current_model()


async def run_full_scan() -> str:
    return format_analysis_result(await ad_agent.analyze_with_graph("full"))


async def run_quick_scan() -> str:
    return format_analysis_result(await ad_agent.analyze_with_graph("quick"))


# --- New Enhanced Analysis Functions ---
async def analyze_graphs_with_agent() -> str:
    """Get agent's analysis of the visualization graphs"""
    result = await ad_agent.analyze_graphs()
    return format_graph_analysis(result)


async def generate_research_conclusions_with_agent() -> str:
    """Generate research paper conclusions using the agent"""
    security_analysis = await ad_agent.analyze_with_graph("full")
    graph_analysis = await ad_agent.analyze_graphs()
    research_result = await ad_agent.generate_research_conclusions(security_analysis, graph_analysis)
    return format_research_conclusions(research_result)


def format_analysis_result(result: Dict[str, Any]) -> str:
    try:
        risk = result.get("risk_level", "UNKNOWN").upper()
        emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(risk, "⚪")
        output = [
            f"## {emoji} Risk Level: {risk}\n",
            f"### 📋 Executive Summary\n{result.get('summary', 'N/A')}\n",
        ]
        if result.get("findings"):
            output.extend(
                ["### 🔍 Key Findings", *[f"- {f}" for f in result["findings"]], ""]
            )
        if result.get("suspicious_activities"):
            output.extend(
                [
                    "### ⚠️ Suspicious Activities",
                    *[f"- {a}" for a in result["suspicious_activities"]],
                    "",
                ]
            )
        if result.get("anomaly_scores"):
            scores = sorted(
                result["anomaly_scores"].items(), key=lambda item: item[1], reverse=True
            )
            output.extend(
                [
                    "### 📊 Anomaly Scores (Top Users by Failure Count)",
                    *[f"- **{entity}**: {score} failures" for entity, score in scores[:10]],
                    "",
                ]
            )
        if result.get("recommendations"):
            output.extend(
                ["### 💡 Recommendations", *[f"- {r}" for r in result["recommendations"]]]
            )
        return "\n".join(output)
    except Exception as e:
        debug_log(f"Error formatting results: {str(e)}")
        return f"❌ Error formatting: {str(e)}\n\nRaw: {json.dumps(result, indent=2, default=str)}"


def format_graph_analysis(result: Dict[str, Any]) -> str:
    """Format graph analysis results for display"""
    try:
        output = [
            "# 📊 Graph Analysis Report\n",
            f"## 🔗 Network Topology Insights\n{result.get('graph_summary', 'N/A')}\n"
        ]
        
        if result.get("network_insights"):
            output.extend([
                "### Network Patterns:",
                *[f"- {insight}" for insight in result["network_insights"]],
                ""
            ])
        
        if result.get("risk_patterns"):
            output.extend([
                "### Risk Heatmap Analysis:",
                *[f"- {pattern}" for pattern in result["risk_patterns"]],
                ""
            ])
        
        if result.get("temporal_findings"):
            output.extend([
                "### Temporal Pattern Analysis:",
                *[f"- {finding}" for finding in result["temporal_findings"]],
                ""
            ])
        
        if result.get("key_metrics"):
            output.extend([
                "### Key Metrics:",
                *[f"- **{k}**: {v}" for k, v in result["key_metrics"].items()],
                ""
            ])
        
        return "\n".join(output)
    except Exception as e:
        return f"❌ Error formatting graph analysis: {str(e)}"


def format_research_conclusions(result: Dict[str, Any]) -> str:
    """Format research conclusions for display"""
    try:
        output = [
            "# 🎓 Research Paper Conclusions\n",
            f"## Methodology\n{result.get('methodology_summary', 'N/A')}\n"
        ]
        
        if result.get("key_findings"):
            output.extend([
                "## Key Findings:",
                *[f"- {finding}" for finding in result["key_findings"]],
                ""
            ])
        
        if result.get("statistical_insights"):
            output.extend([
                "## Statistical Insights:",
                *[f"- {insight}" for insight in result["statistical_insights"]],
                ""
            ])
        
        if result.get("limitations"):
            output.extend([
                "## Study Limitations:",
                *[f"- {limitation}" for limitation in result["limitations"]],
                ""
            ])
        
        if result.get("future_research"):
            output.extend([
                "## Future Research Directions:",
                *[f"- {direction}" for direction in result["future_research"]],
                ""
            ])
        
        output.extend([
            f"## Conclusion\n{result.get('conclusion', 'N/A')}"
        ])
        
        return "\n".join(output)
    except Exception as e:
        return f"❌ Error formatting research conclusions: {str(e)}"


# --- Visualization Queries (Schema-Aligned) ---
async def get_graph_for_visualization():
    connection = Neo4jConnection()
    try:
        query = "MATCH (u:User)<-[:FROM_USER]-(evt:AuthEvent)-[:TO_COMPUTER]->(c:Computer) RETURN u.name AS user_name, c.name AS computer_name, count(evt) AS connection_events ORDER BY connection_events DESC LIMIT 200"
        result = connection.execute_query(query)
        return {"success": result["success"], "data": result.get("records", [])}
    finally:
        connection.close()


async def get_hourly_data():
    connection = Neo4jConnection()
    try:
        query = "MATCH (a:AuthEvent) WHERE a.timestamp IS NOT NULL RETURN a.timestamp.hour as hour, count(*) as event_count ORDER BY hour"
        result = connection.execute_query(query)
        return {
            "success": result["success"],
            "data": {"hourly_data": result.get("records", [])},
        }
    finally:
        connection.close()


async def get_user_behavior_data():
    connection = Neo4jConnection()
    try:
        query = "MATCH (u:User)<-[:FROM_USER]-(ae:AuthEvent) RETURN u.name as username, count(ae) as total, sum(CASE WHEN ae.success = 'Failure' THEN 1 ELSE 0 END) as fails ORDER BY total DESC LIMIT 100"
        result = connection.execute_query(query)
        return {"success": result["success"], "data": result.get("records", [])}
    finally:
        connection.close()