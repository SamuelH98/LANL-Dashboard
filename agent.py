"""
Active Directory Red Team Analysis Dashboard with Gradio
Uses Gemma-3 (lightweight LLM) with visualization dashboard

Requirements:
pip install gradio litellm neo4j python-dotenv plotly pandas numpy openai
"""

from dataclasses import dataclass
from typing import List, Dict, Any
import os
import json
import asyncio

import numpy as np
import plotly.graph_objects as go

import gradio as gr
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

# Configure LiteLLM for Gemma-3
litellm.set_verbose = False  # Set to True for debugging

class ADAnalysisAgent:
    """Lightweight AD analysis agent using LiteLLM with Gemma-3"""

    def __init__(self):
        self.model = "ollama/gemma3"  # Gemma-3 model, ensure Ollama is running this model
        self.system_prompt = (
            "You are a cybersecurity expert specializing in Active Directory security analysis and red team detection. "
            "Analyze authentication events, user behavior, and computer interactions to identify potential security threats. "
            "Focus on detecting lateral movement, privilege escalation, suspicious login patterns, and other red team tactics. "
            "Provide actionable security recommendations and assess risk levels appropriately. "
            "Be concise but thorough in your analysis. Format your response as a valid JSON object following this structure: "
            '{"findings": [], "suspicious_activities": [], "recommendations": [], "summary": "", "risk_level": ""}'
        )

    async def analyze(self, query: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze security data using Gemma-3"""
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

ad_agent = ADAnalysisAgent()

# System Status Check Functions
def check_neo4j_status() -> bool:
    try:
        with GraphDatabase.driver(os.getenv("NEO4J_URI"), auth=basic_auth(os.getenv("NEO4J_USERNAME"), os.getenv("NEO4J_PASSWORD"))) as driver:
            driver.verify_connectivity()
        return True
    except Exception:
        return False

async def check_llm_status() -> bool:
    try:
        await litellm.acompletion(model=ad_agent.model, messages=[{"role": "user", "content": "ping"}], max_tokens=5, timeout=10)
        return True
    except Exception:
        return False

async def get_status_html() -> str:
    neo4j_ok, llm_ok = await asyncio.gather(asyncio.to_thread(check_neo4j_status), check_llm_status())
    neo4j_status = "🟢 Neo4j Connected" if neo4j_ok else "🔴 Neo4j Disconnected"
    llm_status = f"🟢 {ad_agent.model} Ready" if llm_ok else f"🔴 {ad_agent.model} Not Ready"
    # --- UPDATED: CSS for dark theme ---
    return f"""
    <div style="padding: 10px; background: #1F2937; border: 1px solid #374151; border-radius: 8px; color: #D1D5DB;">
        <h4>System Status</h4>
        <p style="margin: 5px 0;">{neo4j_status}</p>
        <p style="margin: 5px 0;">{llm_status}</p>
        <p style="margin: 5px 0;">📊 Dashboard Active</p>
    </div>
    """

# Data collection functions
async def analyze_authentication_patterns():
    # ... (function body is unchanged)
    connection = Neo4jConnection()
    try:
        auth_stats = connection.execute_query("""MATCH (ae:AuthEvent) RETURN ae.success as success_status, count(*) as event_count""")
        return {"success": True, "data": {"auth_statistics": auth_stats["records"]}}
    finally:
        connection.close()
async def detect_lateral_movement():
    # ... (function body is unchanged)
    connection = Neo4jConnection()
    try:
        multi_computer = connection.execute_query("""MATCH (u:User)-[:FROM_USER]->(:AuthEvent)-[:TO_COMPUTER]->(c:Computer) WITH u.name as username, count(DISTINCT c.name) as computer_count WHERE computer_count > 3 RETURN username, computer_count ORDER BY computer_count DESC LIMIT 20""")
        return {"success": True, "data": {"multi_computer_access": multi_computer["records"]}}
    finally:
        connection.close()
async def analyze_user_behavior():
    # ... (function body is unchanged)
    connection = Neo4jConnection()
    try:
        active_users = connection.execute_query("""MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent) RETURN u.name as username, count(ae) as total_events ORDER BY total_events DESC LIMIT 20""")
        return {"success": True, "data": {"most_active_users": active_users["records"]}}
    finally:
        connection.close()
async def get_hourly_data():
    # ... (function body is unchanged)
    connection = Neo4jConnection()
    try:
        hourly = connection.execute_query("""MATCH (ae:AuthEvent) WHERE ae.timestamp IS NOT NULL WITH toInteger(substring(ae.timestamp, 11, 2)) as hour, count(*) as event_count RETURN hour, event_count ORDER BY hour""")
        return hourly
    finally:
        connection.close()

# --- UPDATED: Visualization functions with dark theme ---
def create_auth_success_chart(auth_data):
    fig = go.Figure()
    if auth_data:
        labels = ['Successful', 'Failed']
        values = [sum(r['event_count'] for r in auth_data if r['success_status']),
                  sum(r['event_count'] for r in auth_data if not r['success_status'])]
        fig.add_trace(go.Pie(labels=labels, values=values, hole=.4, marker_colors=['#22c55e', '#ef4444']))
    fig.update_layout(title="Authentication Success Rate", template="plotly_dark", paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#E5E7EB'), legend=dict(font=dict(color='#E5E7EB')))
    return fig

def create_hourly_activity_chart(hourly_data):
    fig = go.Figure()
    if hourly_data:
        hours = [item['hour'] for item in hourly_data]
        activity = [item['event_count'] for item in hourly_data]
        fig.add_trace(go.Bar(x=hours, y=activity))
    fig.update_layout(title="Hourly Authentication Activity", xaxis_title="Hour", yaxis_title="Events", template="plotly_dark", paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#E5E7EB'))
    return fig

def create_user_activity_chart(user_data):
    fig = go.Figure()
    if user_data:
        users = [item['username'] for item in user_data[:10]]
        events = [item['total_events'] for item in user_data[:10]]
        fig.add_trace(go.Bar(x=users, y=events))
    fig.update_layout(title="Top 10 Active Users", xaxis_title="User", yaxis_title="Events", template="plotly_dark", paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#E5E7EB'))
    return fig

def create_lateral_movement_chart(lateral_data):
    fig = go.Figure()
    if lateral_data:
        users = [item['username'] for item in lateral_data[:10]]
        computers = [item['computer_count'] for item in lateral_data[:10]]
        fig.add_trace(go.Bar(x=users, y=computers, marker_color='crimson'))
    fig.update_layout(title="Potential Lateral Movement", xaxis_title="User", yaxis_title="# Computers Accessed", template="plotly_dark", paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#E5E7EB'))
    return fig

# Main analysis functions
async def run_analysis(analysis_func, query, *data_funcs):
    try:
        data_results = await asyncio.gather(*[f() for f in data_funcs])
        combined_data = {func.__name__: res.get("data") for func, res in zip(data_funcs, data_results)}
        result = await ad_agent.analyze(query, combined_data)
        return format_analysis_result(result)
    except Exception as e:
        return f"❌ Analysis failed: {str(e)}"

def format_analysis_result(result: Dict[str, Any]) -> str:
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

# Gradio interface functions
async def update_dashboard_and_status():
    (auth_res, user_res, lateral_res, hourly_res), status_html = await asyncio.gather(
        asyncio.gather(analyze_authentication_patterns(), analyze_user_behavior(), detect_lateral_movement(), get_hourly_data()),
        get_status_html()
    )
    auth_chart = create_auth_success_chart(auth_res.get("data", {}).get("auth_statistics"))
    user_chart = create_user_activity_chart(user_res.get("data", {}).get("most_active_users"))
    lateral_chart = create_lateral_movement_chart(lateral_res.get("data", {}).get("multi_computer_access"))
    hourly_chart = create_hourly_activity_chart(hourly_res.get("records"))
    return auth_chart, user_chart, lateral_chart, hourly_chart, status_html

async def analyze_security_threats(analysis_type: str, progress=gr.Progress(track_tqdm=True)):
    progress(0, desc="Starting Analysis...")
    analysis_map = {
        "Comprehensive Analysis": (run_analysis, "Analyze AD data for threats.", analyze_authentication_patterns, detect_lateral_movement, analyze_user_behavior),
        "Lateral Movement Detection": (run_analysis, "Focus on lateral movement.", detect_lateral_movement),
        "User Behavior Analysis": (run_analysis, "Identify suspicious user patterns.", analyze_user_behavior),
    }
    func, query, *data_funcs = analysis_map.get(analysis_type)
    progress(0.5, desc="Querying database and running LLM analysis...")
    result = await func(func, query, *data_funcs)
    progress(1, desc="Analysis Complete!")
    return result

def create_gradio_interface():
    # --- UPDATED: Theme set to Default for dark mode support ---
    with gr.Blocks(title="AD Red Team Analysis Dashboard", theme=gr.themes.Default()) as demo:
        gr.HTML("""
        <div style="text-align: center; max-width: 900px; margin: 20px auto;">
            <h1 style="font-size: 2.5rem;">🔒 Active Directory Red Team Analysis Dashboard</h1>
            <p style="color: #9CA3AF; font-size: 1.1rem;">Real-time security threat detection</p>
        </div>
        """)

        with gr.Row():
            with gr.Column(scale=3):
                gr.HTML("<h2 style='text-align: left;'>📊 Security Visualizations</h2>")
                with gr.Row():
                    auth_plot = gr.Plot(label="Authentication Success Rate")
                    user_plot = gr.Plot(label="Top Active Users")
                with gr.Row():
                    lateral_plot = gr.Plot(label="Lateral Movement Risk")
                    hourly_plot = gr.Plot(label="Hourly Activity")
                refresh_btn = gr.Button("🔄 Refresh Dashboard & Status", variant="secondary")

            with gr.Column(scale=2):
                gr.HTML("<h2 style='text-align: left;'>🔍 Security Analysis</h2>")
                analysis_dropdown = gr.Dropdown(
                    choices=["Comprehensive Analysis", "Lateral Movement Detection", "User Behavior Analysis"],
                    label="Select Analysis Type", value="Comprehensive Analysis"
                )
                analyze_btn = gr.Button("🚀 Run Analysis", variant="primary")
                # This Markdown component will now render as a dark box
                analysis_output = gr.Markdown(
                    label="Analysis Results",
                    value="*Select an analysis type and click 'Run Analysis'. Results will appear here...*",
                    elem_classes="styled-box" # Added for potential custom CSS
                )
                # This HTML component will now have a dark background
                status_output = gr.HTML(label="System Status")

        analyze_btn.click(fn=analyze_security_threats, inputs=[analysis_dropdown], outputs=[analysis_output])
        refresh_btn.click(fn=update_dashboard_and_status, outputs=[auth_plot, user_plot, lateral_plot, hourly_plot, status_output])
        demo.load(fn=update_dashboard_and_status, outputs=[auth_plot, user_plot, lateral_plot, hourly_plot, status_output])
    return demo

if __name__ == "__main__":
    print("Starting AD Red Team Analysis Dashboard...")
    print("Please ensure your Neo4j database and Ollama (with gemma3 model) are running.")
    print("Verify your .env file is configured with NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD.")
    app = create_gradio_interface()
    app.launch(server_name="0.0.0.0", server_port=7860)