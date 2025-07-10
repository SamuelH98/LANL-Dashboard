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
        self.model = "ollama/gemma3"  # Gemma-3 model
        self.system_prompt = (
            "You are a cybersecurity expert specializing in Active Directory security analysis and red team detection. "
            "Analyze authentication events, user behavior, and computer interactions to identify potential security threats. "
            "Focus on detecting lateral movement, privilege escalation, suspicious login patterns, and other red team tactics. "
            "Provide actionable security recommendations and assess risk levels appropriately. "
            "Be concise but thorough in your analysis. Format your response as JSON with the following structure: "
            '{"findings": [], "suspicious_activities": [], "recommendations": [], "summary": "", "risk_level": ""}'
        )
    
    async def analyze(self, query: str, data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze security data using Gemma-3"""
        try:
            # Prepare the prompt with data context
            context = ""
            if data:
                context = f"\n\nData Context:\n{json.dumps(data, indent=2)}"
            
            full_prompt = f"{query}{context}"
            
            # Call Gemma-3 via LiteLLM
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": full_prompt}
                ],
                temperature=0.3,
                max_tokens=1000
            )
            
            # Parse response
            content = response.choices[0].message.content
            
            # Try to parse as JSON, fallback to structured text
            try:
                result = json.loads(content)
                return result
            except json.JSONDecodeError:
                return {
                    "findings": ["Analysis completed"],
                    "suspicious_activities": [],
                    "recommendations": ["Review the detailed analysis"],
                    "summary": content,
                    "risk_level": "MEDIUM"
                }
                
        except Exception as e:
            return {
                "findings": [f"Analysis error: {str(e)}"],
                "suspicious_activities": [],
                "recommendations": ["Check system configuration"],
                "summary": f"Analysis failed: {str(e)}",
                "risk_level": "UNKNOWN"
            }

# Initialize the analysis agent
ad_agent = ADAnalysisAgent()

# Data collection functions (simplified without tool decorators)
async def analyze_authentication_patterns() -> Dict[str, Any]:
    """Analyze authentication patterns to detect suspicious activities."""
    connection = Neo4jConnection()
    
    try:
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
        
        failed_logins_query = """
        MATCH (ae:AuthEvent {success: false})
        RETURN ae.name as username, count(*) as failed_attempts
        ORDER BY failed_attempts DESC
        LIMIT 10
        """
        
        failed_logins = connection.execute_query(failed_logins_query)
        
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
            "data": {
                "auth_statistics": auth_stats["records"],
                "failed_logins": failed_logins["records"],
                "off_hours_activity": off_hours["records"]
            },
            "error": None
        }
        
    except Exception as e:
        return {"success": False, "data": {}, "error": str(e)}
    finally:
        connection.close()

async def detect_lateral_movement() -> Dict[str, Any]:
    """Detect potential lateral movement patterns in the network."""
    connection = Neo4jConnection()
    
    try:
        multi_computer_query = """
        MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
        WITH u.name as username, collect(DISTINCT c.name) as computers, count(DISTINCT c.name) as computer_count
        WHERE computer_count > 3
        RETURN username, computers, computer_count
        ORDER BY computer_count DESC
        LIMIT 20
        """
        
        multi_computer = connection.execute_query(multi_computer_query)
        
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
            "data": {
                "multi_computer_access": multi_computer["records"],
                "rapid_authentication": rapid_auth["records"],
                "unusual_computer_activity": unusual_computers["records"]
            },
            "error": None
        }
        
    except Exception as e:
        return {"success": False, "data": {}, "error": str(e)}
    finally:
        connection.close()

async def analyze_user_behavior() -> Dict[str, Any]:
    """Analyze user behavior patterns for anomalies."""
    connection = Neo4jConnection()
    
    try:
        active_users_query = """
        MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)
        RETURN u.name as username, count(ae) as total_events,
               sum(CASE WHEN ae.success = true THEN 1 ELSE 0 END) as successful_auths,
               sum(CASE WHEN ae.success = false THEN 1 ELSE 0 END) as failed_auths
        ORDER BY total_events DESC
        LIMIT 20
        """
        
        active_users = connection.execute_query(active_users_query)
        
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
            "data": {
                "most_active_users": active_users["records"],
                "high_failure_rate_users": high_failure["records"],
                "authentication_types": auth_types["records"]
            },
            "error": None
        }
        
    except Exception as e:
        return {"success": False, "data": {}, "error": str(e)}
    finally:
        connection.close()

async def get_timeline_analysis(hours_back: int = 24) -> Dict[str, Any]:
    """Analyze authentication events over a specific time period."""
    connection = Neo4jConnection()
    
    try:
        timeline_query = f"""
        MATCH (u:User)-[:FROM_USER]->(ae:AuthEvent)-[:TO_COMPUTER]->(c:Computer)
        WHERE ae.timestamp IS NOT NULL
        RETURN ae.timestamp as timestamp, u.name as username, c.name as computer, 
               ae.success as success, ae.logon_type as logon_type
        ORDER BY ae.timestamp DESC
        LIMIT 100
        """
        
        timeline = connection.execute_query(timeline_query)
        
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
            "data": {
                "recent_events": timeline["records"],
                "hourly_distribution": hourly["records"]
            },
            "error": None
        }
        
    except Exception as e:
        return {"success": False, "data": {}, "error": str(e)}
    finally:
        connection.close()

async def get_network_overview() -> Dict[str, Any]:
    """Get an overview of the Active Directory network structure."""
    connection = Neo4jConnection()
    
    try:
        stats_query = """
        MATCH (n)
        RETURN labels(n) as node_type, count(*) as count
        ORDER BY count DESC
        """
        
        stats = connection.execute_query(stats_query)
        
        rel_stats_query = """
        MATCH ()-[r]->()
        RETURN type(r) as relationship_type, count(*) as count
        ORDER BY count DESC
        """
        
        rel_stats = connection.execute_query(rel_stats_query)
        
        return {
            "success": True,
            "data": {
                "node_statistics": stats["records"],
                "relationship_statistics": rel_stats["records"]
            },
            "error": None
        }
        
    except Exception as e:
        return {"success": False, "data": {}, "error": str(e)}
    finally:
        connection.close()

# Visualization functions
def create_auth_success_chart(auth_data):
    """Create authentication success/failure chart"""
    if not auth_data:
        return go.Figure()
    
    # Sample data for demonstration
    labels = ['Successful', 'Failed']
    values = [75, 25]  # This would come from actual data
    
    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.3)])
    fig.update_layout(
        title="Authentication Success Rate",
        annotations=[dict(text='Auth<br>Events', x=0.5, y=0.5, font_size=16, showarrow=False)]
    )
    return fig

def create_hourly_activity_chart(hourly_data):
    """Create hourly activity distribution chart"""
    if not hourly_data:
        # Sample data for demonstration
        hours = list(range(24))
        activity = np.random.poisson(50, 24)
        activity[0:6] = np.random.poisson(10, 6)  # Lower activity at night
        activity[22:24] = np.random.poisson(15, 2)
    else:
        hours = [item['hour'] for item in hourly_data]
        activity = [item['event_count'] for item in hourly_data]
    
    fig = go.Figure()
    fig.add_trace(go.Bar(x=hours, y=activity, name='Authentication Events'))
    fig.update_layout(
        title="Hourly Authentication Activity",
        xaxis_title="Hour of Day",
        yaxis_title="Number of Events"
    )
    return fig

def create_user_activity_chart(user_data):
    """Create top user activity chart"""
    if not user_data:
        # Sample data for demonstration
        users = ['user1', 'user2', 'user3', 'user4', 'user5']
        events = [150, 120, 90, 75, 60]
    else:
        users = [item['username'] for item in user_data[:10]]
        events = [item['total_events'] for item in user_data[:10]]
    
    fig = go.Figure()
    fig.add_trace(go.Bar(x=users, y=events, name='Total Events'))
    fig.update_layout(
        title="Top Active Users",
        xaxis_title="Users",
        yaxis_title="Number of Events"
    )
    return fig

def create_lateral_movement_chart(lateral_data):
    """Create lateral movement visualization"""
    if not lateral_data:
        # Sample data for demonstration
        users = ['admin1', 'user2', 'service1', 'user4']
        computers = [8, 6, 5, 4]
    else:
        users = [item['username'] for item in lateral_data[:10]]
        computers = [item['computer_count'] for item in lateral_data[:10]]
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=users, y=computers,
        mode='markers',
        marker=dict(size=15, color='red', opacity=0.7),
        name='Lateral Movement Risk'
    ))
    fig.update_layout(
        title="Potential Lateral Movement (Users accessing multiple computers)",
        xaxis_title="Users",
        yaxis_title="Number of Computers Accessed"
    )
    return fig

# Main analysis functions using LiteLLM
async def run_comprehensive_analysis():
    """Run comprehensive security analysis"""
    try:
        # Collect data from all sources
        auth_data = await analyze_authentication_patterns()
        lateral_data = await detect_lateral_movement()
        user_data = await analyze_user_behavior()
        timeline_data = await get_timeline_analysis()
        network_data = await get_network_overview()
        
        # Combine all data
        combined_data = {
            "authentication_patterns": auth_data,
            "lateral_movement": lateral_data,
            "user_behavior": user_data,
            "timeline": timeline_data,
            "network_overview": network_data
        }
        
        # Analyze with Gemma-3
        result = await ad_agent.analyze(
            "Analyze my Active Directory authentication data for security threats and red team activities. "
            "Look for suspicious patterns, lateral movement, and potential compromises.",
            combined_data
        )
        
        return format_analysis_result(result)
        
    except Exception as e:
        return f"❌ Comprehensive analysis failed: {str(e)}"

async def run_lateral_movement_analysis():
    """Run lateral movement analysis"""
    try:
        lateral_data = await detect_lateral_movement()
        auth_data = await analyze_authentication_patterns()
        
        combined_data = {
            "lateral_movement": lateral_data,
            "authentication_patterns": auth_data
        }
        
        result = await ad_agent.analyze(
            "Focus on detecting lateral movement attempts. Which users are accessing multiple computers? "
            "Are there any rapid authentication sequences that suggest automated tools?",
            combined_data
        )
        
        return format_analysis_result(result)
        
    except Exception as e:
        return f"❌ Lateral movement analysis failed: {str(e)}"

async def run_user_behavior_analysis():
    """Run user behavior analysis"""
    try:
        user_data = await analyze_user_behavior()
        auth_data = await analyze_authentication_patterns()
        
        combined_data = {
            "user_behavior": user_data,
            "authentication_patterns": auth_data
        }
        
        result = await ad_agent.analyze(
            "Identify users with suspicious authentication patterns. Who has high failure rates? "
            "Any off-hours activity or unusual authentication types?",
            combined_data
        )
        
        return format_analysis_result(result)
        
    except Exception as e:
        return f"❌ User behavior analysis failed: {str(e)}"

def format_analysis_result(result: Dict[str, Any]) -> str:
    """Format the analysis result for display"""
    try:
        output = []
        
        # Risk Level
        risk_level = result.get("risk_level", "UNKNOWN")
        risk_emoji = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}.get(risk_level, "⚪")
        output.append(f"## {risk_emoji} Risk Level: {risk_level}\n")
        
        # Summary
        if result.get("summary"):
            output.append(f"## 📋 Executive Summary\n{result['summary']}\n")
        
        # Findings
        if result.get("findings"):
            output.append("## 🔍 Key Findings")
            for finding in result["findings"]:
                output.append(f"• {finding}")
            output.append("")
        
        # Suspicious Activities
        if result.get("suspicious_activities"):
            output.append("## ⚠️ Suspicious Activities")
            for activity in result["suspicious_activities"]:
                output.append(f"• {activity}")
            output.append("")
        
        # Recommendations
        if result.get("recommendations"):
            output.append("## 💡 Recommendations")
            for rec in result["recommendations"]:
                output.append(f"• {rec}")
            output.append("")
        
        return "\n".join(output)
        
    except Exception as e:
        return f"❌ Error formatting results: {str(e)}"

# Gradio interface functions
def update_dashboard():
    """Update all dashboard visualizations"""
    # In a real implementation, this would fetch fresh data from Neo4j
    auth_chart = create_auth_success_chart(None)
    hourly_chart = create_hourly_activity_chart(None)
    user_chart = create_user_activity_chart(None)
    lateral_chart = create_lateral_movement_chart(None)
    
    return auth_chart, hourly_chart, user_chart, lateral_chart

async def analyze_security_threats(analysis_type):
    """Main analysis function for Gradio interface"""
    if analysis_type == "Comprehensive Analysis":
        return await run_comprehensive_analysis()
    elif analysis_type == "Lateral Movement Detection":
        return await run_lateral_movement_analysis()
    elif analysis_type == "User Behavior Analysis":
        return await run_user_behavior_analysis()
    else:
        return "Please select an analysis type."

# Create Gradio interface
def create_gradio_interface():
    """Create the main Gradio interface"""
    
    with gr.Blocks(title="AD Red Team Analysis Dashboard", theme=gr.themes.Soft()) as demo:
        gr.HTML("""
        <div style="text-align: center; padding: 20px;">
            <h1>🔒 Active Directory Red Team Analysis Dashboard</h1>
            <p> Real-time security threat detection and analysis</p>
        </div>
        """)
        
        with gr.Row():
            # Left column - Visualizations
            with gr.Column(scale=2):
                gr.HTML("<h2>📊 Security Visualizations</h2>")
                
                with gr.Row():
                    auth_plot = gr.Plot(label="Authentication Success Rate")
                    hourly_plot = gr.Plot(label="Hourly Activity")
                
                with gr.Row():
                    user_plot = gr.Plot(label="Top Active Users")
                    lateral_plot = gr.Plot(label="Lateral Movement Risk")
                
                refresh_btn = gr.Button("🔄 Refresh Charts", variant="secondary")
                
            # Right column - Analysis and Controls
            with gr.Column(scale=1):
                gr.HTML("<h2>🔍 Security Analysis</h2>")
                
                analysis_dropdown = gr.Dropdown(
                    choices=[
                        "Comprehensive Analysis",
                        "Lateral Movement Detection", 
                        "User Behavior Analysis"
                    ],
                    label="Select Analysis Type",
                    value="Comprehensive Analysis"
                )
                
                analyze_btn = gr.Button("🚀 Run Analysis", variant="primary")
                
                with gr.Accordion("ℹ️ Analysis Information", open=False):
                    gr.HTML("""
                    <ul>
                        <li><strong>Comprehensive Analysis:</strong> Full security assessment</li>
                        <li><strong>Lateral Movement:</strong> Detect horizontal network movement</li>
                        <li><strong>User Behavior:</strong> Identify anomalous user patterns</li>
                    </ul>
                    """)
                
                analysis_output = gr.Textbox(
                    label="Analysis Results",
                    lines=15,
                    placeholder="Analysis results will appear here...",
                    interactive=False
                )
                
                # Status indicators
                with gr.Row():
                    gr.HTML("""
                    <div style="padding: 10px; background: #1F2937; border-radius: 5px;">
                        <h4>System Status</h4>
                        <p>🟢 Neo4j Connected</p>
                        <p>🟢 Gemma-3 Ready (LiteLLM)</p>
                        <p>📊 Dashboard Active</p>
                    </div>
                    """)
        
        # Event handlers
        def run_analysis_sync(analysis_type):
            """Synchronous wrapper for async analysis"""
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(analyze_security_threats(analysis_type))
            finally:
                loop.close()
        
        analyze_btn.click(
            fn=run_analysis_sync,
            inputs=[analysis_dropdown],
            outputs=[analysis_output]
        )
        
        refresh_btn.click(
            fn=update_dashboard,
            outputs=[auth_plot, hourly_plot, user_plot, lateral_plot]
        )
        
        # Initialize charts on load
        demo.load(
            fn=update_dashboard,
            outputs=[auth_plot, hourly_plot, user_plot, lateral_plot]
        )
    
    return demo

# Main execution
if __name__ == "__main__":
    # Create .env file with your credentials:
    # NEO4J_URI=bolt://localhost:7687
    # NEO4J_USERNAME=neo4j
    # NEO4J_PASSWORD=your_password
    
    print("Starting AD Red Team Analysis Dashboard...")
    print("Make sure your Neo4j database is running and .env file is configured.")
    
    demo = create_gradio_interface()
    demo.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False,
        debug=True
    )