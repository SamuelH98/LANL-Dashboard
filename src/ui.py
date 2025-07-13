"""
Gradio UI components for the Active Directory Red Team Analysis Dashboard
"""

import asyncio
import plotly.graph_objects as go
import gradio as gr

from agent import (
    check_neo4j_status, check_llm_status, ad_agent,
    analyze_authentication_patterns, analyze_user_behavior,
    detect_lateral_movement, get_hourly_data, run_analysis
)

# Status functions
async def get_status_html() -> str:
    """Generate HTML status display"""
    neo4j_ok, llm_ok = await asyncio.gather(
        asyncio.to_thread(check_neo4j_status), 
        check_llm_status()
    )
    neo4j_status = "🟢 Neo4j Connected" if neo4j_ok else "🔴 Neo4j Disconnected"
    llm_status = f"🟢 {ad_agent.model} Ready" if llm_ok else f"🔴 {ad_agent.model} Not Ready"
    
    return f"""
    <div style="padding: 10px; background: #1F2937; border: 1px solid #374151; border-radius: 8px; color: #D1D5DB;">
        <h4>System Status</h4>
        <p style="margin: 5px 0;">{neo4j_status}</p>
        <p style="margin: 5px 0;">{llm_status}</p>
        <p style="margin: 5px 0;">📊 Dashboard Active</p>
    </div>
    """

# Visualization functions with dark theme
def create_auth_success_chart(auth_data):
    """Create authentication success rate pie chart"""
    fig = go.Figure()
    if auth_data:
        labels = ['Successful', 'Failed']
        values = [
            sum(r['event_count'] for r in auth_data if r['success_status']),
            sum(r['event_count'] for r in auth_data if not r['success_status'])
        ]
        fig.add_trace(go.Pie(labels=labels, values=values, hole=.4, marker_colors=['#22c55e', '#ef4444']))
    
    fig.update_layout(
        title="Authentication Success Rate",
        template="plotly_dark",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#E5E7EB'),
        legend=dict(font=dict(color='#E5E7EB'))
    )
    return fig

def create_hourly_activity_chart(hourly_data):
    """Create hourly activity bar chart"""
    fig = go.Figure()
    if hourly_data:
        hours = [item['hour'] for item in hourly_data]
        activity = [item['event_count'] for item in hourly_data]
        fig.add_trace(go.Bar(x=hours, y=activity))
    
    fig.update_layout(
        title="Hourly Authentication Activity",
        xaxis_title="Hour",
        yaxis_title="Events",
        template="plotly_dark",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#E5E7EB')
    )
    return fig

def create_user_activity_chart(user_data):
    """Create user activity bar chart"""
    fig = go.Figure()
    if user_data:
        users = [item['username'] for item in user_data[:10]]
        events = [item['total_events'] for item in user_data[:10]]
        fig.add_trace(go.Bar(x=users, y=events))
    
    fig.update_layout(
        title="Top 10 Active Users",
        xaxis_title="User",
        yaxis_title="Events",
        template="plotly_dark",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#E5E7EB')
    )
    return fig

def create_lateral_movement_chart(lateral_data):
    """Create lateral movement risk chart"""
    fig = go.Figure()
    if lateral_data:
        users = [item['username'] for item in lateral_data[:10]]
        computers = [item['computer_count'] for item in lateral_data[:10]]
        fig.add_trace(go.Bar(x=users, y=computers, marker_color='crimson'))
    
    fig.update_layout(
        title="Potential Lateral Movement",
        xaxis_title="User",
        yaxis_title="# Computers Accessed",
        template="plotly_dark",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#E5E7EB')
    )
    return fig

# Dashboard update functions
async def update_dashboard_and_status():
    """Update all dashboard components and system status"""
    (auth_res, user_res, lateral_res, hourly_res), status_html = await asyncio.gather(
        asyncio.gather(
            analyze_authentication_patterns(),
            analyze_user_behavior(),
            detect_lateral_movement(),
            get_hourly_data()
        ),
        get_status_html()
    )
    
    auth_chart = create_auth_success_chart(auth_res.get("data", {}).get("auth_statistics"))
    user_chart = create_user_activity_chart(user_res.get("data", {}).get("most_active_users"))
    lateral_chart = create_lateral_movement_chart(lateral_res.get("data", {}).get("multi_computer_access"))
    hourly_chart = create_hourly_activity_chart(hourly_res.get("records"))
    
    return auth_chart, user_chart, lateral_chart, hourly_chart, status_html

async def analyze_security_threats(analysis_type: str, progress=gr.Progress(track_tqdm=True)):
    """Run security threat analysis based on selected type"""
    progress(0, desc="Starting Analysis...")
    
    analysis_map = {
        "Comprehensive Analysis": (
            run_analysis,
            "Analyze AD data for threats.",
            analyze_authentication_patterns,
            detect_lateral_movement,
            analyze_user_behavior
        ),
        "Lateral Movement Detection": (
            run_analysis,
            "Focus on lateral movement.",
            detect_lateral_movement
        ),
        "User Behavior Analysis": (
            run_analysis,
            "Identify suspicious user patterns.",
            analyze_user_behavior
        ),
    }
    
    func, query, *data_funcs = analysis_map.get(analysis_type)
    progress(0.5, desc="Querying database and running LLM analysis...")
    result = await func(func, query, *data_funcs)
    progress(1, desc="Analysis Complete!")
    return result

def create_gradio_interface():
    """Create and configure the Gradio interface"""
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
                    label="Select Analysis Type",
                    value="Comprehensive Analysis"
                )
                
                analyze_btn = gr.Button("🚀 Run Analysis", variant="primary")
                
                analysis_output = gr.Markdown(
                    label="Analysis Results",
                    value="*Select an analysis type and click 'Run Analysis'. Results will appear here...*",
                    elem_classes="styled-box"
                )
                
                status_output = gr.HTML(label="System Status")

        # Event handlers
        analyze_btn.click(
            fn=analyze_security_threats,
            inputs=[analysis_dropdown],
            outputs=[analysis_output]
        )
        
        refresh_btn.click(
            fn=update_dashboard_and_status,
            outputs=[auth_plot, user_plot, lateral_plot, hourly_plot, status_output]
        )
        
        demo.load(
            fn=update_dashboard_and_status,
            outputs=[auth_plot, user_plot, lateral_plot, hourly_plot, status_output]
        )
    
    return demo