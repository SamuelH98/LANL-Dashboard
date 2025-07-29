"""
Enhanced Gradio UI components for the Active Directory Red Team Analysis Dashboard
Includes debug functionality and ML analysis features
"""

import asyncio
import plotly.graph_objects as go
import plotly.express as px
import gradio as gr
import networkx as nx
import json
import pandas as pd
from datetime import datetime

from agent import *

# Global debug output storage
debug_output = []

def add_debug_output(message: str):
    """Add message to debug output"""
    global debug_output
    timestamp = datetime.now().strftime("%H:%M:%S")
    debug_output.append(f"[{timestamp}] {message}")
    # Keep only last 50 messages
    debug_output = debug_output[-50:]

def get_debug_output() -> str:
    """Get current debug output as formatted string"""
    global debug_output
    return "\n".join(debug_output) if debug_output else "Debug output will appear here..."

def clear_debug_output():
    """Clear debug output"""
    global debug_output
    debug_output = []
    return "Debug output cleared."

# Status functions
async def get_status_html() -> str:
    """Generate HTML status display"""
    neo4j_ok, llm_ok, ollama_ok = await asyncio.gather(
        asyncio.to_thread(check_neo4j_status), 
        check_llm_status(),
        OllamaModelManager().check_ollama_status()
    )
    
    neo4j_status = "🟢 Neo4j Connected" if neo4j_ok else "🔴 Neo4j Disconnected"
    llm_status = f"🟢 {ad_agent.get_current_model()} Ready" if llm_ok else f"🔴 {ad_agent.get_current_model()} Not Ready"
    ollama_status = "🟢 Ollama Service Running" if ollama_ok else "🔴 Ollama Service Down"
    debug_status = f"🔧 Debug Mode: {'ON' if get_debug_mode() else 'OFF'}"
    
    return f"""
    <div style="padding: 15px; background: #1F2937; border: 1px solid #374151; border-radius: 8px; color: #D1D5DB;">
        <h4 style="margin-top: 0;">System Status</h4>
        <p style="margin: 5px 0;">{neo4j_status}</p>
        <p style="margin: 5px 0;">{ollama_status}</p>
        <p style="margin: 5px 0;">{llm_status}</p>
        <p style="margin: 5px 0;">{debug_status}</p>
        <p style="margin: 5px 0;">📊 Dashboard Active</p>
    </div>
    """

# Debug toggle function
async def toggle_debug_mode(enabled: bool):
    """Toggle debug mode and update status"""
    set_debug_mode(enabled)
    add_debug_output(f"Debug mode {'ENABLED' if enabled else 'DISABLED'}")
    status_html = await get_status_html()
    return status_html, get_debug_output()

# Model management functions
async def refresh_available_models():
    """Refresh the list of available models"""
    add_debug_output("Refreshing available models...")
    models = await get_available_models()
    add_debug_output(f"Found {len(models)} available models: {models}")
    return gr.Dropdown(choices=models, value=get_current_model() if get_current_model() in models else (models[0] if models else None))

async def pull_model_handler(model_name: str):
    """Handle model pulling with progress feedback"""
    if not model_name.strip():
        add_debug_output("ERROR: No model name provided for pulling")
        return "❌ Please enter a model name", gr.Dropdown()
    
    try:
        add_debug_output(f"Starting model pull for: {model_name.strip()}")
        result = await pull_model(model_name.strip())
        
        # Explicitly check for manifest errors in updates
        manifest_error = any(
            ("error" in update and "manifest" in update["error"].lower()) 
            for update in result.get("updates", [])
        )
        
        if result["success"] and not manifest_error:
            models = await get_available_models()
            dropdown_update = gr.Dropdown(choices=models, value=model_name.strip())
            add_debug_output(f"SUCCESS: Model {model_name.strip()} pulled successfully")
            return f"✅ {result['message']}", dropdown_update
        else:
            # Extract the manifest error or use default message
            error_msg = next(
                (update["error"] for update in result.get("updates", [])
                 if "error" in update and "manifest" in update["error"].lower()),
                result.get("message", "Model pull failed (unknown error)")
            )
            add_debug_output(f"ERROR: Model pull failed - {error_msg}")
            return f"❌ {error_msg} - incorrect model name", gr.Dropdown()
            
    except Exception as e:
        add_debug_output(f"EXCEPTION during model pull: {str(e)}")
        return f"❌ Error during model pull: {str(e)}", gr.Dropdown()

async def switch_model_handler(model_name: str):
    """Handle model switching"""
    if not model_name:
        add_debug_output("ERROR: No model selected for switching")
        return "❌ Please select a model", await get_status_html()
    
    try:
        add_debug_output(f"Switching to model: {model_name}")
        set_current_model(model_name)
        status_html = await get_status_html()
        add_debug_output(f"SUCCESS: Switched to model {model_name}")
        return f"✅ Switched to model: {model_name}", status_html
    except Exception as e:
        add_debug_output(f"ERROR switching model: {str(e)}")
        status_html = await get_status_html()
        return f"❌ Error switching model: {str(e)}", status_html

# Enhanced visualization functions
async def create_network_visualization():
    """Create a Plotly network graph from Neo4j data with ML insights."""
    add_debug_output("Creating network visualization...")
    
    try:
        graph_data = await get_graph_for_visualization()
        if not graph_data["success"] or not graph_data["data"]:
            add_debug_output("No graph data available for visualization")
            return go.Figure().add_annotation(text="No data available", x=0.5, y=0.5)

        add_debug_output(f"Processing {len(graph_data['data'])} graph records")
        
        G = nx.Graph()
        node_info = {}
        
        for record in graph_data["data"]:
            user = record['u']
            computer = record['c']
            auth_event = record['ae']
            
            user_name = user.get('name', f"user_{user.get('id', 'unknown')}")
            computer_name = computer.get('name', f"computer_{computer.get('id', 'unknown')}")
            
            G.add_node(user_name, type='User', full_data=user)
            G.add_node(computer_name, type='Computer', full_data=computer)
            G.add_edge(user_name, computer_name, auth_data=auth_event)
            
            node_info[user_name] = {'type': 'User', 'data': user}
            node_info[computer_name] = {'type': 'Computer', 'data': computer}

        # Apply ML insights if available
        ml_analysis = graph_data.get("ml_analysis")
        risk_scores = {}
        if ml_analysis and ml_analysis.risk_scores:
            risk_scores = ml_analysis.risk_scores
            add_debug_output(f"Applied ML risk scores to {len(risk_scores)} nodes")

        pos = nx.spring_layout(G, k=1, iterations=50)
        
        # Create edges
        edge_x, edge_y = [], []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines'
        )

        # Create nodes with risk-based coloring
        node_x, node_y, node_text, node_color, node_size = [], [], [], [], []
        
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
            risk_score = risk_scores.get(node, 0)
            node_type = node_info[node]['type']
            
            # Color based on risk score and type
            if risk_score > 0.7:
                color = 'red'
            elif risk_score > 0.4:
                color = 'orange'
            elif node_type == 'User':
                color = 'lightblue'
            else:
                color = 'lightgreen'
            
            node_color.append(color)
            node_size.append(15 + risk_score * 20)  # Size based on risk
            
            hover_text = f"{node}<br>Type: {node_type}<br>Risk Score: {risk_score:.3f}<br>Connections: {G.degree(node)}"
            node_text.append(hover_text)

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=[node_info[node]['data'].get('name', node) for node in G.nodes()],
            hovertext=node_text,
            textposition="middle center",
            marker=dict(
                color=node_color,
                size=node_size,
                line=dict(width=2, color='white')
            )
        )

        fig = go.Figure(data=[edge_trace, node_trace],
                 layout=go.Layout(
                    title='Active Directory Network Graph (Risk-Based Visualization)',
                    titlefont_size=16,
                    showlegend=False,
                    hovermode='closest',
                    margin=dict(b=20,l=5,r=5,t=40),
                    annotations=[dict(
                        text="Node size and color indicate ML-calculated risk levels",
                        showarrow=False,
                        xref="paper", yref="paper",
                        x=0.005, y=-0.002
                    )],
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                ))
        
        add_debug_output("Network visualization created successfully")
        return fig
        
    except Exception as e:
        add_debug_output(f"ERROR creating network visualization: {str(e)}")
        return go.Figure().add_annotation(text=f"Error: {str(e)}", x=0.5, y=0.5)

async def create_risk_heatmap():
    """Create a risk heatmap based on ML analysis"""
    try:
        add_debug_output("Creating risk heatmap...")
        
        # Get user behavior data
        behavior_data = await analyze_user_behavior()
        if not behavior_data["success"]:
            return go.Figure().add_annotation(text="No behavior data available", x=0.5, y=0.5)
        
        users = behavior_data["data"]["most_active_users"][:20]  # Top 20 users
        ml_analysis = behavior_data.get("ml_analysis", {})
        risk_scores = ml_analysis.risk_scores if hasattr(ml_analysis, 'risk_scores') else {}
        
        # Create heatmap data
        usernames = [user["username"] for user in users]
        total_events = [user["total_events"] for user in users]
        failed_events = [user["failed_events"] for user in users]
        risk_values = [risk_scores.get(user["username"], 0) for user in users]
        
        # Create subplot with multiple metrics
        fig = go.Figure()
        
        # Add risk score heatmap
        fig.add_trace(go.Heatmap(
            z=[risk_values],
            x=usernames,
            y=['Risk Score'],
            colorscale='Reds',
            showscale=True,
            colorbar=dict(title="Risk Level")
        ))
        
        fig.update_layout(
            title='User Risk Heatmap (ML-Based)',
            xaxis_title='Users',
            yaxis_title='Metrics',
            height=200
        )
        
        add_debug_output(f"Risk heatmap created for {len(usernames)} users")
        return fig
        
    except Exception as e:
        add_debug_output(f"ERROR creating risk heatmap: {str(e)}")
        return go.Figure().add_annotation(text=f"Error: {str(e)}", x=0.5, y=0.5)

async def create_time_series_plot():
    """Create time series visualization of authentication patterns"""
    try:
        add_debug_output("Creating time series plot...")
        
        hourly_data = await get_hourly_data()
        if not hourly_data["success"]:
            return go.Figure().add_annotation(text="No hourly data available", x=0.5, y=0.5)
        
        hourly_records = hourly_data["data"]["hourly_data"]
        
        hours = [record["hour"] for record in hourly_records]
        events = [record["event_count"] for record in hourly_records]
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=hours,
            y=events,
            mode='lines+markers',
            name='Authentication Events',
            line=dict(color='blue', width=3),
            marker=dict(size=8)
        ))
        
        # Add anomaly detection (simple threshold-based)
        avg_events = sum(events) / len(events)
        threshold = avg_events * 1.5
        
        anomaly_hours = [h for h, e in zip(hours, events) if e > threshold]
        anomaly_events = [e for e in events if e > threshold]
        
        if anomaly_hours:
            fig.add_trace(go.Scatter(
                x=anomaly_hours,
                y=anomaly_events,
                mode='markers',
                name='Anomalous Activity',
                marker=dict(color='red', size=12, symbol='star')
            ))
        
        fig.update_layout(
            title='Hourly Authentication Patterns with Anomaly Detection',
            xaxis_title='Hour of Day',
            yaxis_title='Number of Events',
            height=400
        )
        
        add_debug_output(f"Time series plot created with {len(anomaly_hours)} anomalies detected")
        return fig
        
    except Exception as e:
        add_debug_output(f"ERROR creating time series plot: {str(e)}")
        return go.Figure().add_annotation(text=f"Error: {str(e)}", x=0.5, y=0.5)

# Dashboard update functions
async def update_status_only():
    """Update only the system status"""
    return await get_status_html()

async def analyze_security_threats(analysis_type: str, progress=gr.Progress(track_tqdm=True)):
    """Run security threat analysis based on selected type with ML enhancement"""
    progress(0, desc="Starting Analysis...")
    add_debug_output(f"Starting {analysis_type} analysis")
    
    analysis_map = {
        "Comprehensive Analysis": (
            run_analysis,
            "Perform comprehensive AD security analysis with ML insights. Focus on user behavior, authentication patterns, lateral movement, and network topology.",
            analyze_authentication_patterns,
            detect_lateral_movement,
            analyze_user_behavior,
            analyze_network_segmentation
        ),
        "Lateral Movement Detection": (
            run_analysis,
            "Focus on detecting lateral movement patterns and privilege escalation attempts using ML algorithms.",
            detect_lateral_movement,
            detect_privilege_escalation
        ),
        "User Behavior Analysis": (
            run_analysis,
            "Analyze user behavior patterns, identify outliers and suspicious account usage with ML-powered anomaly detection.",
            analyze_user_behavior,
            analyze_account_usage_patterns
        ),
        "Credential Attack Detection": (
            run_analysis,
            "Detect credential stuffing, brute force attacks, and suspicious authentication patterns.",
            detect_credential_stuffing,
            analyze_authentication_patterns
        ),
        "Network Topology Analysis": (
            run_analysis,
            "Analyze network topology, segmentation, and communication patterns for security insights.",
            analyze_network_segmentation,
            get_graph_for_visualization
        )
    }
    
    if analysis_type not in analysis_map:
        add_debug_output(f"ERROR: Unknown analysis type: {analysis_type}")
        return "❌ Unknown analysis type selected"
    
    func, query, *data_funcs = analysis_map[analysis_type]
    progress(0.3, desc="Collecting data from Neo4j...")
    add_debug_output(f"Running {len(data_funcs)} data collection functions")
    
    progress(0.6, desc=f"Running ML analysis and LLM processing with {get_current_model()}...")
    result = await func(func, query, *data_funcs)
    
    progress(1, desc="Analysis Complete!")
    add_debug_output(f"Analysis completed: {analysis_type}")
    return result

async def refresh_dashboard_data():
    """Refresh all dashboard visualizations"""
    add_debug_output("Refreshing dashboard data...")
    
    try:
        network_viz, risk_heatmap, time_series = await asyncio.gather(
            create_network_visualization(),
            create_risk_heatmap(),
            create_time_series_plot()
        )
        
        add_debug_output("Dashboard data refreshed successfully")
        return network_viz, risk_heatmap, time_series
        
    except Exception as e:
        add_debug_output(f"ERROR refreshing dashboard: {str(e)}")
        empty_fig = go.Figure().add_annotation(text=f"Error: {str(e)}", x=0.5, y=0.5)
        return empty_fig, empty_fig, empty_fig

def create_gradio_interface():
    """Create and configure the enhanced Gradio interface with debug functionality"""
    with gr.Blocks(title="AD Red Team Analysis Dashboard", theme=gr.themes.Default()) as demo:
        gr.HTML("""
        <div style="text-align: center; max-width: 1200px; margin: 20px auto;">
            <h1 style="font-size: 2.5rem;">🔒 AD Red Team Analysis Dashboard</h1>
            <p style="color: #9CA3AF; font-size: 1.1rem;">AI-powered security threat detection with machine learning analysis and advanced debugging</p>
        </div>
        """)

        with gr.Tabs():
            # Main Analysis Tab
            with gr.TabItem("🔍 Security Analysis", id="analysis_tab"):
                with gr.Row():
                    with gr.Column(scale=2):
                        gr.HTML("<h2 style='text-align: left;'>🎯 Analysis Control</h2>")
                        
                        analysis_dropdown = gr.Dropdown(
                            choices=[
                                "Comprehensive Analysis", 
                                "Lateral Movement Detection", 
                                "User Behavior Analysis",
                                "Credential Attack Detection",
                                "Network Topology Analysis"
                            ],
                            label="Select Analysis Type",
                            value="Comprehensive Analysis",
                            info="Choose the type of security analysis to perform"
                        )
                        
                        with gr.Row():
                            analyze_btn = gr.Button("🚀 Run Analysis", variant="primary", size="lg")
                            refresh_data_btn = gr.Button("🔄 Refresh Data", variant="secondary")
                        
                        analysis_output = gr.Markdown(
                            label="Analysis Results",
                            value="*Select an analysis type and click 'Run Analysis'. Results will appear here...*",
                            elem_classes="analysis-output",
                            height=600
                        )

                    with gr.Column(scale=3):
                        gr.HTML("<h2 style='text-align: left;'>📊 Real-time Visualizations</h2>")
                        
                        with gr.Tabs():
                            with gr.TabItem("Network Graph"):
                                network_plot = gr.Plot(
                                    label="AD Network Topology",
                                    value=go.Figure().add_annotation(text="Click 'Refresh Data' to load visualization", x=0.5, y=0.5)
                                )
                            
                            with gr.TabItem("Risk Heatmap"):
                                risk_plot = gr.Plot(
                                    label="User Risk Assessment",
                                    value=go.Figure().add_annotation(text="Click 'Refresh Data' to load heatmap", x=0.5, y=0.5)
                                )
                            
                            with gr.TabItem("Time Series"):
                                time_plot = gr.Plot(
                                    label="Authentication Patterns Over Time",
                                    value=go.Figure().add_annotation(text="Click 'Refresh Data' to load time series", x=0.5, y=0.5)
                                )

            # Model Management Tab
            with gr.TabItem("🤖 Model Management", id="model_tab"):
                with gr.Row():
                    with gr.Column():
                        gr.HTML("<h2>Available Models</h2>")
                        
                        available_models = gr.Dropdown(
                            label="Installed Models",
                            choices=[],
                            value=None,
                            info="Select from models already installed on your system"
                        )
                        
                        with gr.Row():
                            refresh_models_btn = gr.Button("🔄 Refresh Models", size="sm")
                            switch_model_btn = gr.Button("🔀 Switch Model", size="sm", variant="secondary")
                    
                    with gr.Column():
                        gr.HTML("<h2>Model Installation</h2>")
                        
                        recommended_models = gr.Dropdown(
                            label="Recommended Models",
                            choices=get_recommended_models(),
                            info="Curated models optimized for security analysis"
                        )
                        
                        custom_model = gr.Textbox(
                            label="Custom Model Name",
                            placeholder="e.g., llama3.1:8b, mistral:7b, qwen2:7b",
                            info="Enter any model name from Ollama registry"
                        )
                        
                        with gr.Row():
                            pull_recommended_btn = gr.Button("📥 Install Recommended", size="sm", variant="primary")
                            pull_custom_btn = gr.Button("📥 Install Custom", size="sm", variant="primary")
                
                model_status = gr.Markdown(
                    label="Model Management Status",
                    value="*Model operations will be reported here...*"
                )

            # Debug & System Tab
            with gr.TabItem("🔧 Debug & System", id="debug_tab"):
                with gr.Row():
                    with gr.Column():
                        gr.HTML("<h2>System Status</h2>")
                        status_output = gr.HTML(label="Current Status")
                        
                        gr.HTML("<h2>Debug Controls</h2>")
                        debug_toggle = gr.Checkbox(
                            label="Enable Debug Mode",
                            value=False,
                            info="Toggle detailed logging for troubleshooting"
                        )
                        
                        with gr.Row():
                            clear_debug_btn = gr.Button("🗑️ Clear Debug Log", size="sm")
                            refresh_debug_btn = gr.Button("🔄 Refresh Debug", size="sm")
                            export_debug_btn = gr.Button("📤 Export Debug Log", size="sm")
                    
                    with gr.Column():
                        gr.HTML("<h2>Debug Output</h2>")
                        debug_output_display = gr.Textbox(
                            label="Debug Log",
                            value="Debug output will appear here when enabled...",
                            lines=20,
                            max_lines=25,
                            interactive=False,
                            show_copy_button=True
                        )

            # Data Explorer Tab
            with gr.TabItem("📈 Data Explorer", id="data_tab"):
                gr.HTML("<h2>Raw Data Analysis</h2>")
                
                with gr.Row():
                    data_query_dropdown = gr.Dropdown(
                        choices=[
                            "Authentication Statistics",
                            "User Activity Summary", 
                            "Computer Access Patterns",
                            "Failed Login Analysis",
                            "Hourly Activity Distribution",
                            "Service Account Analysis"
                        ],
                        label="Select Data Query",
                        value="Authentication Statistics"
                    )
                    
                    run_query_btn = gr.Button("📊 Run Query", variant="primary")
                
                data_output = gr.DataFrame(
                    label="Query Results",
                    interactive=False,
                    wrap=True
                )
                
                data_insights = gr.Markdown(
                    label="Data Insights",
                    value="*Run a query to see data insights and statistics...*"
                )

        # Event Handlers
        
        # Analysis tab handlers
        analyze_btn.click(
            fn=analyze_security_threats,
            inputs=[analysis_dropdown],
            outputs=[analysis_output]
        )
        
        refresh_data_btn.click(
            fn=refresh_dashboard_data,
            outputs=[network_plot, risk_plot, time_plot]
        )
        
        # Model management handlers
        refresh_models_btn.click(
            fn=refresh_available_models,
            outputs=[available_models]
        )
        
        switch_model_btn.click(
            fn=switch_model_handler,
            inputs=[available_models],
            outputs=[model_status, status_output]
        )
        
        pull_recommended_btn.click(
            fn=pull_model_handler,
            inputs=[recommended_models],
            outputs=[model_status, available_models]
        )
        
        pull_custom_btn.click(
            fn=pull_model_handler,
            inputs=[custom_model],
            outputs=[model_status, available_models]
        )
        
        # Debug tab handlers
        debug_toggle.change(
            fn=toggle_debug_mode,
            inputs=[debug_toggle],
            outputs=[status_output, debug_output_display]
        )
        
        clear_debug_btn.click(
            fn=clear_debug_output,
            outputs=[debug_output_display]
        )
        
        # Manual debug refresh function
        async def refresh_debug_output():
            """Manually refresh debug output"""
            return get_debug_output()
        
        refresh_debug_btn.click(
            fn=refresh_debug_output,
            outputs=[debug_output_display]
        )
        
        # Data explorer handlers
        async def run_data_query(query_type: str):
            """Run selected data query and return results"""
            add_debug_output(f"Running data query: {query_type}")
            
            try:
                query_map = {
                    "Authentication Statistics": analyze_authentication_patterns,
                    "User Activity Summary": analyze_user_behavior,
                    "Computer Access Patterns": detect_lateral_movement,
                    "Failed Login Analysis": detect_credential_stuffing,
                    "Hourly Activity Distribution": get_hourly_data,
                    "Service Account Analysis": analyze_account_usage_patterns
                }
                
                if query_type not in query_map:
                    return pd.DataFrame(), "❌ Unknown query type"
                
                result = await query_map[query_type]()
                
                if not result["success"]:
                    return pd.DataFrame(), f"❌ Query failed: {result.get('error', 'Unknown error')}"
                
                # Convert first available data to DataFrame
                data = result["data"]
                if isinstance(data, dict):
                    # Get the first non-empty dataset
                    for key, value in data.items():
                        if value and isinstance(value, list):
                            df = pd.DataFrame(value)
                            insights = f"### {key.replace('_', ' ').title()}\n\n"
                            insights += f"- **Total Records**: {len(df)}\n"
                            insights += f"- **Columns**: {', '.join(df.columns.tolist())}\n"
                            if len(df) > 0:
                                insights += f"- **Sample Data**: {len(df)} rows loaded\n"
                            
                            # Add ML insights if available
                            if "ml_analysis" in result:
                                ml_data = result["ml_analysis"]
                                if hasattr(ml_data, 'outliers') and ml_data.outliers:
                                    insights += f"- **ML Outliers Detected**: {len(ml_data.outliers)}\n"
                                if hasattr(ml_data, 'risk_scores') and ml_data.risk_scores:
                                    avg_risk = sum(ml_data.risk_scores.values()) / len(ml_data.risk_scores)
                                    insights += f"- **Average Risk Score**: {avg_risk:.3f}\n"
                            
                            add_debug_output(f"Data query completed: {len(df)} records returned")
                            return df.head(100), insights  # Limit to first 100 rows for display
                
                return pd.DataFrame(), "No tabular data available for this query"
                
            except Exception as e:
                add_debug_output(f"ERROR in data query: {str(e)}")
                return pd.DataFrame(), f"❌ Error: {str(e)}"
        
        run_query_btn.click(
            fn=run_data_query,
            inputs=[data_query_dropdown],
            outputs=[data_output, data_insights]
        )
        
        # Initialize dashboard on load
        async def init_dashboard():
            """Initialize dashboard with initial data"""
            add_debug_output("Initializing dashboard...")
            
            try:
                status_data, models = await asyncio.gather(
                    get_status_html(),
                    get_available_models()
                )
                
                current_model = get_current_model()
                model_dropdown = gr.Dropdown(
                    choices=models, 
                    value=current_model if current_model in models else (models[0] if models else None)
                )
                
                add_debug_output("Dashboard initialization completed")
                return status_data, model_dropdown, get_debug_output()
                
            except Exception as e:
                add_debug_output(f"ERROR during dashboard initialization: {str(e)}")
                return await get_status_html(), gr.Dropdown(choices=[], value=None), get_debug_output()
        
        demo.load(
            fn=init_dashboard,
            outputs=[status_output, available_models, debug_output_display]
        )
    
    return demo