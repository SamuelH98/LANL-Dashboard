"""
ui.py
This file has been rewritten to correctly handle the data formats provided by the schema-aligned agent.py.
This fixes all broken visualizations.
"""

import asyncio
import plotly.graph_objects as go
import plotly.express as px
import gradio as gr
import networkx as nx
import pandas as pd
from datetime import datetime

# Import agent functions
from agent import *

# --- Debug and Status Helpers (Unchanged) ---
debug_output = []

def add_debug_output(message: str):
    global debug_output
    timestamp = datetime.now().strftime("%H:%M:%S")
    debug_output.append(f"[{timestamp}] {message}")
    debug_output = debug_output[-50:]

def get_debug_output() -> str:
    return "\n".join(debug_output) if debug_output else "Debug output will appear here..."

def clear_debug_output():
    global debug_output; debug_output = []; return "Debug output cleared."

async def get_status_html() -> str:
    neo4j_ok, llm_ok, ollama_ok = await asyncio.gather(
        asyncio.to_thread(check_neo4j_status), check_llm_status(), ad_agent.model_manager.check_ollama_status()
    )
    statuses = [
        f"🟢 Neo4j Connected" if neo4j_ok else "🔴 Neo4j Disconnected",
        f"🟢 Ollama Service Running" if ollama_ok else "🔴 Ollama Service Down",
        f"🟢 {ad_agent.get_current_model()} Ready" if llm_ok else f"🔴 {ad_agent.get_current_model()} Not Ready",
        f"🔧 Debug Mode: {'ON' if get_debug_mode() else 'OFF'}"
    ]
    return f"""<div style="padding: 10px; background: #222; border-radius: 5px;">{'<br>'.join(statuses)}</div>"""

async def toggle_debug_mode(enabled: bool):
    set_debug_mode(enabled)
    add_debug_output(f"Debug mode {'ENABLED' if enabled else 'DISABLED'}")
    return await get_status_html(), get_debug_output()

# Model management functions
async def refresh_available_models():
    """Refresh the list of available models"""
    add_debug_output("Refreshing available models...")
    models = await get_available_models()
    add_debug_output(f"Found {len(models)} available models: {models}")
    current = get_current_model()
    return gr.Dropdown(choices=models, value=current if current in models else (models[0] if models else None))

async def pull_model_handler(model_name: str):
    """Handle model pulling with progress feedback"""
    if not model_name.strip():
        add_debug_output("ERROR: No model name provided for pulling")
        return "❌ Please enter a model name", gr.Dropdown()
    
    try:
        add_debug_output(f"Starting model pull for: {model_name.strip()}")
        result = await pull_model(model_name.strip())
        
        if result["success"]:
            models = await get_available_models()
            dropdown_update = gr.Dropdown(choices=models, value=model_name.strip())
            add_debug_output(f"SUCCESS: Model {model_name.strip()} pulled successfully")
            return f"✅ {result['message']}", dropdown_update
        else:
            add_debug_output(f"ERROR: Model pull failed - {result['message']}")
            return f"❌ {result['message']}", gr.Dropdown()
            
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


# --- Visualization Functions (Rewritten and Fixed) ---
async def create_network_visualization():
    """Create network visualization, fixed to handle the agent's flat data structure."""
    add_debug_output("Creating network visualization...")
    try:
        graph_data = await get_graph_for_visualization()
        if not graph_data["success"] or not graph_data["data"]:
            return go.Figure().add_annotation(text="No valid graph connections found", x=0.5, y=0.5, showarrow=False)

        G = nx.Graph()
        for record in graph_data["data"]:
            user_name = record.get('user_name')
            computer_name = record.get('computer_name')
            if user_name and computer_name: # Ensure both nodes exist
                G.add_node(user_name, type='User')
                G.add_node(computer_name, type='Computer')
                G.add_edge(user_name, computer_name, weight=record.get('connection_events', 1))

        if not G.nodes():
            return go.Figure().add_annotation(text="No nodes to display", x=0.5, y=0.5, showarrow=False)

        pos = nx.spring_layout(G, k=0.8, iterations=50)
        
        edge_x, edge_y = [], []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]; x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None]); edge_y.extend([y0, y1, None])
        edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=0.5, color='#888'), hoverinfo='none', mode='lines')

        node_x, node_y, node_text, node_color, node_size = [], [], [], [], []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x); node_y.append(y)
            node_type = G.nodes[node].get('type', 'Unknown')
            connections = G.degree(node)
            color = 'red' if connections > 10 else ('orange' if connections > 5 else ('lightblue' if node_type == 'User' else 'lightgreen'))
            node_color.append(color)
            node_size.append(10 + connections * 1.5)
            node_text.append(f"{node}<br>Type: {node_type}<br>Connections: {connections}")

        node_trace = go.Scatter(x=node_x, y=node_y, mode='markers', hoverinfo='text', text=node_text,
                                marker=dict(color=node_color, size=node_size, line_width=2))
        
        fig = go.Figure(data=[edge_trace, node_trace],
                        layout=go.Layout(title='AD Network Topology', showlegend=False,
                                         margin=dict(b=20,l=5,r=5,t=40),
                                         xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                                         yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)))
        add_debug_output("Network visualization created successfully.")
        return fig
    except Exception as e:
        add_debug_output(f"ERROR creating network visualization: {str(e)}")
        return go.Figure().add_annotation(text=f"Error: {str(e)}", x=0.5, y=0.5)

async def create_risk_heatmap():
    """Create risk heatmap, fixed to use the correct data keys from the agent."""
    add_debug_output("Creating risk heatmap...")
    try:
        behavior_data = await get_user_behavior_data()
        if not behavior_data["success"] or not behavior_data["data"]:
            return go.Figure().add_annotation(text="No behavior data available", x=0.5, y=0.5, showarrow=False)
        
        users = [u for u in behavior_data["data"] if u.get("username")][:25] # Top 25
        if not users:
            return go.Figure().add_annotation(text="No valid users for heatmap", x=0.5, y=0.5, showarrow=False)
            
        df = pd.DataFrame(users)
        df['failure_rate'] = df.apply(lambda row: (row.get('fails', 0) / row['total']) if row.get('total', 0) > 0 else 0, axis=1)
        df = df.sort_values('failure_rate', ascending=False)

        fig = px.imshow([df['failure_rate'].values],
                        x=df['username'].values,
                        labels=dict(x="User", y="", color="Failure Rate"),
                        color_continuous_scale='Reds')
        fig.update_layout(title='User Risk Heatmap (by Failure Rate)', yaxis_visible=False)
        add_debug_output(f"Risk heatmap created for {len(df)} users.")
        return fig
    except Exception as e:
        add_debug_output(f"ERROR creating risk heatmap: {str(e)}")
        return go.Figure().add_annotation(text=f"Error: {str(e)}", x=0.5, y=0.5)

async def create_time_series_plot():
    """Create time series plot, fixed to use the correct data keys from the agent."""
    add_debug_output("Creating time series plot...")
    try:
        hourly_data = await get_hourly_data()
        if not hourly_data["success"] or not hourly_data["data"].get("hourly_data"):
            return go.Figure().add_annotation(text="No hourly data available", x=0.5, y=0.5, showarrow=False)

        df = pd.DataFrame(hourly_data["data"]["hourly_data"]).sort_values("hour")
        if df.empty:
            return go.Figure().add_annotation(text="No time series data points", x=0.5, y=0.5, showarrow=False)

        fig = px.line(df, x="hour", y="event_count", title="Hourly Authentication Patterns", markers=True,
                      labels={"hour": "Hour of Day", "event_count": "Number of Events"})
        add_debug_output("Time series plot created.")
        return fig
    except Exception as e:
        add_debug_output(f"ERROR creating time series plot: {str(e)}")
        return go.Figure().add_annotation(text=f"Error: {str(e)}", x=0.5, y=0.5)

# --- UI Layout and Event Handlers (Largely Unchanged) ---
async def analyze_security_threats(scan_type: str, progress=gr.Progress(track_tqdm=True)):
    progress(0, desc="Starting Scan...")
    add_debug_output(f"Starting {scan_type} Scan...")
    try:
        progress(0.2, desc="Querying database and analyzing...")
        result_str = await (run_full_scan() if scan_type == "Full Scan" else run_quick_scan())
        progress(1, desc="Done!")
        add_debug_output("Analysis completed.")
        return result_str
    except Exception as e:
        add_debug_output(f"CRITICAL ERROR in analysis: {str(e)}")
        return f"❌ Analysis failed catastrophically: {str(e)}"

async def refresh_dashboard_data():
    add_debug_output("Refreshing all dashboard visualizations...")
    try:
        net_viz, risk_map, time_plot = await asyncio.gather(
            create_network_visualization(), create_risk_heatmap(), create_time_series_plot()
        )
        add_debug_output("Dashboard data refreshed successfully.")
        return net_viz, risk_map, time_plot
    except Exception as e:
        add_debug_output(f"ERROR refreshing dashboard: {str(e)}")
        fig_err = go.Figure().add_annotation(text=f"Error: {str(e)}", x=0.5, y=0.5)
        return fig_err, fig_err, fig_err

def create_gradio_interface():
    with gr.Blocks(title="AD Red Team Analysis Dashboard", theme=gr.themes.Default(primary_hue="orange")) as demo:
        gr.HTML("""<div style='text-align: center; margin: 20px;'><h1 style='font-size: 2.5rem;'>🔒 AD Red Team Analysis Dashboard</h1></div>""")

        with gr.Tabs():
            with gr.TabItem("🔍 Security Analysis"):
                with gr.Row():
                    with gr.Column(scale=2):
                        gr.Markdown("## Analysis Control")
                        scan_dropdown = gr.Dropdown(choices=["Quick Scan", "Full Scan"], label="Select Scan Type", value="Quick Scan")
                        with gr.Row():
                            analyze_btn = gr.Button("🚀 Run Scan", variant="primary")
                            refresh_data_btn = gr.Button("🔄 Refresh Data")
                        analysis_output = gr.Markdown(value="*Analysis results will appear here...*")

                    with gr.Column(scale=3):
                        gr.Markdown("## Real-time Visualizations")
                        with gr.Tabs():
                            with gr.TabItem("Network Graph"): network_plot = gr.Plot()
                            with gr.TabItem("Risk Heatmap"): risk_plot = gr.Plot()
                            with gr.TabItem("Time Series"): time_plot = gr.Plot()
            # Model Management Tab
            with gr.TabItem("🤖 Model Management", id="model_tab"):
                with gr.Row():
                    with gr.Column():
                        gr.HTML("<h2>Available Models</h2>")
                        
                        available_models = gr.Dropdown(
                            label="Installed Models",
                            choices=[],
                            value=None,
                            info="Select from models already installed"
                        )
                        
                        with gr.Row():
                            refresh_models_btn = gr.Button("🔄 Refresh Models", size="sm")
                            switch_model_btn = gr.Button("🔀 Switch Model", size="sm", variant="secondary")
                    
                    with gr.Column():
                        gr.HTML("<h2>Model Installation</h2>")
                        
                        recommended_models = gr.Dropdown(
                            label="Recommended Models",
                            choices=get_recommended_models(),
                            info="Optimized models for security analysis"
                        )
                        
                        custom_model = gr.Textbox(
                            label="Custom Model Name",
                            placeholder="e.g., llama3.1:8b, mistral:7b",
                            info="Enter any model name from Ollama registry"
                        )
                        
                        with gr.Row():
                            pull_recommended_btn = gr.Button("📥 Install Recommended", size="sm", variant="primary")
                            pull_custom_btn = gr.Button("📥 Install Custom", size="sm", variant="primary")
                
                model_status = gr.Markdown(
                    label="Model Management Status",
                    value="*Model operations will be reported here...*"
                )

            with gr.TabItem("🔧 Debug & System"):
                with gr.Row():
                    with gr.Column():
                        gr.Markdown("## System Status")
                        status_output = gr.HTML()
                        debug_toggle = gr.Checkbox(label="Enable Debug Mode", value=False)
                        clear_debug_btn = gr.Button("🗑️ Clear Debug Log")
                    with gr.Column(scale=2):
                        gr.Markdown("## Debug Output")
                        debug_output_display = gr.Textbox(label="Debug Log", lines=15, interactive=False)
        
        # Event Handlers
        analyze_btn.click(fn=analyze_security_threats, inputs=[scan_dropdown], outputs=[analysis_output])
        refresh_data_btn.click(fn=refresh_dashboard_data, outputs=[network_plot, risk_plot, time_plot])
        debug_toggle.change(fn=toggle_debug_mode, inputs=[debug_toggle], outputs=[status_output, debug_output_display])
        clear_debug_btn.click(fn=clear_debug_output, outputs=[debug_output_display])

     
    
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
        
        
        async def init_dashboard():
            add_debug_output("Initializing dashboard...")
            status, debug_log_out = await asyncio.gather(get_status_html(), asyncio.to_thread(get_debug_output))
            add_debug_output("Dashboard loaded.")
            return status, get_debug_output()
        
        demo.load(fn=init_dashboard, outputs=[status_output, debug_output_display])
    return demo