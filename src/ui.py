"""
Gradio UI components for the Active Directory Red Team Analysis Dashboard
"""

import asyncio
import plotly.graph_objects as go
import gradio as gr
import networkx as nx

from agent import (
    check_neo4j_status, check_llm_status, check_ollama_status, ad_agent,
    analyze_authentication_patterns, analyze_user_behavior,
    detect_lateral_movement, get_hourly_data, run_analysis,
    get_available_models, pull_model, get_recommended_models,
    set_current_model, get_current_model, get_graph_for_visualization
)

# Status functions
async def get_status_html() -> str:
    """Generate HTML status display"""
    neo4j_ok, llm_ok, ollama_ok = await asyncio.gather(
        asyncio.to_thread(check_neo4j_status), 
        check_llm_status(),
        check_ollama_status()
    )
    
    neo4j_status = "🟢 Neo4j Connected" if neo4j_ok else "🔴 Neo4j Disconnected"
    llm_status = f"🟢 {ad_agent.get_current_model()} Ready" if llm_ok else f"🔴 {ad_agent.get_current_model()} Not Ready"
    ollama_status = "🟢 Ollama Service Running" if ollama_ok else "🔴 Ollama Service Down"
    
    return f"""
    <div style="padding: 10px; background: #1F2937; border: 1px solid #374151; border-radius: 8px; color: #D1D5DB;">
        <h4>System Status</h4>
        <p style="margin: 5px 0;">{neo4j_status}</p>
        <p style="margin: 5px 0;">{ollama_status}</p>
        <p style="margin: 5px 0;">{llm_status}</p>
        <p style="margin: 5px 0;">📊 Dashboard Active</p>
    </div>
    """

# Model management functions
async def refresh_available_models():
    """Refresh the list of available models"""
    models = await get_available_models()
    return gr.Dropdown(choices=models, value=get_current_model() if get_current_model() in models else (models if models else None))

async def pull_model_handler(model_name: str):
    """Handle model pulling with progress feedback"""
    if not model_name.strip():
        return "❌ Please enter a model name", gr.Dropdown()
    
    result = await pull_model(model_name.strip())
    
    if result["success"]:
        # Refresh available models after successful pull
        models = await get_available_models()
        dropdown_update = gr.Dropdown(choices=models, value=model_name.strip())
        return f"✅ {result['message']}", dropdown_update
    else:
        return f"❌ {result['message']}", gr.Dropdown()

def switch_model_handler(model_name: str):
    """Handle model switching"""
    if not model_name:
        return "❌ Please select a model", get_status_html()
    
    try:
        set_current_model(model_name)
        return f"✅ Switched to model: {model_name}", get_status_html()
    except Exception as e:
        return f"❌ Error switching model: {str(e)}", get_status_html()

# Visualization functions
async def create_network_visualization():
    """Create a Plotly network graph from Neo4j data."""
    graph_data = await get_graph_for_visualization()
    if not graph_data["success"] or not graph_data["data"]:
        return go.Figure()

    G = nx.Graph()
    for record in graph_data["data"]:
        user = record['u']
        computer = record['c']
        auth_event = record['ae']
        
        G.add_node(user.id, label=user['name'], type='User')
        G.add_node(computer.id, label=computer['name'], type='Computer')
        G.add_edge(user.id, auth_event.id)
        G.add_edge(auth_event.id, computer.id)

    pos = nx.spring_layout(G)
    
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge]
        x1, y1 = pos[edge]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines')

    node_x = []
    node_y = []
    node_text = []
    node_color = []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(G.nodes[node]['label'])
        node_color.append('skyblue' if G.nodes[node]['type'] == 'User' else 'lightgreen')

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers',
        hoverinfo='text',
        text=node_text,
        marker=dict(
            showscale=False,
            color=node_color,
            size=10,
            line_width=2))

    fig = go.Figure(data=[edge_trace, node_trace],
             layout=go.Layout(
                title='<br>Active Directory Object Interactions',
                titlefont_size=16,
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20,l=5,r=5,t=40),
                annotations=[ dict(
                    text="Users and Computers activity",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.005, y=-0.002 ) ],
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False))
                )
    return fig


# Dashboard update functions
async def update_status_only():
    """Update only the system status"""
    return await get_status_html()

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
    progress(0.5, desc=f"Querying database and running analysis with {get_current_model()}...")
    result = await func(func, query, *data_funcs)
    progress(1, desc="Analysis Complete!")
    return result

def create_gradio_interface():
    """Create and configure the Gradio interface"""
    with gr.Blocks(title="AD Red Team Analysis Dashboard", theme=gr.themes.Default()) as demo:
        gr.HTML("""
        <div style="text-align: center; max-width: 1200px; margin: 20px auto;">
            <h1 style="font-size: 2.5rem;">🔒 Active Directory Red Team Analysis Dashboard</h1>
            <p style="color: #9CA3AF; font-size: 1.1rem;">Real-time security threat detection with AI-powered analysis and graph visualization</p>
        </div>
        """)

        with gr.Row():
            with gr.Column(scale=2):
                gr.HTML("<h2 style='text-align: left;'>🌐 AD Graph Visualization</h2>")
                
                vis_plot = gr.Plot(label="Network Graph")
                
                refresh_vis_btn = gr.Button("🔄 Refresh Visualization", variant="secondary")

            with gr.Column(scale=3):
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
                
                # Model Management Section
                gr.HTML("<h2 style='text-align: left;'>🤖 Model Management</h2>")
                
                with gr.Row():
                    with gr.Column():
                        available_models = gr.Dropdown(
                            label="Available Models",
                            choices=[],
                            value=None,
                            info="Select from installed models"
                        )
                        
                        with gr.Row():
                            refresh_models_btn = gr.Button("🔄 Refresh Models", size="sm")
                            switch_model_btn = gr.Button("🔀 Switch Model", size="sm", variant="secondary")
                
                with gr.Row():
                    with gr.Column():
                        recommended_models = gr.Dropdown(
                            label="Recommended Models",
                            choices=get_recommended_models(),
                            value="gemma2:2b",
                            info="Popular models for security analysis"
                        )
                        
                        custom_model = gr.Textbox(
                            label="Custom Model",
                            placeholder="e.g., llama3.1:8b, mistral:7b",
                            info="Enter any Ollama model name"
                        )
                        
                        with gr.Row():
                            pull_recommended_btn = gr.Button("📥 Pull Recommended", size="sm", variant="primary")
                            pull_custom_btn = gr.Button("📥 Pull Custom", size="sm", variant="primary")
                
                model_status = gr.Markdown(
                    label="Model Status",
                    value="*Model management status will appear here...*"
                )
                
                status_output = gr.HTML(label="System Status")

        # Event handlers for analysis
        analyze_btn.click(
            fn=analyze_security_threats,
            inputs=[analysis_dropdown],
            outputs=[analysis_output]
        )
        
        refresh_vis_btn.click(
            fn=create_network_visualization,
            outputs=[vis_plot]
        )
        
        # Event handlers for model management
        refresh_models_btn.click(
            fn=refresh_available_models,
            outputs=[available_models]
        )
        
        switch_model_btn.click(
            fn=lambda model: asyncio.run(asyncio.gather(
                asyncio.to_thread(switch_model_handler, model),
                get_status_html()
            )),
            inputs=[available_models],
            outputs=[model_status, status_output]
        )
        
        pull_recommended_btn.click(
            fn=lambda model: asyncio.run(pull_model_handler(model)),
            inputs=[recommended_models],
            outputs=[model_status, available_models]
        )
        
        pull_custom_btn.click(
            fn=lambda model: asyncio.run(pull_model_handler(model)),
            inputs=[custom_model],
            outputs=[model_status, available_models]
        )
        
        # Initialize dashboard and models on load
        async def init_dashboard():
            status_data, initial_plot, models = await asyncio.gather(
                get_status_html(),
                create_network_visualization(),
                get_available_models()
            )
            
            current_model = get_current_model()
            model_dropdown = gr.Dropdown(
                choices=models, 
                value=current_model if current_model in models else (models if models else None)
            )
            return status_data, initial_plot, model_dropdown
        
        demo.load(
            fn=init_dashboard,
            outputs=[status_output, vis_plot, available_models]
        )
    
    return demo