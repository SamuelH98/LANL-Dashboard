"""
ui.py - Streamlined single-page UI for comprehensive AD security analysis.
"""

import asyncio
import gradio as gr
from datetime import datetime
import plotly.graph_objects as go

# Import agent functions
from agent import (
    ad_agent,
    check_neo4j_status,
    check_llm_status,
    get_debug_mode,
    set_debug_mode,
    get_current_model,
    set_current_model,
    run_full_scan,
    OllamaModelManager,
    analyze_graphs_with_agent,
    generate_research_conclusions_with_agent,
)

# Import visualization functions
from visualizations import (
    create_network_visualization,
    create_risk_heatmap,
    create_time_series_plot,
)

# --- Debug and Status Helpers ---
debug_output = []

def add_debug_output(message: str):
    """Adds a timestamped message to the debug log."""
    global debug_output
    timestamp = datetime.now().strftime("%H:%M:%S")
    debug_output.append(f"[{timestamp}] {message}")
    # Keep the log from growing indefinitely
    debug_output = debug_output[-100:]


def get_debug_output() -> str:
    """Returns the current debug log as a string."""
    return "\n".join(debug_output) if debug_output else "Debug output will appear here..."


def clear_debug_output():
    """Clears the debug log."""
    global debug_output
    debug_output = []
    return "Debug output cleared."


async def get_status_html() -> str:
    """Generates an HTML string with the current system status."""
    neo4j_ok, llm_ok, ollama_ok = await asyncio.gather(
        asyncio.to_thread(check_neo4j_status),
        check_llm_status(),
        ad_agent.model_manager.check_ollama_status(),
    )
    statuses = [
        f"🟢 Neo4j Connected" if neo4j_ok else "🔴 Neo4j Disconnected",
        f"🟢 Ollama Service Running" if ollama_ok else "🔴 Ollama Service Down",
        f"🟢 {ad_agent.get_current_model()} Ready"
        if llm_ok
        else f"🔴 {ad_agent.get_current_model()} Not Ready",
        f"🔧 Debug Mode: {'ON' if get_debug_mode() else 'OFF'}",
    ]
    return f"""<div style="padding: 10px; background: #222; border-radius: 5px; color: white;">{'<br>'.join(statuses)}</div>"""


async def toggle_debug_mode(enabled: bool):
    """Toggles the debug mode on or off."""
    set_debug_mode(enabled)
    add_debug_output(f"Debug mode {'ENABLED' if enabled else 'DISABLED'}")
    return await get_status_html(), get_debug_output()


# --- Model Management Handlers ---
async def refresh_available_models():
    """Refreshes the dropdown list of available Ollama models."""
    add_debug_output("Refreshing available models...")
    models = await OllamaModelManager().get_available_models()
    add_debug_output(f"Found {len(models)} available models.")
    current = get_current_model()
    return gr.Dropdown(
        choices=models, value=current if current in models else (models[0] if models else None)
    )


async def pull_model_handler(model_name: str):
    """Handles the model pull operation with feedback."""
    if not model_name or not model_name.strip():
        add_debug_output("ERROR: No model name provided for pulling.")
        return "❌ Please enter a model name", gr.update()

    model_name = model_name.strip()
    add_debug_output(f"Starting model pull for: {model_name}")
    result = await OllamaModelManager().pull_model(model_name)

    if result["success"]:
        add_debug_output(f"SUCCESS: Model {model_name} pulled.")
        updated_choices = await OllamaModelManager().get_available_models()
        # FIX: Changed gr.Dropdown.update to gr.Dropdown
        return f"✅ {result['message']}", gr.Dropdown(choices=updated_choices, value=model_name)
    else:
        add_debug_output(f"ERROR: Model pull failed - {result['message']}")
        # FIX: Changed gr.Dropdown.update to gr.update (as no change is needed)
        return f"❌ {result['message']}", gr.update()


async def switch_model_handler(model_name: str):
    """Handles switching the active AI model."""
    if not model_name:
        return "❌ Please select a model", await get_status_html()
    add_debug_output(f"Switching to model: {model_name}")
    set_current_model(model_name)
    status_html = await get_status_html()
    add_debug_output(f"SUCCESS: Switched to model {model_name}")
    return f"✅ Switched to model: {model_name}", status_html


# --- Core Analysis and UI Functions ---

def apply_dark_theme(fig):
    """Applies a dark theme to a Plotly figure."""
    if isinstance(fig, go.Figure):
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#FFFFFF")
        )
    return fig

async def run_comprehensive_analysis(progress=gr.Progress(track_tqdm=True)):
    """
    Runs the full suite of analyses: security scan, graph insights, research conclusions,
    and refreshes all visualizations. This is the single main function for the UI.
    """
    progress(0, desc="Starting Comprehensive Analysis...")
    add_debug_output("Starting comprehensive analysis...")

    try:
        # Run all tasks concurrently for efficiency
        progress(0.1, desc="Querying DB & running AI analyses...")
        tasks = [
            run_full_scan(),
            analyze_graphs_with_agent(),
            generate_research_conclusions_with_agent(),
            create_network_visualization(),
            create_risk_heatmap(),
            create_time_series_plot(),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        progress(0.9, desc="Finalizing reports and visualizations...")

        # Unpack results safely, checking for exceptions
        (security_res, graph_res, research_res, net_viz_res, risk_map_res, time_plot_res) = results

        # Helper to format error messages for display
        def format_error(item, item_name):
            if isinstance(item, Exception):
                add_debug_output(f"ERROR in {item_name}: {item}")
                return f"❌ {item_name} failed: {str(item)}"
            return item
        
        # Helper to create a dark-themed error figure for plots
        def error_fig_dark(e):
            fig = go.Figure().add_annotation(text=f"Error loading plot:\n{e}", x=0.5, y=0.5, showarrow=False)
            return apply_dark_theme(fig)

        security_output = format_error(security_res, "Security Analysis")
        graph_output = format_error(graph_res, "Graph Analysis")
        research_output = format_error(research_res, "Research Conclusions")
        
        net_viz = apply_dark_theme(net_viz_res) if not isinstance(net_viz_res, Exception) else error_fig_dark(net_viz_res)
        risk_map = apply_dark_theme(risk_map_res) if not isinstance(risk_map_res, Exception) else error_fig_dark(risk_map_res)
        time_plot = apply_dark_theme(time_plot_res) if not isinstance(time_plot_res, Exception) else error_fig_dark(time_plot_res)

        add_debug_output("Comprehensive analysis processing complete.")
        progress(1, desc="Analysis Complete!")
        
        return security_output, graph_output, research_output, net_viz, risk_map, time_plot

    except Exception as e:
        error_msg = f"❌ A critical error occurred in the handler: {str(e)}"
        add_debug_output(f"CRITICAL ERROR in run_comprehensive_analysis: {str(e)}")
        error_fig_instance = go.Figure().add_annotation(text=f"Critical Error: {e}", x=0.5, y=0.5, showarrow=False)
        dark_error_fig = apply_dark_theme(error_fig_instance)
        return error_msg, error_msg, error_msg, dark_error_fig, dark_error_fig, dark_error_fig


def create_gradio_interface():
    """Creates the entire Gradio UI application in a single-page layout."""
    with gr.Blocks(
        title="Los Alamos Security Breach Dashboard",
        theme=gr.themes.Default(primary_hue="orange", secondary_hue="blue").set(
            body_background_fill="#121212",
            body_text_color="#FFFFFF",
            block_background_fill="#1E1E1E",
            block_border_width="1px",
            block_title_text_color="#FFFFFF",
            border_color_primary="#333333",
            button_primary_background_fill="orange",
            button_primary_text_color="#000000",
        ),
    ) as demo:
        # --- Header ---
        gr.HTML(
            """<div style='text-align: center; margin: 20px;'>
            <h1 style='font-size: 2.5rem; color: #FFFFFF;'>🔒 Los Alamos Security Breach Dashboard</h1>
            <p style='font-size: 1.2rem; color: #BBBBBB;'>A Unified Dashboard for AI-Powered Breach Analysis</p>
            </div>"""
        )

        # --- Visualizations Section ---
        gr.Markdown("--- \n ## 📊 Live Data Visualizations")
        with gr.Row():
            network_plot = gr.Plot(label="Network Topology")
            risk_plot = gr.Plot(label="User Risk Heatmap")
            time_plot = gr.Plot(label="Hourly Event Timeline")
        
        # --- Analysis Reports Section ---
        gr.Markdown("--- \n ## 📝 AI-Powered Analysis Reports")
        
        # --- Main Control Button ---
        with gr.Row():
            run_all_btn = gr.Button(
                "🚀 Run Comprehensive Analysis", variant="primary", size="lg"
            )

        with gr.Accordion("🔒 Security Analysis Report", open=True):
            security_report_output = gr.Markdown("*Run analysis to generate the security report...*")
        
        with gr.Accordion("🤖 AI Graph Insights", open=True):
            graph_analysis_output = gr.Markdown("*Run analysis to generate AI insights on the graphs...*")
        
        with gr.Accordion("🎓 Research Paper Conclusions", open=True):
            research_conclusions_output = gr.Markdown("*Run analysis to generate research-ready conclusions...*")
        
        # --- Advanced Settings and System Info ---
        with gr.Accordion("⚙️ Advanced Settings & System Status", open=False):
            with gr.Row():
                with gr.Column(scale=1):
                    gr.Markdown("## System Status")
                    status_output = gr.HTML()
                with gr.Column(scale=2):
                    gr.Markdown("## Model Management")
                    with gr.Tabs():
                        with gr.TabItem("Switch Active Model"):
                            available_models_dd = gr.Dropdown(label="Installed Models", info="Select an installed model to use for analysis")
                            with gr.Row():
                                refresh_models_btn = gr.Button("🔄 Refresh List")
                                switch_model_btn = gr.Button("🚀 Switch to Selected Model")
                        
                        with gr.TabItem("Install New Model"):
                            recommended_models_dd = gr.Dropdown(
                                label="Recommended Models",
                                choices=OllamaModelManager().get_recommended_models(),
                                info="Optimized models for security analysis",
                            )
                            pull_recommended_btn = gr.Button("📥 Install Recommended", variant="primary")
                            
                            custom_model_tb = gr.Textbox(
                                label="Or, Install a Custom Model",
                                placeholder="e.g., llama3.1:8b, mistral:7b",
                                info="Enter any model name from Ollama registry",
                            )
                            pull_custom_btn = gr.Button("📥 Install Custom", variant="primary")
                    
                    model_status_md = gr.Markdown("*Model operations will be reported here...*")

            with gr.Row():
                 with gr.Column():
                    gr.Markdown("## Debug Information")
                    debug_toggle = gr.Checkbox(label="Enable Debug Mode", value=get_debug_mode())
                    clear_debug_btn = gr.Button("🗑️ Clear Debug Log")
                    debug_output_display = gr.Textbox(label="Debug Log", lines=15, interactive=False)

        # --- Event Handlers ---

        # Main button click
        run_all_btn.click(
            fn=run_comprehensive_analysis,
            inputs=None,
            outputs=[
                security_report_output,
                graph_analysis_output,
                research_conclusions_output,
                network_plot,
                risk_plot,
                time_plot,
            ],
            api_name="run_analysis"
        )
        
        # Model Management handlers
        refresh_models_btn.click(fn=refresh_available_models, outputs=[available_models_dd])
        switch_model_btn.click(fn=switch_model_handler, inputs=[available_models_dd], outputs=[model_status_md, status_output])
        pull_recommended_btn.click(fn=pull_model_handler, inputs=[recommended_models_dd], outputs=[model_status_md, available_models_dd])
        pull_custom_btn.click(fn=pull_model_handler, inputs=[custom_model_tb], outputs=[model_status_md, available_models_dd])

        # Debug handlers
        debug_toggle.change(fn=toggle_debug_mode, inputs=[debug_toggle], outputs=[status_output, debug_output_display])
        clear_debug_btn.click(fn=clear_debug_output, outputs=[debug_output_display])

        # Initial dashboard load
        async def init_dashboard():
            """Initializes the dashboard state on load."""
            add_debug_output("Initializing streamlined dashboard...")
            # Concurrently fetch initial data
            status, debug_log, models, net_viz, risk_map, time_p = await asyncio.gather(
                get_status_html(),
                asyncio.to_thread(get_debug_output),
                refresh_available_models(),
                create_network_visualization(),
                create_risk_heatmap(),
                create_time_series_plot()
            )
            add_debug_output("Dashboard loaded. Ready for analysis.")
            # Apply dark theme to initial plots
            return (
                status, 
                debug_log, 
                models, 
                apply_dark_theme(net_viz), 
                apply_dark_theme(risk_map), 
                apply_dark_theme(time_p)
            )

        demo.load(
            fn=init_dashboard,
            outputs=[
                status_output,
                debug_output_display,
                available_models_dd,
                network_plot,
                risk_plot,
                time_plot
            ]
        )

    return demo