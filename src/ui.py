"""
ui.py
This file has been rewritten to correctly handle the data formats provided by the schema-aligned agent.py.
This fixes all broken visualizations.
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
    run_quick_scan,
    format_analysis_result,
    OllamaModelManager,
)

# Import visualization functions
from visualizations import (
    create_network_visualization,
    create_risk_heatmap,
    create_time_series_plot,
)

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
    global debug_output
    debug_output = []
    return "Debug output cleared."


async def get_status_html() -> str:
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
    return f"""<div style="padding: 10px; background: #222; border-radius: 5px;">{'<br>'.join(statuses)}</div>"""


async def toggle_debug_mode(enabled: bool):
    set_debug_mode(enabled)
    add_debug_output(f"Debug mode {'ENABLED' if enabled else 'DISABLED'}")
    return await get_status_html(), get_debug_output()


# Model management functions
async def refresh_available_models():
    """Refresh the list of available models"""
    add_debug_output("Refreshing available models...")
    models = await OllamaModelManager().get_available_models()
    add_debug_output(f"Found {len(models)} available models: {models}")
    current = get_current_model()
    return gr.Dropdown(
        choices=models, value=current if current in models else (models[0] if models else None)
    )


async def pull_model_handler(model_name: str):
    """Handle model pulling with progress feedback"""
    if not model_name.strip():
        add_debug_output("ERROR: No model name provided for pulling")
        return "❌ Please enter a model name", gr.Dropdown()

    try:
        add_debug_output(f"Starting model pull for: {model_name.strip()}")
        result = await OllamaModelManager().pull_model(model_name.strip())

        if result["success"]:
            models = await OllamaModelManager().get_available_models()
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


# --- UI Layout and Event Handlers (Largely Unchanged) ---
async def analyze_security_threats(scan_type: str, progress=gr.Progress(track_tqdm=True)):
    progress(0, desc="Starting Scan...")
    add_debug_output(f"Starting {scan_type} Scan...")
    try:
        progress(0.2, desc="Querying database and analyzing...")
        result_str = await (
            run_full_scan() if scan_type == "Full Scan" else run_quick_scan()
        )
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
            create_network_visualization(),
            create_risk_heatmap(),
            create_time_series_plot(),
        )
        add_debug_output("Dashboard data refreshed successfully.")
        return net_viz, risk_map, time_plot
    except Exception as e:
        add_debug_output(f"ERROR refreshing dashboard: {str(e)}")
        fig_err = go.Figure().add_annotation(text=f"Error: {str(e)}", x=0.5, y=0.5)
        return fig_err, fig_err, fig_err


def create_gradio_interface():
    with gr.Blocks(
        title="AD Red Team Analysis Dashboard",
        theme=gr.themes.Default(primary_hue="orange"),
    ) as demo:
        gr.HTML(
            """<div style='text-align: center; margin: 20px;'><h1 style='font-size: 2.5rem;'>🔒 AD Red Team Analysis Dashboard</h1></div>"""
        )

        with gr.Tabs():
            with gr.TabItem("🔍 Security Analysis"):
                with gr.Row():
                    with gr.Column(scale=2):
                        gr.Markdown("## Analysis Control")
                        scan_dropdown = gr.Dropdown(
                            choices=["Quick Scan", "Full Scan"],
                            label="Select Scan Type",
                            value="Quick Scan",
                        )
                        with gr.Row():
                            analyze_btn = gr.Button("🚀 Run Scan", variant="primary")
                            refresh_data_btn = gr.Button("🔄 Refresh Data")
                        analysis_output = gr.Markdown(
                            value="*Analysis results will appear here...*"
                        )

                    with gr.Column(scale=3):
                        gr.Markdown("## Real-time Visualizations")
                        with gr.Tabs():
                            with gr.TabItem("Network Graph"):
                                network_plot = gr.Plot()
                            with gr.TabItem("Risk Heatmap"):
                                risk_plot = gr.Plot()
                            with gr.TabItem("Time Series"):
                                time_plot = gr.Plot()
            # Model Management Tab
            with gr.TabItem("🤖 Model Management", id="model_tab"):
                with gr.Row():
                    with gr.Column():
                        gr.HTML("<h2>Available Models</h2>")

                        available_models = gr.Dropdown(
                            label="Installed Models",
                            choices=[],
                            value=None,
                            info="Select from models already installed",
                        )

                        with gr.Row():
                            refresh_models_btn = gr.Button("🔄 Refresh Models", size="sm")
                            switch_model_btn = gr.Button(
                                "🔀 Switch Model", size="sm", variant="secondary"
                            )

                    with gr.Column():
                        gr.HTML("<h2>Model Installation</h2>")

                        recommended_models = gr.Dropdown(
                            label="Recommended Models",
                            choices=OllamaModelManager().get_recommended_models(),
                            info="Optimized models for security analysis",
                        )

                        custom_model = gr.Textbox(
                            label="Custom Model Name",
                            placeholder="e.g., llama3.1:8b, mistral:7b",
                            info="Enter any model name from Ollama registry",
                        )

                        with gr.Row():
                            pull_recommended_btn = gr.Button(
                                "📥 Install Recommended", size="sm", variant="primary"
                            )
                            pull_custom_btn = gr.Button(
                                "📥 Install Custom", size="sm", variant="primary"
                            )

                model_status = gr.Markdown(
                    label="Model Management Status",
                    value="*Model operations will be reported here...*",
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
                        debug_output_display = gr.Textbox(
                            label="Debug Log", lines=15, interactive=False
                        )

        # Event Handlers
        analyze_btn.click(
            fn=analyze_security_threats,
            inputs=[scan_dropdown],
            outputs=[analysis_output],
        )
        refresh_data_btn.click(
            fn=refresh_dashboard_data,
            outputs=[network_plot, risk_plot, time_plot],
        )
        debug_toggle.change(
            fn=toggle_debug_mode,
            inputs=[debug_toggle],
            outputs=[status_output, debug_output_display],
        )
        clear_debug_btn.click(fn=clear_debug_output, outputs=[debug_output_display])

        refresh_models_btn.click(
            fn=refresh_available_models, outputs=[available_models]
        )

        switch_model_btn.click(
            fn=switch_model_handler,
            inputs=[available_models],
            outputs=[model_status, status_output],
        )

        pull_recommended_btn.click(
            fn=pull_model_handler,
            inputs=[recommended_models],
            outputs=[model_status, available_models],
        )

        pull_custom_btn.click(
            fn=pull_model_handler,
            inputs=[custom_model],
            outputs=[model_status, available_models],
        )

        async def init_dashboard():
            add_debug_output("Initializing dashboard...")
            status, debug_log_out = await asyncio.gather(
                get_status_html(), asyncio.to_thread(get_debug_output)
            )
            add_debug_output("Dashboard loaded.")
            return status, get_debug_output()

        demo.load(fn=init_dashboard, outputs=[status_output, debug_output_display])
    return demo