import asyncio
import gradio as gr
from datetime import datetime
import plotly.graph_objects as go
import os

# Import agent functions
from agent import (
    AnalysisAgent,
    check_llm_status,
    get_debug_mode,
    set_debug_mode,
    get_current_model,
    set_current_model,
    format_analysis_result,
    format_graph_analysis,
    format_research_conclusions,
)

from visualizations import (
    create_network_visualization,
    create_risk_heatmap,
    create_time_series_plot,    
    get_user_behavior_data,
    get_hourly_data
)


# --- Global state ---
debug_output = []
# Persist last analysis reports so the Analysis Reports panels can show stored results
last_security_output = None
last_graph_output = None
last_research_output = None

def add_debug_output(message: str):
    """Adds a timestamped message to the debug log."""
    global debug_output
    timestamp = datetime.now().strftime("%H:%M:%S")
    debug_output.append(f"[{timestamp}] {message}")
    debug_output = debug_output[-100:]

def get_debug_output() -> str:
    """Returns the current debug log as a string."""
    return "\n".join(debug_output) if debug_output else "Debug output will appear here..."

def clear_debug_output():
    """Clears the debug log."""
    global debug_output
    debug_output = []
    return "Debug output cleared."

async def get_system_metrics():
    """Get system metrics for dashboard cards."""
    try:
        db_stats = await asyncio.to_thread(analysis_agent.db.get_database_stats)
        if db_stats.get("success") and db_stats.get("auth_stats") and db_stats.get("node_counts"):
            stats = db_stats["auth_stats"]
            return {
                "total_events": stats.get('total_events', 0),
                "redteam_events": stats.get('redteam_events', 0),
                "active_users": len([n for n in db_stats.get('node_counts', []) if n.get('label') == 'User']),
                "risk_score": 7.2 # Placeholder from original design
            }
        else:
            # Fallback to zeros if missing data
            return {"total_events": 0, "redteam_events": 0, "active_users": 0, "risk_score": 0.0}
    except Exception as e:
        add_debug_output(f"Error getting system metrics: {e}")
        return {"total_events": 0, "redteam_events": 0, "active_users": 0, "risk_score": 0.0}

async def get_status_indicators():
    """Get system status for header indicators."""
    try:
        neo4j_ok, ollama_ok, llm_ok = await asyncio.gather(
            asyncio.to_thread(analysis_agent.db.is_connected),
            analysis_agent.model_manager.check_ollama_status(),
            check_llm_status(analysis_agent),
        )
        return {"neo4j": neo4j_ok, "ollama": ollama_ok, "llm": llm_ok}
    except Exception as e:
        add_debug_output(f"Status check error: {str(e)}")
        return {"neo4j": False, "ollama": False, "llm": False}

# --- Data Import & Model Management ---
async def handle_clear_database():
    add_debug_output("Clearing database...")
    try:
        result = await asyncio.to_thread(analysis_agent.db.clear_existing_data)
        if result.get("success"):
            return "✅ Database cleared successfully."
        else:
            return f"❌ Failed to clear database: {result.get('error', 'Unknown error')}"
    except Exception as e:
        return f"❌ Error clearing database: {str(e)}"

async def handle_file_upload(file):
    if file is None: return "❌ Please upload a CSV file"
    add_debug_output(f"File uploaded: {os.path.basename(file.name)}")
    validation = await asyncio.to_thread(analysis_agent.db.validate_csv_file, file.name)
    if validation["valid"]: return f"✅ File validation passed - {validation['total_rows']:,} rows ready for import"
    else: return f"❌ Validation failed: {validation['error']}"

async def handle_import_data(file, clear_existing):
    if file is None: return "❌ Please upload a CSV file first"
    add_debug_output(f"Starting data import, clear_existing={clear_existing}")
    try:
        result = await asyncio.to_thread(analysis_agent.db.import_csv_data, file.name, clear_existing)
        if result["success"]: return f"✅ Import successful! {result['stats']['total_events']:,} events loaded"
        else: return f"❌ Import failed: {result['error']}"
    except Exception as e: return f"❌ Import error: {str(e)}"

async def refresh_available_models():
    add_debug_output("Refreshing available models...")
    models = await analysis_agent.model_manager.get_available_models()
    current = analysis_agent.get_current_model()
    return gr.update(choices=models, value=current if current in models else (models[0] if models else None))

async def pull_model_handler(model_name: str):
    """Handles the model pull operation with feedback."""
    if not model_name or not model_name.strip():
        add_debug_output("ERROR: No model name provided for pulling.")
        return "❌ Please enter a model name", gr.update()

    model_name = model_name.strip()
    add_debug_output(f"Starting model pull for: {model_name}")
    result = await analysis_agent.model_manager.pull_model(model_name)

    if result["success"]:
        add_debug_output(f"SUCCESS: Model {model_name} pulled.")
        updated_choices = await analysis_agent.model_manager.get_available_models()
        # FIX: Changed gr.Dropdown.update to gr.Dropdown
        return f"✅ {result['message']}", gr.Dropdown(choices=updated_choices, value=model_name)
    else:
        add_debug_output(f"ERROR: Model pull failed - {result['message']}")
        # FIX: Changed gr.Dropdown.update to gr.update (as no change is needed)
        return f"❌ {result['message']}", gr.update()

async def switch_model_handler(model_name: str):
    if not model_name: return "❌ Please select a model"
    add_debug_output(f"Switching to model: {model_name}")
    analysis_agent.set_model(model_name)
    return f"✅ Switched to model: {model_name}"

# --- Analysis & Plotting ---
def apply_dark_theme(fig):
    if isinstance(fig, go.Figure):
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#a1a1aa"), # zinc-400
            margin=dict(l=40, r=40, t=40, b=40)
        )
    return fig

def create_error_fig(error_message):
    fig = go.Figure().add_annotation(text=error_message, x=0.5, y=0.5, showarrow=False, font=dict(color="#ef4444", size=14)) # red-500
    return apply_dark_theme(fig)

async def run_comprehensive_analysis(progress=gr.Progress(track_tqdm=True)):
    """
    Runs the full suite of analyses: security scan, graph insights, research conclusions,
    and refreshes all visualizations. This is the single main function for the UI.
    """
    progress(0, desc="Starting Comprehensive Analysis...")
    add_debug_output("Starting comprehensive analysis...")

    try:
        # Run security and graph analysis concurrently to get raw dicts
        progress(0.1, desc="Querying DB & running AI analyses...")
        security_task = analysis_agent.analyze_with_graph("full")
        graph_task = analysis_agent.analyze_graphs()
        security_res, graph_res = await asyncio.gather(security_task, graph_task, return_exceptions=True)

        # Handle exceptions from the agent calls
        def format_error(item, item_name):
            if isinstance(item, Exception):
                add_debug_output(f"ERROR in {item_name}: {item}")
                return {"summary": f"{item_name} failed: {str(item)}", "risk_level": "UNKNOWN"}
            return item

        security_dict = format_error(security_res, "Security Analysis")
        graph_dict = format_error(graph_res, "Graph Analysis")

        # Format outputs for UI display
        security_output = format_analysis_result(security_dict)
        graph_output = format_graph_analysis(graph_dict)

        # Generate research conclusions using the already-obtained dicts (avoid duplicate LLM calls)
        try:
            research_dict = await analysis_agent.generate_research_conclusions(security_dict, graph_dict)
            research_output = format_research_conclusions(research_dict)
        except Exception as e:
            add_debug_output(f"Research generation failed: {e}")
            research_output = f"❌ Research generation failed: {e}"

        progress(0.9, desc="Finalizing reports and visualizations...")

        # Persist the latest analysis results so other UI flows (init, navigation) can display them
        try:
            global last_security_output, last_graph_output, last_research_output
            last_security_output = security_output
            last_graph_output = graph_output
            last_research_output = research_output
        except Exception:
            add_debug_output("Failed to persist analysis outputs")

        add_debug_output("Comprehensive analysis processing complete.")
        progress(1, desc="Analysis Complete!")

        return security_output, graph_output, research_output

    except Exception as e:
        error_msg = f"❌ A critical error occurred in the handler: {str(e)}"
        add_debug_output(f"CRITICAL ERROR in run_comprehensive_analysis: {str(e)}")
        return error_msg, error_msg, error_msg

def create_gradio_interface(agent: AnalysisAgent):
    global analysis_agent
    analysis_agent = agent

    # Custom CSS to inject Launch UI's dark theme aesthetic
    custom_css = """
    body { background-color: #09090b; }
    .gradio-container {
        max-width: none !important;
        background-color: #09090b;
        color: #a1a1aa;
    }

    :root {
        --ring-color: rgba(59, 130, 246, 0.5); /* Default ring color */
    }

    button {
        /* Layout and Sizing */
        display: inline-flex;
        align-items: center;
        justify-content: center;
        height: 2.5rem; /* h-10 */
        padding-left: 1.25rem; /* px-5 */
        padding-right: 1.25rem; /* px-5 */
        
        /* Typography */
        white-space: nowrap;
        font-size: 0.875rem; /* text-sm */
        font-weight: 500; /* font-medium */
        
        /* Appearance */
        border-radius: 0.375rem; /* rounded-md */
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1); /* shadow-md */

        /* Transitions */
        transition: background-color 0.2s ease-in-out, color 0.2s ease-in-out, border-color 0.2s ease-in-out, box-shadow 0.2s ease-in-out; /* transition-colors and others */

        /* Custom Glass Effect (glass-4) */
        background-color: rgba(255, 255, 255, 0.04); /* Example: slight white tint */
        border: 1px solid rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(4px);
        -webkit-backdrop-filter: blur(4px); /* For Safari */

        /* States */
        cursor: pointer;
    }

    button:hover {
        /* Custom Hover Glass Effect (hover:glass-5) */
        background-color: rgba(255, 255, 255, 0.05); /* Example: slightly more opaque */
        backdrop-filter: blur(5px);
        -webkit-backdrop-filter: blur(5px);
    }

    button:focus-visible {
        outline: none; /* focus-visible:outline-hidden */
        box-shadow: 0 0 0 1px var(--ring-color); /* focus-visible:ring-1 focus-visible:ring-ring */
    }

    button:disabled {
        pointer-events: none; /* disabled:pointer-events-none */
        opacity: 0.5; /* disabled:opacity-50 */
    }
    
    """

    with gr.Blocks(
        title="LANL Security Dashboard",
        theme=gr.themes.Base(),
        head='<script src="https://cdn.tailwindcss.com"></script>',
        css=custom_css
    ) as demo:

        with gr.Column(elem_classes="w-full min-h-screen bg-zinc-950 text-zinc-400 font-sans"):
            # --- Header / Navbar ---
            with gr.Row(elem_classes="px-4 py-3 border-b border-zinc-800 flex items-center justify-between"):
                with gr.Column(scale=1):
                    gr.HTML("""
                    <div class="flex items-center gap-2">
                        <h1 class="text-xl font-bold text-white">LANL Dashboard</h1>
                    </div>""")
                with gr.Column(scale=3):
                    with gr.Row(elem_classes="flex justify-center items-center gap-4"):
                        dashboard_btn = gr.Button("Dashboard", elem_id="nav-dashboard", elem_classes="text-white font-semibold transition-colors duration-200")
                        analysis_btn = gr.Button("Analysis", elem_id="nav-analysis", elem_classes="text-zinc-400 hover:text-white transition-colors duration-200")
                        data_btn = gr.Button("Data", elem_id="nav-data", elem_classes="text-zinc-400 hover:text-white transition-colors duration-200")
                        settings_btn = gr.Button("Settings", elem_id="nav-settings", elem_classes="text-zinc-400 hover:text-white transition-colors duration-200")
                with gr.Column(scale=1):
                     status_html = gr.HTML("""
                     <div class="flex items-center justify-end gap-3 text-sm">
                        <div class="flex items-center gap-2" title="Checking..."><div class="w-2 h-2 rounded-full bg-yellow-500 animate-pulse"></div>DB</div>
                        <div class="flex items-center gap-2" title="Checking..."><div class="w-2 h-2 rounded-full bg-yellow-500 animate-pulse"></div>LLM</div>
                        <div class="flex items-center gap-2" title="Checking..."><div class="w-2 h-2 rounded-full bg-yellow-500 animate-pulse"></div>Ollama</div>
                     </div>""")

            # --- Main Content Area ---
            with gr.Column(elem_classes="p-6 md:p-8"):
                # --- Dashboard Page ---
                with gr.Column(visible=True) as dashboard_page:
                    gr.HTML('<h1 class="text-3xl font-semibold text-white">Dashboard</h1><p class="text-zinc-400 mb-6">Security Analysis Overview</p>')
                    stats_cards_html = gr.HTML("""
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                        <div class="bg-zinc-900 border border-zinc-800 rounded-xl p-6"><p class="text-sm font-medium text-zinc-400">Total Events</p><p class="text-4xl font-bold text-white mt-2">0</p><p class="text-xs text-zinc-500 mt-2">+0.0% from last month</p></div>
                        <div class="bg-zinc-900 border border-zinc-800 rounded-xl p-6"><p class="text-sm font-medium text-zinc-400">Red Team Events</p><p class="text-4xl font-bold text-white mt-2">0</p><p class="text-xs text-zinc-500 mt-2">+0.0% from last month</p></div>
                        <!-- <div class="bg-zinc-900 border border-zinc-800 rounded-xl p-6"><p class="text-sm font-medium text-zinc-400">Active Users</p><p class="text-4xl font-bold text-white mt-2">0</p><p class="text-xs text-zinc-500 mt-2">+0.0% from last month</p></div>
                        <div class="bg-zinc-900 border border-zinc-800 rounded-xl p-6"><p class="text-sm font-medium text-zinc-400">Risk Score</p><p class="text-4xl font-bold text-white mt-2">0.0</p><p class="text-xs text-zinc-500 mt-2">Analysis pending</p></div> -->
                    </div>""")

                    with gr.Row(elem_classes="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-6"):
                        with gr.Column(scale=2, elem_classes="lg:col-span-2 bg-zinc-900 border border-zinc-800 rounded-xl p-4"):
                            gr.HTML('<h2 class="text-lg font-semibold text-white px-4 pt-2 mb-2">Event Timeline</h2>')
                            timeline_plot = gr.Plot()
                        with gr.Column(scale=1, elem_classes="bg-zinc-900 border border-zinc-800 rounded-xl p-4"):
                            gr.HTML('<h2 class="text-lg font-semibold text-white px-4 pt-2 mb-2">Risk Distribution</h2>')
                            risk_plot = gr.Plot()
                    with gr.Row(elem_classes="mt-6"):
                        with gr.Column(elem_classes="bg-zinc-900 border border-zinc-800 rounded-xl p-4"):
                            gr.HTML('<h2 class="text-lg font-semibold text-white px-4 pt-2 mb-2">Network Topology</h2>')
                            network_plot = gr.Plot()

                # --- Other Pages (Analysis, Data, Settings) ---
                with gr.Column(visible=False) as analysis_page:
                    gr.HTML('<h1 class="text-3xl font-semibold text-white">Analysis Reports</h1><p class="text-zinc-400 mb-6">AI-Powered Security Insights</p>')
                    run_analysis_btn = gr.Button("🚀 Run Comprehensive Analysis", elem_classes="px-6 py-3 bg-white text-zinc-900 font-semibold rounded-lg shadow-md hover:-translate-y-0.5 transition-transform")
                    with gr.Column(elem_classes="bg-zinc-900 border border-zinc-800 rounded-xl p-6 mt-6"):
                        gr.HTML('<h2 class="text-lg font-semibold text-white mb-4">Security Analysis</h2>')
                        security_output = gr.Markdown("*Click 'Run Analysis' to generate insights...*")
                    with gr.Column(elem_classes="bg-zinc-900 border border-zinc-800 rounded-xl p-6 mt-6"):
                        gr.HTML('<h2 class="text-lg font-semibold text-white mb-4">AI Graph Insights</h2>')
                        graph_output = gr.Markdown("*Click 'Run Analysis' to generate insights...*")
                    with gr.Column(elem_classes="bg-zinc-900 border border-zinc-800 rounded-xl p-6 mt-6"):
                        gr.HTML('<h2 class="text-lg font-semibold text-white mb-4">Research Conclusions</h2>')
                        research_output = gr.Markdown("*Click 'Run Analysis' to generate insights...*")

                with gr.Column(visible=False) as data_page:
                    gr.HTML('<h1 class="text-3xl font-semibold text-white">Data Management</h1><p class="text-zinc-400 mb-6">Import and manage security event data</p>')
                    with gr.Row(elem_classes="grid grid-cols-1 md:grid-cols-2 gap-8"):
                        with gr.Column(elem_classes="bg-zinc-900 border border-zinc-800 rounded-xl p-6"):
                            gr.HTML('<h2 class="text-lg font-semibold text-white mb-4">Import Data</h2>')
                            csv_file = gr.File(label="Select CSV File", file_types=[".csv"], type="filepath")
                            clear_existing = gr.Checkbox(label="Clear existing data before import", value=False)
                            with gr.Row():
                                import_btn = gr.Button("Import Data", elem_classes="bg-white text-zinc-900 font-semibold rounded-lg px-4 py-2 hover:bg-zinc-200 transition-colors")
                                clear_btn = gr.Button("Clear Database", elem_classes="bg-red-600 text-white font-semibold rounded-lg px-4 py-2 hover:bg-red-700 transition-colors")
                            import_status = gr.Markdown("*Select a CSV file to begin...*")
                        
                with gr.Column(visible=False) as settings_page:
                    gr.HTML('<h1 class="text-3xl font-semibold text-white">Settings</h1><p class="text-zinc-400 mb-6">System configuration and model management</p>')
                    
                    with gr.Row(elem_classes="grid grid-cols-1 md:grid-cols-2 gap-8"):
                        # AI Model Management Section
                        with gr.Column(elem_classes="bg-zinc-900 border border-zinc-800 rounded-xl p-6"):
                            gr.HTML('<h2 class="text-lg font-semibold text-white mb-4">AI Model Management</h2>')
                            
                            with gr.Tabs():
                                with gr.TabItem("Switch Active Model"):
                                    model_dropdown = gr.Dropdown(
                                        label="Active Model", 
                                        info="Select the AI model for analysis", 
                                        allow_custom_value=True
                                    )
                                    available_models_dd = gr.Dropdown(
                                        label="Installed Models", 
                                        info="Select an installed model to use for analysis"
                                    )
                                    with gr.Row():
                                        refresh_models_btn = gr.Button("🔄 Refresh List")
                                        switch_model_btn = gr.Button(
                                            "🚀 Switch to Selected Model", 
                                            elem_classes="bg-white text-zinc-900 font-semibold rounded-lg px-4 py-2 hover:bg-zinc-200 transition-colors"
                                        )
                                    model_status = gr.Markdown("*Model status will appear here...*")
                                
                                with gr.TabItem("Install New Model"):
                                    recommended_models_dd = gr.Dropdown(
                                        label="Recommended Models",
                                        choices=agent.model_manager.get_recommended_models(),
                                        info="Optimized models for security analysis",
                                    )
                                    pull_recommended_btn = gr.Button("📥 Install Recommended", variant="primary")
                                    
                                    custom_model_tb = gr.Textbox(
                                        label="Or, Install a Custom Model",
                                        placeholder="e.g., llama3.1:8b, mistral:7b",
                                        info="Enter any model name from Ollama registry",
                                    )
                                    pull_custom_btn = gr.Button("📥 Install Custom", variant="primary")
                        
                        with gr.Column(elem_classes="bg-zinc-900 border border-zinc-800 rounded-xl p-6"):
                            gr.HTML('<h2 class="text-lg font-semibold text-white mb-4">Debug Console</h2>')
                            debug_toggle = gr.Checkbox(label="Enable Debug Mode", value=get_debug_mode())
                            clear_debug_btn = gr.Button("Clear Log")
                            debug_console = gr.Textbox(label="Debug Output", lines=10, interactive=False, value=get_debug_output)

        # --- Event Handlers ---
        nav_buttons = [dashboard_btn, analysis_btn, data_btn, settings_btn]
        pages = [dashboard_page, analysis_page, data_page, settings_page]

        def create_nav_click_fn(selected_index):
            def navigation_handler():
                page_visibility = [gr.update(visible=(i == selected_index)) for i in range(len(pages))]
                button_styles = [
                    gr.update(elem_classes="text-white font-semibold transition-colors duration-200" if i == selected_index else "text-zinc-400 hover:text-white transition-colors duration-200")
                    for i in range(len(nav_buttons))
                ]
                return tuple(page_visibility + button_styles)
            return navigation_handler

        for i, btn in enumerate(nav_buttons):
            btn.click(fn=create_nav_click_fn(i), inputs=None, outputs=pages + nav_buttons)

        run_analysis_btn.click(fn=run_comprehensive_analysis, outputs=[security_output, graph_output, research_output])
        csv_file.upload(fn=handle_file_upload, inputs=[csv_file], outputs=[import_status])
        import_btn.click(fn=handle_import_data, inputs=[csv_file, clear_existing], outputs=[import_status])
        clear_btn.click(fn=handle_clear_database, outputs=[import_status])
        refresh_models_btn.click(fn=refresh_available_models, outputs=[model_dropdown])
        switch_model_btn.click(fn=switch_model_handler, inputs=[model_dropdown], outputs=[model_status])
        pull_recommended_btn.click(fn=pull_model_handler, inputs=[recommended_models_dd], outputs=[model_status, available_models_dd])
        pull_custom_btn.click(fn=pull_model_handler, inputs=[custom_model_tb], outputs=[model_status, available_models_dd])
        clear_debug_btn.click(fn=clear_debug_output, outputs=[debug_console])

        # --- Dashboard Initialization & Updates ---
        async def update_status_display():
            statuses = await get_status_indicators()
            def get_light_class(status): return "bg-green-500" if status else "bg-red-500"
            return f"""<div class="flex items-center justify-end gap-3 text-sm">
                <div class="flex items-center gap-2" title="{'Connected' if statuses['neo4j'] else 'Disconnected'}"><div class="w-2 h-2 rounded-full {get_light_class(statuses['neo4j'])}"></div>DB</div>
                <div class="flex items-center gap-2" title="{'Online' if statuses['ollama'] else 'Offline'}"><div class="w-2 h-2 rounded-full {get_light_class(statuses['ollama'])}"></div>Ollama</div>
                <div class="flex items-center gap-2" title="{'Online' if statuses['llm'] else 'Offline'}"><div class="w-2 h-2 rounded-full {get_light_class(statuses['llm'])}"></div>LLM</div>
            </div>"""

        async def update_metric_cards():
            metrics = await get_system_metrics()
            # Values from the screenshot for styling
            trends = {"total_events": "+placeholder%", "redteam_events": "+placeholder%", "active_users": "+placeholder%", "risk_score": "+placeholder since last hour"}
            card_template = '<div class="bg-zinc-900 border border-zinc-800 rounded-xl p-6"><p class="text-sm font-medium text-zinc-400">{label}</p><p class="text-4xl font-bold text-white mt-2">{value}</p><p class="text-xs text-zinc-500 mt-2">{trend} from last month</p></div>'
            return f"""<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {card_template.format(label="Total Events", value=f"+{metrics['total_events']:,}", trend=trends['total_events'])}
                {card_template.format(label="Red Team Events", value=f"+{metrics['redteam_events']:,}", trend=trends['redteam_events'])}
                <!-- {card_template.format(label="Active Users", value=f"+{metrics['active_users']}", trend=trends['active_users'])}
                {card_template.format(label="Risk Score", value=f"{metrics['risk_score']:.1f}", trend=trends['risk_score'])} -->
            </div>"""

        async def init_dashboard():
            add_debug_output("Initializing dashboard...")
            # Only pass coroutines to asyncio.gather
            results = await asyncio.gather(
                refresh_available_models(),
                update_status_display(),
                update_metric_cards(),
                return_exceptions=True
            )
            models, status, cards = results

            
            net_viz = await create_network_visualization(analysis_agent)
            risk_viz = await create_risk_heatmap(analysis_agent)
            time_viz = await create_time_series_plot(analysis_agent)

            def handle_result(res, is_plot=False):
                if isinstance(res, Exception):
                    add_debug_output(f"Init Error: {res}")
                    return create_error_fig("Initialization Failed") if is_plot else "Error"
                return apply_dark_theme(res) if is_plot else res

            # Prepare persisted analysis report values (show last results if available)
            try:
                sec_report = last_security_output if last_security_output is not None else "*Click 'Run Analysis' to generate insights...*"
                graph_report = last_graph_output if last_graph_output is not None else "*Click 'Run Analysis' to generate insights...*"
                research_report = last_research_output if last_research_output is not None else "*Click 'Run Analysis' to generate insights...*"
            except Exception:
                sec_report = graph_report = research_report = "*Click 'Run Analysis' to generate insights...*"

            return (
                handle_result(net_viz, is_plot=True),
                handle_result(risk_viz, is_plot=True),
                handle_result(time_viz, is_plot=True),
                handle_result(models),
                get_debug_output(),
                handle_result(status),
                handle_result(cards),
                sec_report,
                graph_report,
                research_report,
            )

        demo.load(
            fn=init_dashboard,
            outputs=[
                network_plot, risk_plot, timeline_plot,
                model_dropdown, debug_console, status_html, stats_cards_html,
                security_output, graph_output, research_output,
            ]
        )
    return demo

