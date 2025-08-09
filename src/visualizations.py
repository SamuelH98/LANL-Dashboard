"""
visualizations.py
This file contains all the functions for creating visualizations for the dashboard.
"""

import plotly.graph_objects as go
import plotly.express as px
import networkx as nx
import pandas as pd

from agent import (
    get_graph_for_visualization,
    get_hourly_data,
    get_user_behavior_data,
    add_debug_output,
)


async def create_network_visualization():
    """Create network visualization, fixed to handle the agent's flat data structure."""
    add_debug_output("Creating network visualization...")
    try:
        graph_data = await get_graph_for_visualization()
        if not graph_data["success"] or not graph_data["data"]:
            return go.Figure().add_annotation(
                text="No valid graph connections found",
                x=0.5,
                y=0.5,
                showarrow=False,
            )

        G = nx.Graph()
        for record in graph_data["data"]:
            user_name = record.get("user_name")
            computer_name = record.get("computer_name")
            if user_name and computer_name:  # Ensure both nodes exist
                G.add_node(user_name, type="User")
                G.add_node(computer_name, type="Computer")
                G.add_edge(
                    user_name,
                    computer_name,
                    weight=record.get("connection_events", 1),
                )

        if not G.nodes():
            return go.Figure().add_annotation(
                text="No nodes to display", x=0.5, y=0.5, showarrow=False
            )

        pos = nx.spring_layout(G, k=0.8, iterations=50)

        edge_x, edge_y = [], []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        edge_trace = go.Scatter(
            x=edge_x,
            y=edge_y,
            line=dict(width=0.5, color="#888"),
            hoverinfo="none",
            mode="lines",
        )

        node_x, node_y, node_text, node_color, node_size = [], [], [], [], []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_type = G.nodes[node].get("type", "Unknown")
            connections = G.degree(node)
            color = (
                "red"
                if connections > 10
                else (
                    "orange"
                    if connections > 5
                    else ("lightblue" if node_type == "User" else "lightgreen")
                )
            )
            node_color.append(color)
            node_size.append(10 + connections * 1.5)
            node_text.append(
                f"{node}<br>Type: {node_type}<br>Connections: {connections}"
            )

        node_trace = go.Scatter(
            x=node_x,
            y=node_y,
            mode="markers",
            hoverinfo="text",
            text=node_text,
            marker=dict(color=node_color, size=node_size, line_width=2),
        )

        fig = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                title="AD Network Topology",
                showlegend=False,
                margin=dict(b=20, l=5, r=5, t=40),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            ),
        )
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
            return go.Figure().add_annotation(
                text="No behavior data available", x=0.5, y=0.5, showarrow=False
            )

        users = [u for u in behavior_data["data"] if u.get("username")][:25]  # Top 25
        if not users:
            return go.Figure().add_annotation(
                text="No valid users for heatmap", x=0.5, y=0.5, showarrow=False
            )

        df = pd.DataFrame(users)
        df["failure_rate"] = df.apply(
            lambda row: (row.get("fails", 0) / row["total"])
            if row.get("total", 0) > 0
            else 0,
            axis=1,
        )
        df = df.sort_values("failure_rate", ascending=False)

        fig = px.imshow(
            [df["failure_rate"].values],
            x=df["username"].values,
            labels=dict(x="User", y="", color="Failure Rate"),
            color_continuous_scale="Reds",
        )
        fig.update_layout(title="User Risk Heatmap (by Failure Rate)", yaxis_visible=False)
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
            return go.Figure().add_annotation(
                text="No hourly data available", x=0.5, y=0.5, showarrow=False
            )

        df = pd.DataFrame(hourly_data["data"]["hourly_data"]).sort_values("hour")
        if df.empty:
            return go.Figure().add_annotation(
                text="No time series data points", x=0.5, y=0.5, showarrow=False
            )

        fig = px.line(
            df,
            x="hour",
            y="event_count",
            title="Hourly Authentication Patterns",
            markers=True,
            labels={"hour": "Hour of Day", "event_count": "Number of Events"},
        )
        add_debug_output("Time series plot created.")
        return fig
    except Exception as e:
        add_debug_output(f"ERROR creating time series plot: {str(e)}")
        return go.Figure().add_annotation(text=f"Error: {str(e)}", x=0.5, y=0.5)