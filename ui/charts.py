"""
Cybersecurity UI Charts & Visualizations
Dark SOC-themed Plotly configurations: gauges, donut charts, and risk timeline.
"""
import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, Any, List

def create_cyber_gauge(value: float, title: str = "EXPOSURE & THREAT INDEX") -> go.Figure:
    """Builds a high-contrast tactical gauge with glowing threshold markers."""
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': title.upper(), 'font': {'color': '#94a3b8', 'size': 13, 'family': 'sans-serif'}},
        number={'font': {'color': '#00f2fe', 'size': 36, 'family': 'Courier New, monospace'}},
        gauge={
            'axis': {'range': [0, 100], 'tickcolor': '#334155', 'tickwidth': 1},
            'bar': {'color': "#00f2fe", 'thickness': 0.28},
            'bgcolor': "#0b132b",
            'borderwidth': 1,
            'bordercolor': "#1e3a5f",
            'steps': [
                {'range': [0, 35], 'color': "rgba(16, 185, 129, 0.2)"},
                {'range': [35, 70], 'color': "rgba(245, 158, 11, 0.2)"},
                {'range': [70, 100], 'color': "rgba(239, 68, 68, 0.3)"},
            ],
            'threshold': {
                'line': {'color': "#ef4444", 'width': 3},
                'thickness': 0.8,
                'value': 70
            }
        }
    ))
    fig.update_layout(
        paper_bgcolor="rgba(9, 18, 34, 0.85)",
        plot_bgcolor="rgba(9, 18, 34, 0.85)",
        height=230,
        margin=dict(l=20, r=20, t=35, b=15)
    )
    return fig


def create_category_donut(category_counts: Dict[str, int]) -> go.Figure:
    """Creates a dark donut chart of detected sensitive data categories."""
    labels = list(category_counts.keys())
    values = list(category_counts.values())

    colors = ["#00f2fe", "#38bdf8", "#818cf8", "#f59e0b", "#ef4444", "#10b981", "#ec4899"]

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=.55,
        marker=dict(colors=colors, line=dict(color="#070d18", width=2)),
        textinfo='label+percent',
        insidetextorientation='radial'
    )])

    fig.update_layout(
        paper_bgcolor="rgba(13, 27, 42, 0.6)",
        plot_bgcolor="rgba(13, 27, 42, 0.6)",
        font=dict(color="#cbd5e1", size=12),
        showlegend=False,
        height=260,
        margin=dict(l=10, r=10, t=20, b=10)
    )
    return fig
