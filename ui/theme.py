"""
UI Design System & Global Theme Engine
Strictly air-gapped: uses local CSS and system/safe web fonts without external runtime CDNs.
"""

def get_theme_css() -> str:
    return """
<style>
    /* Design Tokens */
    :root {
        --dpg-bg-primary: #070d18;
        --dpg-bg-secondary: #0d1b2a;
        --dpg-bg-card: rgba(13, 27, 42, 0.75);
        --dpg-border: #1e3a5f;
        --dpg-border-focus: #00f2fe;
        --dpg-cyan: #00f2fe;
        --dpg-blue: #38bdf8;
        --dpg-emerald: #10b981;
        --dpg-amber: #f59e0b;
        --dpg-crimson: #ef4444;
        --dpg-text-primary: #f8fafc;
        --dpg-text-secondary: #94a3b8;
        --dpg-text-muted: #64748b;
        --dpg-font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        --dpg-font-mono: "Consolas", "SFMono-Regular", "Menlo", "Courier New", monospace;
    }

    /* Base Body & App Container */
    .stApp {
        background-color: var(--dpg-bg-primary) !important;
        color: var(--dpg-text-primary) !important;
        font-family: var(--dpg-font-sans) !important;
    }

    /* Custom Modern Scrollbars */
    ::-webkit-scrollbar {
        width: 6px;
        height: 6px;
    }
    ::-webkit-scrollbar-track {
        background: var(--dpg-bg-primary);
    }
    ::-webkit-scrollbar-thumb {
        background: #1e293b;
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: var(--dpg-cyan);
    }

    /* Glassmorphism Metric Cards */
    div[data-testid="stMetric"] {
        background: var(--dpg-bg-card) !important;
        backdrop-filter: blur(8px) !important;
        border: 1px solid var(--dpg-border) !important;
        border-radius: 8px !important;
        padding: 14px 18px !important;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3) !important;
        transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease !important;
    }
    div[data-testid="stMetric"]:hover {
        border-color: var(--dpg-cyan) !important;
        box-shadow: 0 0 16px rgba(0, 242, 254, 0.2) !important;
        transform: translateY(-2px) !important;
    }
    div[data-testid="stMetricValue"] {
        color: var(--dpg-cyan) !important;
        font-family: var(--dpg-font-mono) !important;
        font-weight: 700 !important;
    }

    /* Tactical Top SOC Header Banner */
    .soc-header {
        background: linear-gradient(135deg, #091222 0%, #0d1b2a 50%, #102a43 100%);
        border: 1px solid var(--dpg-border);
        border-radius: 10px;
        padding: 20px 24px;
        margin-bottom: 24px;
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4);
        position: relative;
        overflow: hidden;
    }
    .soc-header::before {
        content: "";
        position: absolute;
        top: 0; left: 0; right: 0; height: 3px;
        background: linear-gradient(90deg, #00f2fe 0%, #38bdf8 50%, #00f2fe 100%);
        box-shadow: 0 0 12px #00f2fe;
    }
    .soc-title {
        color: #ffffff;
        font-size: 24px;
        font-weight: 800;
        letter-spacing: -0.3px;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .soc-badge {
        display: inline-block;
        background: rgba(0, 242, 254, 0.1);
        color: var(--dpg-cyan);
        border: 1px solid rgba(0, 242, 254, 0.3);
        font-family: var(--dpg-font-mono);
        font-size: 11px;
        font-weight: 600;
        padding: 2px 10px;
        border-radius: 12px;
        letter-spacing: 0.8px;
        text-transform: uppercase;
        margin-top: 6px;
    }
    .soc-status {
        color: var(--dpg-text-secondary);
        font-size: 13px;
        margin-top: 6px;
    }

    /* Styled Buttons */
    button[kind="primary"], .stButton > button {
        background: linear-gradient(135deg, #0d2137 0%, #102a43 100%) !important;
        color: #ffffff !important;
        border: 1px solid var(--dpg-border) !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
        font-family: var(--dpg-font-sans) !important;
        transition: all 0.2s ease !important;
    }
    button[kind="primary"]:hover, .stButton > button:hover {
        border-color: var(--dpg-cyan) !important;
        box-shadow: 0 0 14px rgba(0, 242, 254, 0.3) !important;
        color: var(--dpg-cyan) !important;
    }

    /* Styled Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid #1e293b;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: transparent !important;
        border-radius: 6px 6px 0 0;
        color: var(--dpg-text-secondary) !important;
        font-weight: 600 !important;
        padding: 8px 16px !important;
    }
    .stTabs [aria-selected="true"] {
        color: var(--dpg-cyan) !important;
        border-bottom: 2px solid var(--dpg-cyan) !important;
    }

    /* Dataframe Container */
    div[data-testid="stDataFrame"] {
        border: 1px solid var(--dpg-border) !important;
        border-radius: 8px !important;
        background: var(--dpg-bg-secondary) !important;
    }

    /* Custom Tag Chips */
    .chip {
        display: inline-block;
        font-family: var(--dpg-font-mono);
        font-size: 11px;
        padding: 2px 8px;
        border-radius: 4px;
        margin: 2px;
        font-weight: 600;
    }
    .chip-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .chip-high { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }
    .chip-medium { background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); }
    .chip-safe { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }

    /* Feed Terminal Box */
    .terminal-feed {
        background: #050a12;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 12px 16px;
        font-family: var(--dpg-font-mono);
        font-size: 12px;
        line-height: 1.6;
        max-height: 220px;
        overflow-y: auto;
    }
    .feed-time { color: var(--dpg-text-muted); }
    .feed-info { color: #38bdf8; }
    .feed-warn { color: #fbbf24; }
    .feed-crit { color: #f87171; }
</style>
"""

def inject_theme():
    """Safely injects the theme stylesheet."""
    import streamlit as st
    try:
        st.markdown(get_theme_css(), unsafe_allow_html=True)
    except Exception:
        pass
