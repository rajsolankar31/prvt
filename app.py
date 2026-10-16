from src import (
    detect_sensitive_data,
    apply_protection,
    calculate_risk_assessment,
    evaluate_utility,
    generate_markdown_report,
    scan_document,
)

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from io import BytesIO
import os
import json


st.set_page_config(
    page_title="Data Privacy Guardian",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# UI Layer Enhancement Modules
try:
    from ui import inject_theme, render_background, render_soc_header, render_sidebar_footer
    UI_AVAILABLE = True
except Exception:
    UI_AVAILABLE = False

use_new_ui = st.sidebar.toggle("⚡ Use Cyber SOC UI v2", value=True, key="USE_NEW_UI")

if use_new_ui and UI_AVAILABLE:
    inject_theme()
    bg_fx_enabled = st.sidebar.toggle("🌐 Background FX", value=True, key="ui2_bg_fx")
    render_background(enabled=bg_fx_enabled)
else:
    st.markdown("""
    <div style="background:#091222; border:1px solid #1e3a5f; border-radius:10px; padding:18px; margin-bottom:20px;">
        <h2 style="color:#ffffff; margin:0;">🛡️ DATA PRIVACY GUARDIAN [CLASSIC]</h2>
        <div style="color:#00f2fe; font-size:12px; margin-top:5px;">● LOCAL PRIVACY ENGINE</div>
    </div>
    """, unsafe_allow_html=True)

@st.cache_data(show_spinner=False)
def load_dataset(file_bytes, filename):
    if filename.lower().endswith(".csv"):
        try:
            return pd.read_csv(BytesIO(file_bytes))
        except UnicodeDecodeError:
            return pd.read_csv(BytesIO(file_bytes), encoding="latin-1")
    return pd.read_excel(BytesIO(file_bytes), engine="openpyxl")


def format_bytes(size):
    if size < 1024:
        return f"{size} B"
    if size < 1024**2:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024**2):.2f} MB"


# Sidebar Navigation
st.sidebar.markdown("### 🎛️ NAVIGATION")

MODE_TABULAR = "📊 Tabular Datasets (CSV & Excel)"
MODE_DOCS = "📄 Documents & Text Files (PDF / Word / TXT)"
MODE_WEB = "🌐 Web Links & Tracker Finder"
MODULE_LIST = [MODE_TABULAR, MODE_DOCS, MODE_WEB]

if st.session_state.get("nav_mode_radio") not in MODULE_LIST:
    st.session_state["nav_mode_radio"] = MODULE_LIST[0]

mode = st.sidebar.radio("Choose a Privacy Tool:", MODULE_LIST, key="nav_mode_radio")

if use_new_ui and UI_AVAILABLE:
    render_sidebar_footer()
    render_soc_header(mode.split(" ", 1)[-1])


# ----------------------------------------------------
# MODE 1: TABULAR DATASETS (With PETs & Differential Privacy)
# ----------------------------------------------------
if mode == MODE_TABULAR:
    st.subheader("📊 Tabular Datasets Cleaner")
    st.write("Scan spreadsheet files (**CSV**, **Excel**) for customer names, emails, phone numbers, and salaries. Automatically mask or redact them before sharing.")

    # Easy In-Page File Ingestion
    up_card1, up_card2 = st.columns([3, 2])
    with up_card1:
        uploaded_file = st.file_uploader(
            "📁 Select or Drop a CSV or Excel file:",
            type=["csv", "xlsx"],
            help="Your file is processed locally on your device."
        )
    with up_card2:
        st.write("**Or try with test data:**")
        load_sample = st.button("⚡ Load Demo Medical/Customer Dataset", width="stretch")

    active_df = None
    file_name = ""
    file_size_str = ""

    if load_sample:
        sample_path = os.path.join(os.path.dirname(__file__), "sample_data", "sample_dataset.csv")
        if os.path.exists(sample_path):
            active_df = pd.read_csv(sample_path)
            file_name = "sample_dataset.csv"
            file_size_str = format_bytes(os.path.getsize(sample_path))
            st.session_state["tab_df"] = active_df
            st.session_state["tab_name"] = file_name
            st.session_state["tab_size"] = file_size_str

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        active_df = load_dataset(file_bytes, uploaded_file.name)
        file_name = uploaded_file.name
        file_size_str = format_bytes(len(file_bytes))
        st.session_state["tab_df"] = active_df
        st.session_state["tab_name"] = file_name
        st.session_state["tab_size"] = file_size_str
    elif "tab_df" in st.session_state:
        active_df = st.session_state["tab_df"]
        file_name = st.session_state["tab_name"]
        file_size_str = st.session_state["tab_size"]

    if active_df is not None:
        df = active_df.copy()

        if df.empty:
            st.warning("The selected dataset contains no data rows or columns.")
        else:
            # 1. Overview
            with st.expander("📊 1. Dataset Overview & Preview", expanded=True):
                col1, col2, col3, col4, col5 = st.columns(5)
                col1.metric("Total Rows", f"{df.shape[0]:,}")
                col2.metric("Total Columns", f"{df.shape[1]:,}")
                col3.metric("Missing Cells", f"{int(df.isna().sum().sum()):,}")
                col4.metric("Duplicate Rows", f"{int(df.duplicated().sum()):,}")
                col5.metric("File Size", file_size_str)

                st.caption(f"File: `{file_name}`")
                st.dataframe(df.head(10), width="stretch")

            # 2. Sensitive Information Discovery
            st.subheader("🔍 2. Sensitive Information Discovery")
            findings = detect_sensitive_data(df)

            if findings.empty:
                st.success("No supported sensitive-data indicators were detected by the rule patterns.")
            else:
                direct_count = len(findings[findings["Role"] == "Direct Identifier"])
                quasi_count = len(findings[findings["Role"] == "Quasi-Identifier"])
                sens_count = len(findings[findings["Role"] == "Sensitive Attribute"])

                fcol1, fcol2, fcol3 = st.columns(3)
                fcol1.metric("Direct Identifiers (PII)", direct_count, help="Names, Emails, Phones, IDs")
                fcol2.metric("Quasi-Identifiers", quasi_count, help="Age, ZIP, Gender (Can identify when linked)")
                fcol3.metric("Sensitive Attributes", sens_count, help="Salaries, Diagnoses, Financials")

                st.dataframe(findings, width="stretch")

            # 3. Protection Configuration
            st.subheader("🛡️ 3. Privacy Protection & PETs Configuration")
            detected_cols = findings["Column"].unique().tolist() if not findings.empty else []
            all_cols = list(df.columns)

            col_selection = st.multiselect(
                "Select columns to protect:",
                options=all_cols,
                default=[c for c in detected_cols if c in all_cols],
                help="Select columns to apply redaction, masking, generalization, pseudonymization, differential privacy, or removal."
            )

            column_actions = {}
            if col_selection:
                st.write("#### Configure Methods for Selected Columns:")
                grid_cols = st.columns(min(len(col_selection), 3))
                
                for i, c in enumerate(col_selection):
                    with grid_cols[i % len(grid_cols)]:
                        st.markdown(f"**Column: `{c}`**")
                        role_guess = "Direct Identifier"
                        if not findings.empty:
                            matched = findings[findings["Column"] == c]
                            if not matched.empty:
                                role_guess = matched.iloc[0]["Role"]
                        
                        default_idx = 0
                        if role_guess == "Direct Identifier":
                            default_idx = 1 # Mask or Redact
                        elif role_guess == "Quasi-Identifier":
                            default_idx = 3 # Generalize
                        elif role_guess == "Sensitive Attribute":
                            default_idx = 3 # Generalize or Redact

                        method = st.selectbox(
                            f"Action for {c}",
                            options=["Redact", "Mask", "Pseudonymize", "Generalize", "Differential Privacy", "Remove"],
                            index=default_idx,
                            key=f"method_{c}"
                        )

                        params = {}
                        if method == "Generalize":
                            step = st.number_input(f"Bin interval for {c}", min_value=1, max_value=100000, value=10, key=f"step_{c}")
                            params["step"] = float(step)
                        elif method == "Mask":
                            keep = st.slider(f"Unmasked edge chars for {c}", 0, 4, 1, key=f"mask_{c}")
                            params["keep_first"] = keep
                            params["keep_last"] = keep
                        elif method == "Pseudonymize":
                            params["salt"] = "guardian_secret_salt"
                        elif method == "Differential Privacy":
                            eps = st.slider(f"Epsilon (ε) budget for {c}", min_value=0.1, max_value=5.0, value=1.0, step=0.1, key=f"eps_{c}", help="Lower ε = more noise & stronger privacy.")
                            params["epsilon"] = float(eps)

                        column_actions[c] = {"method": method, "params": params}

            protected_df = apply_protection(df, column_actions)

            # 4. Preview
            with st.expander("👁️ 4. Protected Dataset Preview", expanded=True):
                st.dataframe(protected_df.head(10), width="stretch")

            # 5. Risk Assessment (k-anonymity & l-diversity)
            st.subheader("⚖️ 5. Advanced Privacy Risk, k-Anonymity & l-Diversity")
            risk_data = calculate_risk_assessment(df, protected_df, findings, column_actions)

            r_col1, r_col2, r_col3, r_col4, r_col5 = st.columns(5)
            r_col1.metric("Overall Risk Score", f"{risk_data['overall_risk_score']}/100", delta=risk_data["risk_level"], delta_color="inverse")
            r_col2.metric("Singling-Out Risk", f"{risk_data['reidentification_risk']}%")
            r_col3.metric("Min k-Anonymity", f"k = {risk_data['k_anonymity_estimate']}")
            r_col4.metric("Min l-Diversity", f"l = {risk_data.get('l_diversity_estimate', 1)}")
            r_col5.metric("Detection Coverage", f"{risk_data['coverage_percentage']}%")

            # Tactical Cybersecurity Threat Gauge
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=risk_data['overall_risk_score'],
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "TACTICAL RE-IDENTIFICATION & EXPOSURE INDEX", 'font': {'color': '#94a3b8', 'size': 14}},
                number={'font': {'color': '#38bdf8', 'size': 38, 'family': 'JetBrains Mono'}},
                gauge={
                    'axis': {'range': [0, 100], 'tickcolor': '#475569'},
                    'bar': {'color': "#00f2fe"},
                    'bgcolor': "#0b132b",
                    'borderwidth': 1,
                    'bordercolor': "#1e293b",
                    'steps': [
                        {'range': [0, 35], 'color': "rgba(16, 185, 129, 0.25)"},
                        {'range': [35, 70], 'color': "rgba(245, 158, 11, 0.25)"},
                        {'range': [70, 100], 'color': "rgba(239, 68, 68, 0.35)"},
                    ],
                    'threshold': {
                        'line': {'color': "#ef4444", 'width': 3},
                        'thickness': 0.8,
                        'value': 70
                    }
                }
            ))
            fig_gauge.update_layout(
                paper_bgcolor="#091222",
                plot_bgcolor="#091222",
                height=250,
                margin=dict(l=20, r=20, t=35, b=15)
            )
            st.plotly_chart(fig_gauge, width="stretch")

            st.markdown("**🛡️ Risk Mitigation Recommendations:**")
            for rec in risk_data["recommendations"]:
                st.info(f"👉 {rec}")

            # 6. Utility
            st.subheader("📈 6. Analytical Utility & Trade-Off Assessment")
            utility_data = evaluate_utility(df, protected_df)

            u_col1, u_col2, u_col3 = st.columns(3)
            u_col1.metric("Overall Utility Score", f"{utility_data['overall_utility_score']}%")
            u_col2.metric("Row Retention", f"{utility_data['rows_retained_pct']}%")
            u_col3.metric("Column Retention", f"{utility_data['columns_retained_pct']}%")

            if not utility_data["numeric_metrics"].empty:
                st.write("##### Numerical Distribution Preservation:")
                st.dataframe(utility_data["numeric_metrics"], width="stretch")

            if not utility_data["categorical_metrics"].empty:
                st.write("##### Categorical Diversity Preservation:")
                st.dataframe(utility_data["categorical_metrics"], width="stretch")

            # 7. Export
            st.subheader("📥 7. Export Protected Dataset & Audit Report")
            report_md = generate_markdown_report(
                file_name,
                df.shape,
                protected_df.shape,
                findings,
                risk_data,
                utility_data,
                column_actions
            )

            d_col1, d_col2 = st.columns(2)
            with d_col1:
                csv_data = protected_df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "⬇️ Download Protected Dataset (CSV)",
                    data=csv_data,
                    file_name=f"protected_{file_name if file_name.endswith('.csv') else file_name + '.csv'}",
                    mime="text/csv",
                    width="stretch"
                )

            with d_col2:
                st.download_button(
                    "📄 Download Privacy Audit Report (Markdown)",
                    data=report_md.encode("utf-8"),
                    file_name=f"privacy_audit_report_{file_name}.md",
                    mime="text/markdown",
                    width="stretch"
                )
    else:
        st.info("👈 Upload a dataset via the sidebar or click **'Load Sample Medical/Customer Dataset'** to begin.")


# ----------------------------------------------------
# MODE 2: DOCUMENTS, CODE & SECRETS
# ----------------------------------------------------
elif mode == MODE_DOCS:
    st.subheader("📄 Documents & Text Files Scanner")
    st.write(
        "Scan documents (**PDF**, **Word**, **TXT**, **Markdown**) for personal data, "
        "passwords, database connection strings, and exposed API tokens."
    )

    doc_upload = st.file_uploader(
        "Upload a PDF, Word or Text File",
        type=["pdf", "docx", "txt", "md"],
        help="Supports PDF, Word (.docx), plain text and Markdown."
    )

    demo_choice = st.selectbox(
        "Or test with a pre-configured scenario:",
        ["None (Upload your own)", "Sample Confidential Agreement (DOCX/TXT)", "Exposed Secrets & API Keys (text)"]
    )

    raw_bytes = None
    doc_name = ""

    if demo_choice == "Sample Confidential Agreement (DOCX/TXT)":
        sample_text = """
CONFIDENTIAL SERVICE AGREEMENT
Customer Name: Johnathan Doe
Contact Email: j.doe@megacorp.internal
Direct Phone: +1-555-891-2345
Billing SSN: 123-45-6789
Home Address: 742 Evergreen Terrace, San Francisco, CA
Credit Card: 4111111111111111
Diagnosis Note: Patient reported severe chronic migraine symptoms.
        """.strip()
        raw_bytes = sample_text.encode("utf-8")
        doc_name = "sample_agreement.txt"
    elif demo_choice == "Exposed Secrets & API Keys (text)":
        sample_code = """
# Production Configuration File
ENVIRONMENT=production
DB_URI="postgresql://db_admin:SuperSecretPass123!@prod-db.internal:5432/customer_db"
OPENAI_API_KEY="sk-proj-9876543210abcdef9876543210"
AWS_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"
SUPPORT_EMAIL="admin@securecompany.org"
        """.strip()
        raw_bytes = sample_code.encode("utf-8")
        doc_name = "prod_config.txt"
    elif doc_upload is not None:
        raw_bytes = doc_upload.getvalue()
        doc_name = doc_upload.name

    if raw_bytes is not None:
        st.write(f"**Scanning File:** `{doc_name}` ({format_bytes(len(raw_bytes))})")
        doc_findings = scan_document(raw_bytes, doc_name)

        if not doc_findings:
            st.success("✅ Clean! No sensitive identifiers or secret tokens detected in this document.")
        else:
            findings_df = pd.DataFrame(doc_findings)
            secret_count = len(findings_df[findings_df["Category"] == "Authentication Secret"])
            pii_count = len(findings_df) - secret_count

            m1, m2, m3 = st.columns(3)
            m1.metric("Total Findings", len(findings_df))
            m2.metric("PII Elements Found", pii_count)
            m3.metric("🚨 Exposed Secrets / Tokens", secret_count)

            st.dataframe(findings_df, width="stretch")

            csv_report = findings_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "⬇️ Download Document Findings Report (CSV)",
                data=csv_report,
                file_name=f"document_findings_{doc_name}.csv",
                mime="text/csv"
            )


# ----------------------------------------------------
# WEB LINKS & TRACKER FINDER
# ----------------------------------------------------
elif mode == MODE_WEB:
    from src.link_scanner import scan_live_web_link, scan_html_source

    st.subheader("🌐 Web Links & Tracker Finder")
    st.write(
        "Check a link or web page before you click, open or share it. Finds ad and analytics trackers, "
        "session recorders, fingerprinting, hidden pixels, tracking cookies and risky scripts, "
        "and explains **what each one does to you**."
    )

    tab_live, tab_html = st.tabs(["🔗 Scan a Link (URL)", "📋 Paste Page Source (offline)"])

    def render_link_report(rep, key_prefix):
        if rep.get("threat_summary"):
            for msg in rep["threat_summary"]:
                st.warning(msg)

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Privacy Threat Score", f"{rep['risk_score']}/100", delta=rep["risk_level"], delta_color="inverse")
        c2.metric("Trackers", len(rep["third_party_trackers"]))
        c3.metric("URL Tracking Tokens", len(rep["url_trackers"]))
        c4.metric("Hidden Pixels", len(rep["tracking_pixels"]))
        c5.metric("Risky Scripts", len(rep["suspicious_scripts"]))

        gauge = go.Figure(go.Indicator(
            mode="gauge+number", value=rep["risk_score"],
            title={"text": "LINK PRIVACY & TRACKING INDEX", "font": {"color": "#94a3b8", "size": 14}},
            number={"font": {"color": "#38bdf8", "size": 38}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#475569"},
                "bar": {"color": "#00f2fe"}, "bgcolor": "#0b132b", "borderwidth": 1, "bordercolor": "#1e293b",
                "steps": [
                    {"range": [0, 35], "color": "rgba(16, 185, 129, 0.25)"},
                    {"range": [35, 65], "color": "rgba(245, 158, 11, 0.25)"},
                    {"range": [65, 100], "color": "rgba(239, 68, 68, 0.35)"},
                ],
                "threshold": {"line": {"color": "#ef4444", "width": 3}, "thickness": 0.8, "value": 65},
            },
        ))
        gauge.update_layout(paper_bgcolor="#091222", plot_bgcolor="#091222", height=240, margin=dict(l=20, r=20, t=30, b=15))
        st.plotly_chart(gauge, width="stretch", key=f"{key_prefix}_gauge")

        # What this means for you
        if rep["effects"]:
            st.write("### ⚠️ What This Means For You")
            for e in rep["effects"]:
                st.markdown(f"- {e}")
        elif rep["is_accessible"]:
            st.success("✅ No known trackers or risky behavior detected.")

        # Category breakdown
        if rep["category_counts"]:
            cat_df = pd.DataFrame({"Category": list(rep["category_counts"].keys()),
                                   "Trackers": list(rep["category_counts"].values())})
            st.plotly_chart(px.bar(cat_df, x="Category", y="Trackers", title="Trackers by Type"),
                            width="stretch", key=f"{key_prefix}_cats")

        if rep["third_party_trackers"]:
            st.write("### 👁️ Trackers Found, Their Data & Effects")
            st.dataframe(pd.DataFrame(rep["third_party_trackers"]), width="stretch")

        if rep["url_trackers"]:
            st.write("### 🏷️ Tracking Parameters In The Link")
            st.dataframe(pd.DataFrame(rep["url_trackers"]), width="stretch")
            if rep.get("clean_url"):
                st.write("**Clean link (tracking removed) — safer to share:**")
                st.code(rep["clean_url"], language=None)

        if rep["tracking_pixels"]:
            st.write("### 🔍 Hidden Tracking Pixels")
            st.dataframe(pd.DataFrame(rep["tracking_pixels"]), width="stretch")

        if rep["cookies"]:
            st.write("### 🍪 Tracking / Third-Party Cookies")
            st.dataframe(pd.DataFrame(rep["cookies"]), width="stretch")

        if rep["suspicious_scripts"]:
            st.error("### 🚨 Risky Script Behavior")
            st.dataframe(pd.DataFrame(rep["suspicious_scripts"]), width="stretch")

        if rep["third_party_domains"]:
            with st.expander(f"🌍 All third-party domains contacted ({len(rep['third_party_domains'])})"):
                st.dataframe(pd.DataFrame(rep["third_party_domains"]), width="stretch")

        if rep["security_headers"]:
            with st.expander("🛡️ HTTP Security & Privacy Headers"):
                st.json(rep["security_headers"])
                if rep["missing_privacy_headers"]:
                    st.warning("Missing: " + "; ".join(rep["missing_privacy_headers"]))

        rows = (rep["url_trackers"] + rep["third_party_trackers"] + rep["tracking_pixels"]
                + rep["cookies"] + rep["suspicious_scripts"])
        if rows:
            st.download_button(
                "⬇️ Download Link Privacy Report (CSV)",
                data=pd.DataFrame(rows).to_csv(index=False).encode("utf-8"),
                file_name="link_privacy_report.csv", mime="text/csv", key=f"{key_prefix}_dl",
            )

    with tab_live:
        target_link = st.text_input(
            "Enter a web link (URL):",
            value="https://example.com?utm_source=newsletter&fbclid=IwAR2XYZ9876543210&gclid=Cj0KCQj12345",
        )
        st.caption("The page is fetched by this server. Local and private-network addresses are blocked.")
        if st.button("🔍 Scan Link For Trackers", type="primary", key="scan_live"):
            if target_link.startswith(("http://", "https://")):
                with st.spinner("Fetching page and checking trackers, scripts, cookies and headers..."):
                    st.session_state["link_report"] = scan_live_web_link(target_link)
            else:
                st.error("Please enter a valid URL starting with http:// or https://")
        if st.session_state.get("link_report"):
            render_link_report(st.session_state["link_report"], "live")

    with tab_html:
        st.write("No network needed. In your browser, open the page, press **Ctrl+U** (view source), copy it and paste below.")
        page_url_in = st.text_input("Page URL (optional, improves third-party detection):", key="html_url")
        html_in = st.text_area("Paste page HTML source:", height=200, key="html_src")
        if st.button("🔍 Scan Pasted Source", type="primary", key="scan_html"):
            if html_in.strip():
                st.session_state["html_report"] = scan_html_source(html_in, page_url_in.strip())
            else:
                st.error("Paste some HTML first.")
        if st.session_state.get("html_report"):
            render_link_report(st.session_state["html_report"], "html")
