import datetime
import pandas as pd
from typing import Dict, Any


def generate_markdown_report(
    dataset_name: str,
    orig_shape: tuple,
    prot_shape: tuple,
    findings_df: pd.DataFrame,
    risk_data: Dict[str, Any],
    utility_data: Dict[str, Any],
    actions_taken: Dict[str, Any]
) -> str:
    """
    Produces a comprehensive, professional privacy audit report in Markdown format.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    md = []
    md.append(f"# 🛡️ Data Privacy Guardian — Audit & Assessment Report")
    md.append(f"**Generated:** {timestamp}  ")
    md.append(f"**Dataset:** `{dataset_name}`  ")
    md.append("---")

    md.append("## 1. Executive Summary")
    md.append(f"- **Original Dimensions:** {orig_shape[0]:,} rows × {orig_shape[1]:,} columns")
    md.append(f"- **Protected Dimensions:** {prot_shape[0]:,} rows × {prot_shape[1]:,} columns")
    md.append(f"- **Overall Residual Privacy Risk:** **{risk_data.get('risk_level', 'Unknown').upper()}** (Score: {risk_data.get('overall_risk_score', 0)}/100)")
    md.append(f"- **Analytical Utility Score:** **{utility_data.get('overall_utility_score', 0)}%** preserved")
    md.append(f"- **Detection Coverage:** {risk_data.get('coverage_percentage', 0)}% of identified sensitive fields addressed\n")

    md.append("## 2. Sensitive Information Discovery")
    if findings_df.empty:
        md.append("No sensitive identifiers detected by standard rule-based heuristics.")
    else:
        md.append(f"Detected **{len(findings_df)}** potential sensitive indicators:\n")
        md.append("| Column | Category | Role | Confidence | Matched Values |")
        md.append("|---|---|---|---|---|")
        for _, row in findings_df.iterrows():
            md.append(f"| {row['Column']} | {row['Category']} | {row['Role']} | {row['Confidence']} | {row['Matched Values']} |")
    md.append("")

    md.append("## 3. Data Protection Transformations Applied")
    if not actions_taken:
        md.append("No protection operations were selected for this dataset.")
    else:
        md.append("| Column | Selected Method | Details |")
        md.append("|---|---|---|")
        for col, act in actions_taken.items():
            method = act.get("method", "None")
            params = act.get("params", {})
            param_str = ", ".join([f"{k}={v}" for k, v in params.items()]) if params else "Default"
            md.append(f"| {col} | {method} | {param_str} |")
    md.append("")

    md.append("## 4. Privacy Risk & Re-Identification Analysis")
    md.append(f"- **Direct Identifiers Remaining Exposed:** {risk_data.get('direct_ids_exposed', 0)}")
    md.append(f"- **Estimated Min k-Anonymity:** `k = {risk_data.get('k_anonymity_estimate', 1)}`")
    md.append(f"- **Singling-out / Re-identification Risk:** {risk_data.get('reidentification_risk', 0)}% of records are distinct across quasi-identifiers.")
    md.append("\n**Key Recommendations:**")
    for rec in risk_data.get("recommendations", []):
        md.append(f"- {rec}")
    md.append("")

    md.append("## 5. Analytical Utility Preservation")
    md.append(f"- **Row Completeness:** {utility_data.get('rows_retained_pct', 100)}%")
    md.append(f"- **Column Retention:** {utility_data.get('columns_retained_pct', 100)}%")
    md.append(f"- **Overall Utility Preservation Score:** {utility_data.get('overall_utility_score', 100)}%\n")

    md.append("---")
    md.append("*Disclaimer: This automated assessment is produced by the local Data Privacy Guardian tool for developer and analyst guidance. It does not replace formal regulatory compliance certifications.*")

    return "\n".join(md)
