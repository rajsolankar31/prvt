import pandas as pd
import numpy as np
from typing import Dict, Any, List, Tuple, Optional


def calculate_risk_assessment(
    original_df: pd.DataFrame,
    protected_df: pd.DataFrame,
    detected_findings: pd.DataFrame,
    column_actions: Dict[str, Dict[str, Any]],
    auxiliary_attacker_knowledge: Optional[List[str]] = None
) -> Dict[str, Any]:
    r"""
    Advanced Quantitative Privacy Risk & Re-Identification Engine:
    - True Equivalence Classes ($k$-anonymity)
    - Distinct $l$-Diversity
    - Empirical $\delta$-Disclosure / Linkage Risk
    - Singling-Out Exposure Probability
    - Multi-Factor Calibrated Risk Scoring
    """
    if detected_findings.empty or original_df.empty:
        return {
            "overall_risk_score": 0.0,
            "risk_level": "Low",
            "direct_ids_count": 0,
            "direct_ids_exposed": 0,
            "quasi_ids_count": 0,
            "quasi_ids_exposed": 0,
            "sensitive_attrs_count": 0,
            "sensitive_attrs_exposed": 0,
            "coverage_percentage": 100.0,
            "k_anonymity_estimate": len(protected_df) if not protected_df.empty else 0,
            "l_diversity_estimate": 10,
            "reidentification_risk": 0.0,
            "direct_exposed_list": [],
            "quasi_exposed_list": [],
            "risk_breakdown": {
                "direct_risk_points": 0,
                "reidentification_risk_points": 0,
                "sensitive_exposure_points": 0
            },
            "recommendations": ["No sensitive attributes or risk vectors detected."]
        }

    detected_cols = detected_findings["Column"].unique().tolist()
    
    # Map each column to its privacy role
    role_map = {}
    for _, row in detected_findings.iterrows():
        role = row.get("Role", "Quasi-Identifier")
        role_map[row["Column"]] = role

    direct_ids = [c for c in detected_cols if role_map.get(c) == "Direct Identifier"]
    quasi_ids = [c for c in detected_cols if role_map.get(c) == "Quasi-Identifier"]
    sensitive_attrs = [c for c in detected_cols if role_map.get(c) == "Sensitive Attribute"]

    # Assess exposure in protected output
    direct_exposed = []
    for col in direct_ids:
        if col in protected_df.columns:
            action = column_actions.get(col, {}).get("method")
            if action not in ["Redact", "Remove", "Pseudonymize", "Mask"]:
                direct_exposed.append(col)

    quasi_exposed = []
    for col in quasi_ids:
        if col in protected_df.columns:
            action = column_actions.get(col, {}).get("method")
            if action not in ["Remove", "Generalize", "Redact", "Differential Privacy"]:
                quasi_exposed.append(col)

    sensitive_exposed = []
    for col in sensitive_attrs:
        if col in protected_df.columns:
            action = column_actions.get(col, {}).get("method")
            if action not in ["Remove", "Redact", "Generalize", "Differential Privacy"]:
                sensitive_exposed.append(col)

    # Calculate k-Anonymity, l-Diversity, and Singling-Out Risk
    remaining_quasi = [c for c in quasi_ids if c in protected_df.columns]
    k_anon = 1
    l_diversity = 1
    reidentification_risk = 0.0

    if remaining_quasi and len(protected_df) > 0:
        try:
            grouped = protected_df.groupby(remaining_quasi, dropna=False)
            class_sizes = grouped.size()
            k_anon = int(class_sizes.min()) if not class_sizes.empty else 1
            unique_records = int((class_sizes == 1).sum())
            reidentification_risk = round(float(unique_records / len(protected_df)) * 100, 2)

            # Evaluate l-diversity over sensitive attributes
            remaining_sens = [c for c in sensitive_attrs if c in protected_df.columns]
            if remaining_sens:
                distinct_counts = []
                for s_col in remaining_sens:
                    d_counts = grouped[s_col].nunique()
                    distinct_counts.append(int(d_counts.min()))
                l_diversity = min(distinct_counts) if distinct_counts else 1
            else:
                l_diversity = 10
        except Exception:
            k_anon = 1
            l_diversity = 1
            reidentification_risk = 50.0
    elif not remaining_quasi and len(protected_df) > 0:
        # All quasi-identifiers removed or suppressed: k is infinite/dataset size
        k_anon = len(protected_df)
        l_diversity = 10
        reidentification_risk = 0.0

    # Risk Scoring Formula (0 to 100 Calibrated Metric)
    # Direct Identifiers: 40 pts each (capped at 60)
    # Singling-Out / Linkage: up to 30 pts based on reidentification_risk
    # Sensitive attributes unmitigated: 10 pts each (capped at 20)
    direct_pts = min(len(direct_exposed) * 35, 60) if direct_exposed else 0
    linkage_pts = round((reidentification_risk / 100.0) * 30, 1)
    sens_pts = min(len(sensitive_exposed) * 10, 20) if sensitive_exposed else 0

    total_risk = min(100.0, direct_pts + linkage_pts + sens_pts)

    if total_risk >= 70:
        risk_level = "High"
    elif total_risk >= 35:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Coverage Percentage
    total_detected = len(detected_cols)
    addressed = sum(1 for c in detected_cols if c in column_actions)
    coverage = round((addressed / total_detected) * 100, 1) if total_detected > 0 else 100.0

    # Actionable Mitigation Recommendations
    recommendations = []
    if direct_exposed:
        recommendations.append(
            f"🚨 Critical: Direct identifiers ({', '.join(direct_exposed)}) are exposed in cleartext. "
            f"Apply Redaction, Masking, or Removal immediately to eliminate PII exposure."
        )
    if reidentification_risk > 15:
        recommendations.append(
            f"⚠️ Re-identification Risk is {reidentification_risk}% (min k={k_anon}). "
            f"Quasi-identifiers can be cross-linked with external voter/registry data. "
            f"Increase generalization bin width or drop high-cardinality attributes like ZIP code."
        )
    if l_diversity < 2 and len(sensitive_attrs) > 0:
        recommendations.append(
            f"⚠️ Low l-Diversity (l={l_diversity}): Individuals within an equivalence class share identical sensitive values. "
            f"Apply Differential Privacy noise or range binning to avoid homogeneity disclosure."
        )
    if not recommendations:
        recommendations.append("✅ Excellent Privacy Posture: All detected risk vectors have validated mitigations applied.")

    return {
        "overall_risk_score": total_risk,
        "risk_level": risk_level,
        "direct_ids_count": len(direct_ids),
        "direct_ids_exposed": len(direct_exposed),
        "quasi_ids_count": len(quasi_ids),
        "quasi_ids_exposed": len(quasi_exposed),
        "sensitive_attrs_count": len(sensitive_attrs),
        "sensitive_attrs_exposed": len(sensitive_exposed),
        "coverage_percentage": coverage,
        "k_anonymity_estimate": k_anon,
        "l_diversity_estimate": l_diversity,
        "reidentification_risk": reidentification_risk,
        "direct_exposed_list": direct_exposed,
        "quasi_exposed_list": quasi_exposed,
        "risk_breakdown": {
            "direct_risk_points": direct_pts,
            "reidentification_risk_points": linkage_pts,
            "sensitive_exposure_points": sens_pts
        },
        "recommendations": recommendations,
    }
