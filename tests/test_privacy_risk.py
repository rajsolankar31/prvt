import pytest
import pandas as pd
from src.privacy_risk import calculate_risk_assessment
from src.utility_assessment import evaluate_utility

def test_risk_and_utility_calculation():
    orig_df = pd.DataFrame({
        "full_name": ["Alice", "Bob", "Charlie"],
        "age": [25, 45, 25],
        "zip": ["94016", "94016", "94016"],
        "salary": [80000, 120000, 80000]
    })
    findings = pd.DataFrame([
        {"Column": "full_name", "Role": "Direct Identifier"},
        {"Column": "age", "Role": "Quasi-Identifier"},
        {"Column": "zip", "Role": "Quasi-Identifier"},
        {"Column": "salary", "Role": "Sensitive Attribute"}
    ])
    
    # 1. Unmitigated: high risk
    risk_unmitigated = calculate_risk_assessment(orig_df, orig_df, findings, {})
    assert risk_unmitigated["overall_risk_score"] > 50

    # 2. Mitigated: lower risk
    actions = {
        "full_name": {"method": "Redact"},
        "age": {"method": "Generalize", "params": {"step": 10}},
        "zip": {"method": "Remove"}
    }
    from src.protection import apply_protection
    prot_df = apply_protection(orig_df, actions)
    
    risk_mitigated = calculate_risk_assessment(orig_df, prot_df, findings, actions)
    assert risk_mitigated["direct_ids_exposed"] == 0
    assert risk_mitigated["overall_risk_score"] < risk_unmitigated["overall_risk_score"]

    # 3. Utility assessment
    utility = evaluate_utility(orig_df, prot_df)
    assert utility["rows_retained_pct"] == 100.0
    assert utility["columns_retained_pct"] == 75.0  # 3 of 4 columns retained
    assert utility["overall_utility_score"] > 50.0
