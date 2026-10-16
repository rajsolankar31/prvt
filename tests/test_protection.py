import pytest
import pandas as pd
from src.protection import (
    redact_values,
    mask_values,
    generalize_values,
    pseudonymize_values,
    remove_columns,
    apply_protection
)

def test_redact_values():
    s = pd.Series(["Secret1", None, "Secret2"])
    redacted = redact_values(s)
    assert redacted.iloc[0] == "[REDACTED]"
    assert pd.isna(redacted.iloc[1])
    assert redacted.iloc[2] == "[REDACTED]"

def test_mask_values():
    s = pd.Series(["alice@example.com", "1234567890"])
    masked = mask_values(s)
    # email masking preserves domain
    assert "@example.com" in masked.iloc[0]
    assert masked.iloc[0].startswith("a")
    # string masking preserves edges
    assert masked.iloc[1].startswith("1")
    assert masked.iloc[1].endswith("90")

def test_generalize_values():
    # Numeric binning
    s_num = pd.Series([23, 47, 81])
    gen_num = generalize_values(s_num, step=10)
    assert gen_num.iloc[0] == "20 - 29"
    assert gen_num.iloc[1] == "40 - 49"
    assert gen_num.iloc[2] == "80 - 89"

def test_pseudonymize_values():
    s = pd.Series(["user_123", "user_123", "user_456"])
    pseudo = pseudonymize_values(s, salt="test_salt")
    assert pseudo.iloc[0].startswith("PSEUDO_")
    # Deterministic mapping
    assert pseudo.iloc[0] == pseudo.iloc[1]
    assert pseudo.iloc[0] != pseudo.iloc[2]

def test_apply_protection():
    df = pd.DataFrame({
        "name": ["Alice", "Bob"],
        "age": [25, 45],
        "drop_me": [1, 2]
    })
    actions = {
        "name": {"method": "Redact", "params": {}},
        "age": {"method": "Generalize", "params": {"step": 10}},
        "drop_me": {"method": "Remove", "params": {}}
    }
    protected = apply_protection(df, actions)
    assert "drop_me" not in protected.columns
    assert protected["name"].iloc[0] == "[REDACTED]"
    assert protected["age"].iloc[0] == "20 - 29"
