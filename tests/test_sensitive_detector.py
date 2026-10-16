import pytest
import pandas as pd
from src.sensitive_detector import detect_sensitive_data, classify_column

def test_classify_column():
    assert classify_column("email_address") == "Email"
    assert classify_column("phone_no") == "Phone Number"
    assert classify_column("patient_name") == "Name"
    assert classify_column("salary") == "Financial Information"
    assert classify_column("zip_code") == "Location"
    assert classify_column("random_unrelated_col") is None

def test_detect_sensitive_data():
    df = pd.DataFrame({
        "full_name": ["Alice", "Bob"],
        "email": ["alice@example.com", "bob@work.org"],
        "phone": ["+1-555-123-4567", "555-987-6543"],
        "age": [25, 45],
        "notes": ["Patient diagnosed with cold", "Regular follow-up"]
    })
    findings = detect_sensitive_data(df)
    assert not findings.empty
    detected_cols = findings["Column"].tolist()
    assert "full_name" in detected_cols
    assert "email" in detected_cols
    assert "phone" in detected_cols
    assert "age" in detected_cols
