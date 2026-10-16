import pytest
from src.document_scanner import scan_document, mask_evidence

def test_mask_evidence():
    masked = mask_evidence("secret_token_12345", keep_chars=3)
    assert masked.startswith("sec")
    assert masked.endswith("345")
    assert "*" in masked
    assert mask_evidence("short") == "*****"

def test_scan_text_and_secrets():
    content = b"""
    Contact email: support@testcorp.com
    Emergency phone: 555-123-4567
    AWS_KEY = AKIAIOSFODNN7EXAMPLE
    DB_URL = postgresql://admin:secretPass1@database.internal:5432/main
    """
    findings = scan_document(content, "config.env")
    categories = [f["Category"] for f in findings]
    
    assert "Email" in categories
    assert "Phone Number" in categories
    assert "Authentication Secret" in categories
    
    # Evidence must be masked
    secret_findings = [f for f in findings if f["Category"] == "Authentication Secret"]
    for sf in secret_findings:
        assert "*" in sf["Evidence"]
