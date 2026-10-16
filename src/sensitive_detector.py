import re
import math
import pandas as pd
import numpy as np
from typing import Dict, Any, List, Optional, Tuple

# Comprehensive Semantic Category Mapping
COLUMN_CATEGORIES = {
    "Email": [
        "email", "e_mail", "mail_id", "email_address", "electronic_mail", "user_email", "contact_email"
    ],
    "Phone Number": [
        "phone", "mobile", "telephone", "contact_no", "contact_number", "cell", "cell_phone", "tel_no"
    ],
    "Name": [
        "name", "full_name", "first_name", "last_name", "fname", "lname", "customer_name",
        "patient_name", "employee_name", "client_name", "sur_name", "middle_name"
    ],
    "Financial Information": [
        "salary", "income", "bank_account", "account_number", "acc_no", "credit_card",
        "card_number", "cvv", "payment", "iban", "swift", "routing_number", "balance",
        "net_worth", "wage", "compensation", "revenue"
    ],
    "Government ID": [
        "aadhaar", "aadhar", "passport", "national_id", "tax_id", "pan_number", "ssn",
        "social_security", "voter_id", "driving_license", "dl_number", "tin", "ein"
    ],
    "Location": [
        "address", "street", "postal_code", "zip_code", "zip", "pincode", "latitude", "lat",
        "longitude", "long", "lon", "city", "state", "country", "province", "geo"
    ],
    "Health Information": [
        "diagnosis", "medical", "health", "patient", "prescription", "blood_group",
        "disease", "condition", "treatment", "doctor", "clinical", "medication", "symptom"
    ],
    "Demographics": [
        "age", "gender", "sex", "race", "ethnicity", "religion", "marital_status", "dob", "birth_date"
    ],
}

# Regex Patterns for Value-Level Inspection
PATTERNS = {
    "Email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),
    "Phone Number": re.compile(
        r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    "Credit Card": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    ),
    "SSN": re.compile(
        r"\b\d{3}-\d{2}-\d{4}\b"
    ),
    "Indian PAN": re.compile(
        r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"
    ),
    "Indian Aadhaar": re.compile(
        r"\b\d{4}\s?\d{4}\s?\d{4}\b"
    ),
    "IPv4 Address": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ),
}

CATEGORY_ROLE_MAP = {
    "Email": "Direct Identifier",
    "Phone Number": "Direct Identifier",
    "Name": "Direct Identifier",
    "Government ID": "Direct Identifier",
    "Credit Card": "Direct Identifier",
    "SSN": "Direct Identifier",
    "Indian PAN": "Direct Identifier",
    "Indian Aadhaar": "Direct Identifier",
    "IPv4 Address": "Direct Identifier",
    "Location": "Quasi-Identifier",
    "Demographics": "Quasi-Identifier",
    "Financial Information": "Sensitive Attribute",
    "Health Information": "Sensitive Attribute",
}


def compute_shannon_entropy(series: pd.Series) -> float:
    """Calculates Shannon entropy of non-null string values to measure randomness / uniqueness."""
    clean = series.dropna().astype(str)
    if len(clean) == 0:
        return 0.0
    val_counts = clean.value_counts()
    n = len(clean)
    probs = val_counts / n
    return -sum(p * math.log2(p) for p in probs if p > 0)


def classify_column(column_name: str) -> Optional[str]:
    """Semantic heuristic classifier using token matching and word boundaries."""
    normalized = str(column_name).lower().strip()
    normalized = re.sub(r"[^a-z0-9]+", "_", normalized)

    tokens = set(normalized.split("_"))
    for category, keywords in COLUMN_CATEGORIES.items():
        for keyword in keywords:
            if keyword in tokens or normalized == keyword or f"_{keyword}_" in f"_{normalized}_":
                return category
    return None


def detect_sensitive_data(df: pd.DataFrame, sample_size: int = 1000) -> pd.DataFrame:
    """
    High-Performance, Multi-Tier Sensitive Data Discovery:
    Tier 1: Column semantics & token categorization
    Tier 2: Value-level regex pattern recognition with confidence scoring
    Tier 3: Statistical distribution & uniqueness profiling (unmasking primary keys and candidate identifiers)
    """
    findings = []

    if df.empty:
        return pd.DataFrame(columns=[
            "Column", "Category", "Role", "Detection Method",
            "Matched Values", "Confidence", "Evidence", "Actionable Recommendation"
        ])

    sample_df = df.head(sample_size) if len(df) > sample_size else df
    total_rows = len(df)

    for column in df.columns:
        col_name = str(column)
        col_category = classify_column(col_name)
        non_null_count = int(df[column].notna().sum())
        clean_sample = sample_df[column].dropna().astype(str).str.strip()

        # Tier 1: Semantic Column Classification
        if col_category:
            role = CATEGORY_ROLE_MAP.get(col_category, "Quasi-Identifier")
            conf = "High" if col_category in ["Email", "Phone Number", "Government ID"] else "Medium"
            findings.append({
                "Column": col_name,
                "Category": col_category,
                "Role": role,
                "Detection Method": "Semantic Column Header",
                "Matched Values": non_null_count,
                "Confidence": conf,
                "Evidence": f"Header matches semantic patterns for '{col_category}'.",
                "Actionable Recommendation": (
                    "Apply Redaction or Masking" if role == "Direct Identifier" else
                    "Generalize/Bin values" if role == "Quasi-Identifier" else
                    "Apply Differential Privacy or Range Generalization"
                )
            })

        if len(clean_sample) == 0:
            continue

        # Tier 2: Deep Pattern Matching across string sample
        for pat_name, pat_regex in PATTERNS.items():
            matches = clean_sample.apply(lambda val: bool(pat_regex.search(val)))
            match_count = int(matches.sum())
            ratio = match_count / len(clean_sample)

            if ratio >= 0.05: # At least 5% of sample values match format
                estimated_total = int(ratio * non_null_count)
                role = CATEGORY_ROLE_MAP.get(pat_name, "Direct Identifier")
                conf_level = "Very High" if ratio > 0.4 else "High"

                already = any(
                    f["Column"] == col_name and f["Category"] == pat_name 
                    for f in findings
                )
                if not already:
                    findings.append({
                        "Column": col_name,
                        "Category": pat_name,
                        "Role": role,
                        "Detection Method": "Value Pattern Recognition",
                        "Matched Values": estimated_total,
                        "Confidence": conf_level,
                        "Evidence": f"{match_count}/{len(clean_sample)} sampled values ({ratio*100:.1f}%) matched '{pat_name}' syntax.",
                        "Actionable Recommendation": "Sanitize using token masking or cryptographic pseudonymization."
                    })

        # Tier 3: High-Entropy / Primary Key Uniqueness Discovery
        # If a column is 100% unique or near-100% unique, it poses singling-out / tracker risks
        if non_null_count > 10 and not any(f["Column"] == col_name for f in findings):
            unique_ratio = df[column].nunique(dropna=True) / max(non_null_count, 1)
            entropy = compute_shannon_entropy(sample_df[column])

            if unique_ratio > 0.95 and entropy > 3.0:
                findings.append({
                    "Column": col_name,
                    "Category": "Unique Identifier / Tracker",
                    "Role": "Direct Identifier",
                    "Detection Method": "Statistical Uniqueness & Entropy",
                    "Matched Values": non_null_count,
                    "Confidence": "Medium-High",
                    "Evidence": f"Extremely high uniqueness ({unique_ratio*100:.1f}%) and entropy ({entropy:.2f}). Acts as a unique record tracker.",
                    "Actionable Recommendation": "Drop column or apply salted pseudonymization to eliminate linkage."
                })

    return pd.DataFrame(
        findings,
        columns=[
            "Column",
            "Category",
            "Role",
            "Detection Method",
            "Matched Values",
            "Confidence",
            "Evidence",
            "Actionable Recommendation"
        ]
    )
