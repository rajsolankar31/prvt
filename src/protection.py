import hashlib
import pandas as pd
import numpy as np
from typing import Dict, Any, List


def redact_values(series: pd.Series, placeholder: str = "[REDACTED]") -> pd.Series:
    """Replaces all non-null values with a static redaction placeholder."""
    return series.map(lambda val: placeholder if pd.notna(val) else val)


def remove_columns(df: pd.DataFrame, columns_to_remove: List[str]) -> pd.DataFrame:
    """Drops the specified columns from the dataframe."""
    existing_cols = [col for col in columns_to_remove if col in df.columns]
    return df.drop(columns=existing_cols)


def mask_values(series: pd.Series, keep_first: int = 1, keep_last: int = 2, mask_char: str = "*") -> pd.Series:
    """
    Masks middle characters of strings (e.g., '123456789' -> '1******89', emails -> 'j***e@domain.com').
    """
    def _mask_single(val):
        if pd.isna(val):
            return val
        s = str(val)
        if "@" in s:
            parts = s.split("@", 1)
            local_part, domain = parts[0], parts[1]
            if len(local_part) <= 2:
                masked_local = mask_char * len(local_part)
            else:
                masked_local = local_part[0] + (mask_char * (len(local_part) - 2)) + local_part[-1]
            return f"{masked_local}@{domain}"

        if len(s) <= (keep_first + keep_last):
            return mask_char * len(s)
        
        return s[:keep_first] + (mask_char * (len(s) - keep_first - keep_last)) + s[-keep_last:]

    return series.map(_mask_single)


def generalize_values(series: pd.Series, step: float = 10.0) -> pd.Series:
    """
    Generalizes numerical attributes into bins/ranges (e.g., age 27 -> '20-29', or salary into ranges).
    If series is string/categorical (like postal codes), truncates precision.
    """
    # Check if numeric
    numeric_series = pd.to_numeric(series, errors="coerce")
    if numeric_series.notna().sum() / max(len(series), 1) > 0.6:
        # Numeric binning
        def _bin_num(val):
            if pd.isna(val):
                return val
            try:
                num = float(val)
                lower = int(np.floor(num / step) * step)
                upper = int(lower + step - 1)
                return f"{lower} - {upper}"
            except Exception:
                return val
        return series.map(_bin_num)
    else:
        # String generalization (e.g. ZIP code or long location strings: truncate last 2 characters)
        def _generalize_str(val):
            if pd.isna(val):
                return val
            s = str(val)
            if len(s) >= 4:
                return s[:-2] + "XX"
            return s
        return series.map(_generalize_str)


def pseudonymize_values(series: pd.Series, salt: str = "dpg_salt_key") -> pd.Series:
    """
    Deterministic cryptographic tokenization/pseudonymization using salted SHA-256.
    Ensures referential integrity while hiding cleartext identities.
    """
    def _pseudo_single(val):
        if pd.isna(val):
            return val
        salted = f"{salt}:{val}".encode("utf-8")
        h = hashlib.sha256(salted).hexdigest()[:12]
        return f"PSEUDO_{h}"

    return series.map(_pseudo_single)


def apply_protection(
    df: pd.DataFrame,
    column_actions: Dict[str, Dict[str, Any]]
) -> pd.DataFrame:
    """
    Applies designated protection mechanisms per column.
    column_actions format:
    {
        "ColumnName": {
            "method": "Redact" | "Mask" | "Generalize" | "Pseudonymize" | "Remove",
            "params": {...}
        }
    }
    """
    protected_df = df.copy()
    columns_to_drop = []

    for col, action in column_actions.items():
        if col not in protected_df.columns:
            continue
            
        method = action.get("method")
        params = action.get("params", {})

        if method == "Remove":
            columns_to_drop.append(col)
        elif method == "Redact":
            placeholder = params.get("placeholder", "[REDACTED]")
            protected_df[col] = redact_values(protected_df[col], placeholder=placeholder)
        elif method == "Mask":
            k_first = params.get("keep_first", 1)
            k_last = params.get("keep_last", 2)
            protected_df[col] = mask_values(protected_df[col], keep_first=k_first, keep_last=k_last)
        elif method == "Generalize":
            step = params.get("step", 10.0)
            protected_df[col] = generalize_values(protected_df[col], step=step)
        elif method == "Pseudonymize":
            salt = params.get("salt", "dpg_salt_key")
            protected_df[col] = pseudonymize_values(protected_df[col], salt=salt)
        elif method == "Differential Privacy":
            epsilon = params.get("epsilon", 1.0)
            from .advanced_pets import add_laplace_noise
            protected_df[col] = add_laplace_noise(protected_df[col], epsilon=epsilon)

    if columns_to_drop:
        protected_df = protected_df.drop(columns=columns_to_drop)

    return protected_df
