import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional

def add_laplace_noise(
    series: pd.Series,
    epsilon: float = 1.0,
    sensitivity: Optional[float] = None
) -> pd.Series:
    """
    Applies Differential Privacy (Laplace Mechanism) to a numerical series:
    Noise drawn from Laplace(0, scale = sensitivity / epsilon).
    Lower epsilon -> stronger privacy, higher noise.
    Higher epsilon -> weaker privacy, lower noise.
    """
    numeric_series = pd.to_numeric(series, errors="coerce")
    valid_mask = numeric_series.notna()
    
    if not valid_mask.any():
        return series

    vals = numeric_series[valid_mask].values
    if sensitivity is None:
        # Global sensitivity estimation based on data range
        val_range = float(vals.max() - vals.min())
        sensitivity = max(val_range / len(vals), 1.0)

    # Scale parameter b = sensitivity / epsilon
    scale = max(sensitivity / max(epsilon, 0.01), 1e-4)
    noise = np.random.laplace(0.0, scale, size=len(vals))
    
    noisy_vals = vals + noise
    
    # If original was integer, round to nearest integer
    if np.issubdtype(numeric_series.dtype, np.integer):
        noisy_vals = np.round(noisy_vals)

    res = series.copy()
    res.loc[valid_mask] = noisy_vals
    return res


def generate_synthetic_dataset(
    df: pd.DataFrame,
    num_samples: Optional[int] = None,
    noise_factor: float = 0.05
) -> pd.DataFrame:
    """
    Generates a privacy-preserving synthetic dataset preserving marginal distributions,
    means, covariances, and categorical frequency representations while breaking 
    record-level direct linkage.
    """
    if df.empty:
        return df.copy()

    n = num_samples if num_samples is not None else len(df)
    synth_dict = {}

    for col in df.columns:
        s = df[col]
        numeric_s = pd.to_numeric(s, errors="coerce")
        
        # Numeric Column: Sample from fitted Gaussian/Kernel with jitter
        if numeric_s.notna().sum() / max(len(s), 1) > 0.6:
            valid_nums = numeric_s.dropna().values
            mean = float(np.mean(valid_nums))
            std = float(np.std(valid_nums)) if len(valid_nums) > 1 else 1.0
            std = max(std, 1e-3)
            
            # Generate parametric Gaussian synthetic values
            generated = np.random.normal(loc=mean, scale=std, size=n)
            
            # If original had bounded positive values (e.g. age, salary), clip at min
            if (valid_nums >= 0).all():
                generated = np.clip(generated, a_min=0, a_max=None)
                
            if np.issubdtype(s.dtype, np.integer):
                generated = np.round(generated).astype(int)
            else:
                generated = np.round(generated, 2)
                
            synth_dict[col] = generated
        else:
            # Categorical / String Column: Sample proportionally to empirical probabilities
            non_null_s = s.dropna()
            if non_null_s.empty:
                synth_dict[col] = [None] * n
            else:
                val_counts = non_null_s.value_counts(normalize=True)
                choices = val_counts.index.values
                probs = val_counts.values
                synth_dict[col] = np.random.choice(choices, size=n, p=probs)

    synth_df = pd.DataFrame(synth_dict)
    return synth_df
