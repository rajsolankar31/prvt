import pytest
import pandas as pd
import numpy as np
from src.advanced_pets import add_laplace_noise, generate_synthetic_dataset

def test_laplace_noise():
    s = pd.Series([100.0, 200.0, 300.0, 400.0, 500.0])
    noisy = add_laplace_noise(s, epsilon=1.0)
    assert len(noisy) == len(s)
    # Ensure noise altered values but kept distribution roughly reasonable
    assert not s.equals(noisy)
    assert abs(noisy.mean() - s.mean()) < 150.0

def test_synthetic_data_generator():
    df = pd.DataFrame({
        "age": [20, 30, 40, 50, 60],
        "category": ["A", "B", "A", "B", "A"],
        "salary": [50000, 60000, 70000, 80000, 90000]
    })
    synth = generate_synthetic_dataset(df, num_samples=10)
    assert len(synth) == 10
    assert "age" in synth.columns
    assert "category" in synth.columns
    assert "salary" in synth.columns
    assert set(synth["category"].unique()).issubset({"A", "B"})
