# pipeline/preprocess_batadal.py
import pandas as pd
import numpy as np

def load_batadal(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, parse_dates=['DATETIME'])
    df.columns = df.columns.str.strip().str.lower()
    df['is_attack'] = (df['att_flag'] == 1).astype(int)
    df = df.drop(columns=['att_flag'])
    return df

def extract_features(df: pd.DataFrame, window: int = 5) -> pd.DataFrame:
    """Rolling statistical features over sensor columns."""
    sensor_cols = [c for c in df.columns if c not in ['datetime', 'is_attack']]
    
    for col in sensor_cols:
        df[f'{col}_delta']   = df[col].diff()
        df[f'{col}_rollmean'] = df[col].rolling(window).mean()
        df[f'{col}_rollstd']  = df[col].rolling(window).std()
    
    df = df.dropna()
    return df

train_normal = load_batadal('data/batadal/BATADAL_dataset03.csv')
train_attack  = load_batadal('data/batadal/BATADAL_dataset04.csv')

train_normal = extract_features(train_normal)
train_attack  = extract_features(train_attack)

train_normal.to_parquet('data/batadal/train_normal.parquet')
train_attack.to_parquet('data/batadal/train_attack.parquet')

print(f"Normal samples: {len(train_normal)}")
print(f"Attack samples: {train_attack['is_attack'].sum()}")