# pipeline/preprocess_toniot.py
import pandas as pd

FEATURE_COLS = [
    'proto', 'duration', 'src_bytes', 'dst_bytes',
    'conn_state', 'missed_bytes', 'src_pkts', 'dst_pkts',
    'src_ip_bytes', 'dst_ip_bytes'
]

def load_toniot(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    df['is_attack'] = (df['label'] == 1).astype(int)
    df['type']      = df['type'].fillna('normal')
    
    # Encode categoricals
    df['proto']      = df['proto'].astype('category').cat.codes
    df['conn_state'] = df['conn_state'].astype('category').cat.codes
    
    return df[FEATURE_COLS + ['is_attack', 'type']]

df = load_toniot('data/toniot/Train_Test_Network.csv')
df.to_parquet('data/toniot/processed.parquet')

print(df['type'].value_counts())