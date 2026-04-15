"""
bootstrap_train.py
──────────────────
Generates synthetic training data matching BATADAL and TON_IoT schemas,
trains Isolation Forest (process) and One-Class SVM (network) models,
and saves them to models/ so the live pipeline can start immediately.

Run once before starting pipeline/zeek_parser.py.
Replace data/ CSVs with real datasets later and re-run to improve accuracy.
"""

import os, sys
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

SEED = 42
rng  = np.random.default_rng(SEED)

os.makedirs("models", exist_ok=True)
os.makedirs("data/batadal", exist_ok=True)
os.makedirs("data/toniot",  exist_ok=True)

# ─────────────────────────────────────────────
# 1.  BATADAL-schema synthetic data
#     Sensors: pressure (P), flow (F), tank level (L), pump state (S)
#     7 sensors typical in BATADAL water network
# ─────────────────────────────────────────────
print("\n[1/4] Generating BATADAL-schema synthetic data …")

N_NORMAL = 8_000
N_ATTACK = 2_000

# Normal: sensors drawn from stable Gaussian distributions
SENSOR_MEANS = [62.1, 48.3, 75.0, 1.0, 55.2, 43.8, 68.4]   # 7 sensors
SENSOR_STDS  = [ 3.2,  2.5,  4.1, 0.05, 2.9,  2.1,  3.7]

normal_sensors = np.column_stack([
    rng.normal(mu, sigma, N_NORMAL)
    for mu, sigma in zip(SENSOR_MEANS, SENSOR_STDS)
])

# Attack: abrupt shifts / spikes / frozen values on random sensors
attack_sensors = np.column_stack([
    rng.normal(mu, sigma, N_ATTACK)
    for mu, sigma in zip(SENSOR_MEANS, SENSOR_STDS)
])

attack_types = rng.choice(
    ['pressure_spike', 'flow_drop', 'level_freeze', 'pump_flip'],
    size=N_ATTACK
)
for i, atype in enumerate(attack_types):
    if atype == 'pressure_spike':
        attack_sensors[i, 0] += rng.uniform(20, 40)
    elif atype == 'flow_drop':
        attack_sensors[i, 1] -= rng.uniform(30, 48)
    elif atype == 'level_freeze':
        attack_sensors[i, 2] = SENSOR_MEANS[2]   # frozen reading
    elif atype == 'pump_flip':
        attack_sensors[i, 3] = 1.0 - attack_sensors[i, 3]

SENSOR_COLS = [f'sensor_{i+1}' for i in range(7)]

df_normal = pd.DataFrame(normal_sensors, columns=SENSOR_COLS)
df_normal['is_attack'] = 0

df_attack = pd.DataFrame(attack_sensors, columns=SENSOR_COLS)
df_attack['is_attack'] = 1
df_attack['attack_type'] = attack_types

df_batadal = pd.concat([df_normal, df_attack], ignore_index=True)
df_batadal.to_parquet('data/batadal/combined.parquet', index=False)
print(f"   Normal: {N_NORMAL:,}  |  Attack: {N_ATTACK:,}")

# ─────────────────────────────────────────────
# 2.  TON_IoT-schema synthetic data
#     Features mirroring TON_IoT network flow columns
# ─────────────────────────────────────────────
print("[2/4] Generating TON_IoT-schema synthetic data …")

N_NET_NORMAL = 10_000
N_NET_ATTACK =  3_000

def gen_normal_flows(n):
    return pd.DataFrame({
        'duration':     rng.exponential(0.5,  n),
        'orig_bytes':   rng.exponential(512,  n).astype(int),
        'resp_bytes':   rng.exponential(256,  n).astype(int),
        'orig_pkts':    rng.poisson(5,        n).astype(int),
        'resp_pkts':    rng.poisson(3,        n).astype(int),
        'missed_bytes': np.zeros(n, dtype=int),
        'proto':        rng.choice([6, 17],   n),   # 6=TCP, 17=UDP
        'conn_state':   rng.choice([0,1,2,3], n, p=[0.7,0.15,0.1,0.05]),
        'is_attack': 0,
        'attack_type': 'normal',
    })

def gen_attack_flows(n):
    atype = rng.choice(
        ['scan', 'dos', 'injection', 'mitm', 'backdoor'],
        size=n, p=[0.3, 0.25, 0.2, 0.15, 0.1]
    )
    df = pd.DataFrame({
        'duration':     np.where(atype=='dos',  rng.uniform(0,0.01,n), rng.exponential(2,n)),
        'orig_bytes':   np.where(atype=='dos',  rng.integers(6000,65000,n), rng.integers(0,100,n)),
        'resp_bytes':   np.where(atype=='mitm', rng.integers(2000,8000,n),  np.zeros(n,int)),
        'orig_pkts':    np.where(atype=='dos',  rng.integers(500,5000,n),   rng.integers(1,3,n)),
        'resp_pkts':    np.zeros(n, dtype=int),
        'missed_bytes': np.where(atype=='dos',  rng.integers(1000,50000,n), np.zeros(n,int)),
        'proto':        rng.choice([6,17], n),
        'conn_state':   rng.choice([4,5,6], n),   # abnormal states
        'is_attack': 1,
        'attack_type': atype,
    })
    return df

df_net = pd.concat([
    gen_normal_flows(N_NET_NORMAL),
    gen_attack_flows(N_NET_ATTACK),
], ignore_index=True)

df_net.to_parquet('data/toniot/combined.parquet', index=False)
print(f"   Normal: {N_NET_NORMAL:,}  |  Attack: {N_NET_ATTACK:,}")

# ─────────────────────────────────────────────
# 3.  Train Isolation Forest — process detector
# ─────────────────────────────────────────────
print("[3/4] Training Isolation Forest (process anomaly) …")

PROC_FEATURES = SENSOR_COLS

# Add rolling features
df_proc = pd.read_parquet('data/batadal/combined.parquet')
for col in SENSOR_COLS:
    df_proc[f'{col}_delta']    = df_proc[col].diff().fillna(0)
    df_proc[f'{col}_rollmean'] = df_proc[col].rolling(5, min_periods=1).mean()
    df_proc[f'{col}_rollstd']  = df_proc[col].rolling(5, min_periods=1).std().fillna(0)

ALL_PROC_FEATS = [c for c in df_proc.columns if c not in ['is_attack','attack_type']]

X_train_proc = df_proc[df_proc['is_attack']==0][ALL_PROC_FEATS].values
X_test_proc  = df_proc[ALL_PROC_FEATS].values
y_test_proc  = df_proc['is_attack'].values

proc_scaler  = StandardScaler()
X_train_proc = proc_scaler.fit_transform(X_train_proc)
X_test_proc  = proc_scaler.transform(X_test_proc)

iso_forest = IsolationForest(
    n_estimators=200, contamination=0.05, random_state=SEED, n_jobs=-1
)
iso_forest.fit(X_train_proc)

preds_proc = (iso_forest.predict(X_test_proc) == -1).astype(int)
print("\n   ── Isolation Forest results ──")
print(classification_report(y_test_proc, preds_proc,
      target_names=['Normal', 'Attack'], zero_division=0))

joblib.dump(iso_forest,   'models/isolation_forest.pkl')
joblib.dump(proc_scaler,  'models/process_scaler.pkl')
joblib.dump(ALL_PROC_FEATS, 'models/process_feature_names.pkl')
print("   Saved: models/isolation_forest.pkl")

# ─────────────────────────────────────────────
# 4.  Train One-Class SVM — network detector
# ─────────────────────────────────────────────
print("[4/4] Training One-Class SVM (network anomaly) …")

NET_FEATURES = ['duration','orig_bytes','resp_bytes','orig_pkts',
                'resp_pkts','missed_bytes','proto','conn_state']

df_net = pd.read_parquet('data/toniot/combined.parquet')
X_train_net = df_net[df_net['is_attack']==0][NET_FEATURES].values.astype(float)
X_test_net  = df_net[NET_FEATURES].values.astype(float)
y_test_net  = df_net['is_attack'].values

net_scaler   = StandardScaler()
X_train_net  = net_scaler.fit_transform(X_train_net)
X_test_net   = net_scaler.transform(X_test_net)

ocsvm = OneClassSVM(kernel='rbf', nu=0.05, gamma='scale')
ocsvm.fit(X_train_net)

preds_net = (ocsvm.predict(X_test_net) == -1).astype(int)
print("\n   ── One-Class SVM results ──")
print(classification_report(y_test_net, preds_net,
      target_names=['Normal', 'Attack'], zero_division=0))

joblib.dump(ocsvm,        'models/ocsvm.pkl')
joblib.dump(net_scaler,   'models/network_scaler.pkl')
joblib.dump(NET_FEATURES, 'models/network_feature_names.pkl')
print("   Saved: models/ocsvm.pkl")

print("\n✓ Bootstrap training complete. All models saved to models/")
print("  Run:  python pipeline/zeek_parser.py")