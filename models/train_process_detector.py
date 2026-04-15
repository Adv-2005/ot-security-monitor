# models/train_process_detector.py
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

# Load only normal data for unsupervised training
normal = pd.read_parquet('data/batadal/train_normal.parquet')
attack = pd.read_parquet('data/batadal/train_attack.parquet')

label_col  = 'is_attack'
feature_cols = [c for c in normal.columns if c not in ['datetime', label_col]]

X_train = normal[feature_cols].values
X_test  = attack[feature_cols].values
y_test  = attack[label_col].values

# Scale
scaler  = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# Train Isolation Forest
model = IsolationForest(
    n_estimators=200,
    contamination=0.05,   # ~5% expected anomaly rate
    random_state=42,
    n_jobs=-1
)
model.fit(X_train)

# Evaluate (convert IF output: -1=anomaly → 1, 1=normal → 0)
preds = (model.predict(X_test) == -1).astype(int)
print(classification_report(y_test, preds, target_names=['Normal', 'Attack']))

joblib.dump(model,  'models/isolation_forest.pkl')
joblib.dump(scaler, 'models/process_scaler.pkl')