# models/train_network_detector.py
import pandas as pd
import joblib
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

df = pd.read_parquet('data/toniot/processed.parquet')

feature_cols = [c for c in df.columns if c not in ['is_attack', 'type']]

# Train only on normal traffic
normal_df = df[df['is_attack'] == 0]
X_train   = normal_df[feature_cols].values

# Test on full dataset
X_test = df[feature_cols].values
y_test = df['is_attack'].values

scaler  = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# Train One-Class SVM
model = OneClassSVM(kernel='rbf', nu=0.05, gamma='scale')
model.fit(X_train)

preds = (model.predict(X_test) == -1).astype(int)
print(classification_report(y_test, preds, target_names=['Normal', 'Attack']))

joblib.dump(model,  'models/ocsvm.pkl')
joblib.dump(scaler, 'models/network_scaler.pkl')