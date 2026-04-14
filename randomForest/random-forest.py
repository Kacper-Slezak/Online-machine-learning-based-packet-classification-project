import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report

from features import preprocess, aggregate_flows


# ===== LOAD =====
df = pd.read_csv("dataset.csv")

# ===== PREPROCESS =====
df = preprocess(df)

# ===== AGGREGATION =====
df = aggregate_flows(df)

# ===== LABEL =====
le = LabelEncoder()
df["y"] = le.fit_transform(df["label"])

X = df.drop(columns=["label", "y"])
y = df["y"]

# ===== SPLIT =====
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# ===== MODEL =====
model = RandomForestClassifier(
    n_estimators=300,
    max_depth=20,
    min_samples_split=5,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# ===== EVAL =====
pred = model.predict(X_test)

print("\n=== REPORT ===")
print(classification_report(y_test, pred, target_names=le.classes_))

# ===== FEATURE IMPORTANCE =====
import pandas as pd

importance = pd.Series(model.feature_importances_, index=X.columns)
print("\nTOP FEATURES:")
print(importance.sort_values(ascending=False).head(15))

# ===== SAVE =====
os.makedirs("models", exist_ok=True)

joblib.dump(model, "models/model.pkl")
joblib.dump(le, "models/label_encoder.pkl")