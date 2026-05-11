import os
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.metrics import classification_report, accuracy_score, f1_score
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight

from visualization.confusion_matrix_plot import plot_confusion_matrix
from visualization.feature_importance_plot import plot_feature_importance
from visualization.correlation_plot import plot_feature_correlation
from visualization.cv_scores_plot import plot_cv_scores


class RandomForestTrainer:

    def __init__(self, dataset_path, reports_dir="reports"):
        self.dataset_path = dataset_path
        self.reports_dir = reports_dir
        self.model = None
        self.label_encoder = LabelEncoder()
        self.feature_names = None

        os.makedirs(self.reports_dir, exist_ok=True)

    # --------------------------------------------------------------

    def _load_data(self):
        print(f"[*] Loading data from {self.dataset_path}...")

        try:
            df = pd.read_csv(self.dataset_path)
        except Exception as e:
            print(f"[!] Error during dataset loading: {e}")
            return None, None, None

        if df.empty:
            print("[!] Dataset is empty.")
            return None, None, None

        drop_cols = [c for c in ["label", "granularity"] if c in df.columns]
        X = df.drop(columns=drop_cols)
        y = df["label"]
        self.feature_names = list(X.columns)

        print(f"[+] Loaded {len(df)} samples | {X.shape[1]} features | {y.nunique()} classes")

        return X, y, df

    # --------------------------------------------------------------

    def _build_model(self, class_weights_dict):
        return RandomForestClassifier(
            n_estimators=100,
            class_weight=class_weights_dict,
            random_state=42
        )

    # --------------------------------------------------------------

    def _drop_correlated_features(self, X, y, threshold=0.85):
        pre = RandomForestClassifier(n_estimators=50, random_state=42)
        pre.fit(X, y)

        importances = pd.Series(pre.feature_importances_, index=X.columns)
        corr = X.corr(method="pearson").abs()
        cols = X.columns.tolist()
        to_drop = set()

        for i in range(len(cols)):
            for j in range(i + 1, len(cols)):
                if cols[i] in to_drop or cols[j] in to_drop:
                    continue

                if corr.loc[cols[i], cols[j]] >= threshold:
                    weaker = cols[i] if importances[cols[i]] < importances[cols[j]] else cols[j]
                    to_drop.add(weaker)

        dropped = sorted(to_drop)
        return X.drop(columns=dropped), dropped

    # --------------------------------------------------------------

    def train_and_evaluate(self):
        X, y, df = self._load_data()

        if X is None:
            return None

        classes = np.array(sorted(y.unique()))
        raw_weights = compute_class_weight("balanced", classes=classes, y=y)
        cw_dict = dict(zip(classes, raw_weights))

        gran_tag = os.path.splitext(os.path.basename(self.dataset_path))[0]

        X_before = X.copy()
        X, dropped = self._drop_correlated_features(X, y)
        self.feature_names = list(X.columns)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=42, stratify=y
        )

        cv_model = self._build_model(cw_dict)
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

        cv_res = cross_validate(
            cv_model, X, y, cv=cv, scoring=["accuracy", "f1_weighted", "f1_macro"]
        )

        self.model = self._build_model(cw_dict)
        self.model.fit(X_train, y_train)

        preds = self.model.predict(X_test)
        acc = accuracy_score(y_test, preds)
        f1w = f1_score(y_test, preds, average="weighted")

        print(f"\nAccuracy: {acc * 100:.2f}%")
        print(f"F1 weighted: {f1w:.4f}")
        print("\n" + classification_report(y_test, preds, digits=4))

        plot_confusion_matrix(y_test, preds, sorted(y.unique()), self.reports_dir, gran_tag)
        plot_feature_importance(self.model, self.feature_names, self.reports_dir, gran_tag)
        plot_feature_correlation(X_before, X_train, self.reports_dir, gran_tag)
        plot_cv_scores(cv_res, self.reports_dir, gran_tag)

        return acc

    # --------------------------------------------------------------

    def validate_features(self):
        X, y, df = self._load_data()

        if X is None:
            return

        print("\n" + "=" * 50)
        print(" FEATURE VALIDATION REPORT")
        print("=" * 50)

        missing = X.isnull().sum()

        if missing.any():
            print("\n[!] Features with missing values:")
            print(missing[missing > 0])
        else:
            print("\n[✓] No missing values detected.")

        variances = X.var()
        zero_var = variances[variances == 0].index.tolist()

        if zero_var:
            print(f"\n[!] Zero-variance features: {zero_var}")
        else:
            print("[✓] No zero-variance features.")

        return variances

    # --------------------------------------------------------------

    def save_model(self, model_path):
        if self.model is None:
            print("[!] No model to save.")
            return

        payload = {
            "model": self.model,
            "label_encoder": self.label_encoder,
            "feature_names": self.feature_names,
        }

        joblib.dump(payload, model_path)
        print(f"[+] Model saved to: {model_path}")

    # --------------------------------------------------------------

    def load_model(self, model_path):
        payload = joblib.load(model_path)

        self.model = payload["model"]
        self.label_encoder = payload["label_encoder"]
        self.feature_names = payload["feature_names"]

        print(f"[+] Model loaded from: {model_path}")