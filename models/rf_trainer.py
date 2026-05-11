# models/rf_trainer.py

import os
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.metrics import (
    classification_report, accuracy_score, confusion_matrix,
    ConfusionMatrixDisplay, roc_auc_score, f1_score
)
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight


class RandomForestTrainer:
    def __init__(self, dataset_path, reports_dir="reports"):
        """Initializes the trainer with the path to the aggregated feature CSV."""
        self.dataset_path   = dataset_path
        self.reports_dir    = reports_dir
        self.model          = None
        self.label_encoder  = LabelEncoder()
        self.feature_names  = None
        os.makedirs(self.reports_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_data(self):
        """Loads the CSV dataset and returns (X, y, df)."""
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
        print(f"    Classes: {sorted(y.unique())}")
        print("\n    Class distribution:")
        for cls, cnt in y.value_counts().items():
            print(f"      {cls:20s}: {cnt:5d} samples ({cnt / len(y) * 100:.1f}%)")

        return X, y, df

    def _build_model(self, class_weights_dict):
        """Builds the RandomForestClassifier with balanced class weights."""
        return RandomForestClassifier(
            n_estimators=100,
            class_weight=class_weights_dict,
            random_state=42,
        )

    def _drop_correlated_features(self, X, y, threshold=0.85):
        """Removes redundant correlated features before training.

        For each pair with |r| >= threshold, drops the feature with lower
        Gini importance (determined by a quick 50-tree preliminary RF fit).
        Returns (X_filtered, dropped_list).
        """
        # Quick fit just to get importances for tie-breaking
        pre = RandomForestClassifier(n_estimators=50, random_state=42)
        pre.fit(X, y)
        importances = pd.Series(pre.feature_importances_, index=X.columns)

        corr    = X.corr(method="pearson").abs()
        cols    = X.columns.tolist()
        to_drop = set()

        for i in range(len(cols)):
            for j in range(i + 1, len(cols)):
                if cols[i] in to_drop or cols[j] in to_drop:
                    continue
                if corr.loc[cols[i], cols[j]] >= threshold:
                    weaker = cols[i] if importances[cols[i]] < importances[cols[j]] else cols[j]
                    to_drop.add(weaker)

        dropped = sorted(to_drop)
        if dropped:
            print(f"\n[*] Dropping {len(dropped)} correlated feature(s) (|r| >= {threshold}):")
            for feat in dropped:
                print(f"    - {feat}  (importance: {importances[feat]:.5f})")
        else:
            print(f"\n[✓] No correlated features to drop (threshold |r| >= {threshold}).")

        return X.drop(columns=dropped), dropped

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def train_and_evaluate(self):
        """Full training + evaluation pipeline.

        Steps:
          1. Load & inspect data
          2. Compute balanced class weights
          3. Stratified train/test split
          4. 5-fold stratified cross-validation
          5. Final fit on train set, evaluate on test set
          6. Save all reports/plots

        Returns float accuracy or None on error.
        """
        X, y, df = self._load_data()
        if X is None:
            return None

        # ---- 1. Class weights ----------------------------------------
        classes     = np.array(sorted(y.unique()))
        raw_weights = compute_class_weight("balanced", classes=classes, y=y)
        cw_dict     = dict(zip(classes, raw_weights))
        print("\n[*] Computed class weights (balanced):")
        for cls, w in cw_dict.items():
            print(f"    {cls:20s}: {w:.4f}")

        # ---- 2. Drop correlated features -----------------------------
        gran_tag  = os.path.splitext(os.path.basename(self.dataset_path))[0]
        X_before  = X.copy()
        X, dropped = self._drop_correlated_features(X, y)
        self.feature_names = list(X.columns)

        # ---- 3. Train / test split -----------------------------------
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=42, stratify=y
        )
        print(f"\n[*] Split → train: {len(X_train)}, test: {len(X_test)}")

        # ---- 3. Cross-validation ------------------------------------
        print("\n[*] Running 5-fold stratified cross-validation...")
        cv_model = self._build_model(cw_dict)
        cv       = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_res   = cross_validate(
            cv_model, X, y, cv=cv,
            scoring=["accuracy", "f1_weighted", "f1_macro"],
        )
        print("    CV Results (mean ± std):")
        for metric in ["test_accuracy", "test_f1_weighted", "test_f1_macro"]:
            vals = cv_res[metric]
            label = metric.replace("test_", "")
            print(f"    {label:20s}: {vals.mean():.4f} ± {vals.std():.4f}  "
                  f"[{vals.min():.4f} – {vals.max():.4f}]")

        # ---- 4. Final model -----------------------------------------
        print("\n[*] Training final Random Forest model...")
        self.model = self._build_model(cw_dict)
        self.model.fit(X_train, y_train)

        preds = self.model.predict(X_test)
        acc   = accuracy_score(y_test, preds)
        f1w   = f1_score(y_test, preds, average="weighted")

        print(f"\n=== Test-set results ===")
        print(f"    Accuracy (test) : {acc * 100:.2f}%")
        print(f"    F1 weighted     : {f1w:.4f}")
        print(f"\n{classification_report(y_test, preds, digits=4)}")

        # ---- 5. Save plots ------------------------------------------
        self._plot_confusion_matrix(y_test, preds, gran_tag)
        self._plot_feature_importance(gran_tag)
        self._plot_feature_correlation(X_before, X_train, gran_tag)
        self._plot_cv_scores(cv_res, gran_tag)

        return acc

    # ------------------------------------------------------------------
    # Validation plots
    # ------------------------------------------------------------------

    def _plot_confusion_matrix(self, y_true, y_pred, tag):
        labels = sorted(y_true.unique())
        cm     = confusion_matrix(y_true, y_pred, labels=labels)

        fig, axes = plt.subplots(1, 2, figsize=(14, 5))

        # Raw counts
        disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
        disp.plot(ax=axes[0], colorbar=False, cmap="Blues")
        axes[0].set_title("Confusion Matrix — raw counts")
        axes[0].tick_params(axis='x', rotation=45)

        # Normalised (recall per class)
        cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True)
        disp2   = ConfusionMatrixDisplay(confusion_matrix=cm_norm, display_labels=labels)
        disp2.plot(ax=axes[1], colorbar=False, cmap="Blues", values_format=".2f")
        axes[1].set_title("Confusion Matrix — normalised (recall)")
        axes[1].tick_params(axis='x', rotation=45)

        plt.tight_layout()
        path = os.path.join(self.reports_dir, f"confusion_matrix_{tag}.png")
        plt.savefig(path, dpi=150, bbox_inches="tight")
        plt.close()
        print(f"[+] Confusion matrix saved → {path}")

    def _plot_feature_importance(self, tag):
        importances = pd.Series(
            self.model.feature_importances_,
            index=self.feature_names
        ).sort_values(ascending=False)

        fig, ax = plt.subplots(figsize=(10, max(4, len(importances) * 0.45)))
        colors  = ["#2196F3" if i < 5 else "#90CAF9" for i in range(len(importances))]
        importances.plot(kind="barh", ax=ax, color=colors[::-1])
        ax.invert_yaxis()
        ax.set_xlabel("Mean decrease in impurity (Gini importance)")
        ax.set_title("Feature Importance (Random Forest)")
        ax.axvline(importances.mean(), color="red", linestyle="--", label="mean")
        ax.legend()

        # Annotate top-5
        for i, (feat, val) in enumerate(importances.items()):
            if i >= 5:
                break
            ax.text(val + 0.001, i, f"{val:.4f}", va="center", fontsize=8)

        plt.tight_layout()
        path = os.path.join(self.reports_dir, f"feature_importance_{tag}.png")
        plt.savefig(path, dpi=150, bbox_inches="tight")
        plt.close()
        print(f"[+] Feature importance saved → {path}")

        print("\n    Top-10 features by importance:")
        for feat, val in importances.head(10).items():
            bar = "█" * int(val * 200)
            print(f"    {feat:30s}: {val:.5f}  {bar}")

    def _plot_feature_correlation(self, X_before, X_after, tag):
        """Saves a side-by-side correlation heatmap: before vs after dropping."""
        corr_before = X_before.corr(method="pearson")
        corr_after  = X_after.corr(method="pearson")

        n_before = len(corr_before)
        n_after  = len(corr_after)
        cell_size = 0.85

        fig, axes = plt.subplots(
            1, 2,
            figsize=(n_before * cell_size + n_after * cell_size + 2, max(n_before, n_after) * cell_size + 2)
        )

        for ax, corr, title in [
            (axes[0], corr_before, f"BEFORE  ({n_before} features)"),
            (axes[1], corr_after,  f"AFTER   ({n_after} features)"),
        ]:
            mask = np.triu(np.ones_like(corr, dtype=bool))
            sns.heatmap(
                corr, mask=mask, annot=True, fmt=".2f", cmap="coolwarm",
                center=0, square=True, linewidths=0.5,
                annot_kws={"size": 7}, ax=ax, vmin=-1, vmax=1,
                cbar=False,
            )
            ax.set_title(title, fontsize=10, fontweight="bold")
            ax.tick_params(axis='x', rotation=45, labelsize=7)
            ax.tick_params(axis='y', rotation=0,  labelsize=7)

        fig.suptitle("Feature Correlation Matrix — before vs after dropping correlated features",
                     fontsize=11, y=1.01)
        plt.tight_layout()

        path = os.path.join(self.reports_dir, f"feature_correlation_{tag}.png")
        plt.savefig(path, dpi=150, bbox_inches="tight")
        plt.close()
        print(f"[+] Correlation matrix (before/after) saved → {path}")

    def _plot_cv_scores(self, cv_res, tag):
        metrics = {
            "Accuracy":    cv_res["test_accuracy"],
            "F1 weighted": cv_res["test_f1_weighted"],
            "F1 macro":    cv_res["test_f1_macro"],
        }
        folds = np.arange(1, 6)

        fig, ax = plt.subplots(figsize=(8, 4))
        for name, vals in metrics.items():
            ax.plot(folds, vals, marker="o", label=f"{name} (μ={vals.mean():.3f})")

        ax.set_xlabel("Fold")
        ax.set_ylabel("Score")
        ax.set_ylim(0, 1.05)
        ax.set_title("5-Fold Cross-Validation Scores")
        ax.legend()
        ax.grid(True, alpha=0.3)

        plt.tight_layout()
        path = os.path.join(self.reports_dir, f"cv_scores_{tag}.png")
        plt.savefig(path, dpi=150, bbox_inches="tight")
        plt.close()
        print(f"[+] CV score plot saved → {path}")

    # ------------------------------------------------------------------
    # Feature validation report
    # ------------------------------------------------------------------

    def validate_features(self):
        """Standalone feature-quality analysis — call before training.

        Prints/saves:
          - Missing value summary
          - Per-feature statistics
          - Zero-variance features
          - Per-class feature distributions
        """
        X, y, df = self._load_data()
        if X is None:
            return

        print("\n" + "=" * 50)
        print(" FEATURE VALIDATION REPORT")
        print("=" * 50)

        # Missing values
        missing = X.isnull().sum()
        if missing.any():
            print("\n[!] Features with missing values:")
            print(missing[missing > 0])
        else:
            print("\n[✓] No missing values detected.")

        # Zero-variance features
        variances = X.var()
        zero_var  = variances[variances == 0].index.tolist()
        if zero_var:
            print(f"\n[!] Zero-variance features (should be removed): {zero_var}")
        else:
            print("[✓] No zero-variance features.")

        # Descriptive stats
        print("\n[*] Per-feature statistics:")
        stats = X.describe().T
        stats["cv"] = stats["std"] / stats["mean"].abs().replace(0, np.nan)
        print(stats[["mean", "std", "min", "max", "cv"]].round(4).to_string())

        # Per-class box plots
        gran_tag = os.path.splitext(os.path.basename(self.dataset_path))[0]
        n_feats  = len(X.columns)
        n_cols   = 3
        n_rows   = (n_feats + n_cols - 1) // n_cols

        fig, axes = plt.subplots(n_rows, n_cols,
                                 figsize=(n_cols * 5, n_rows * 3.5))
        axes      = axes.flatten()

        df_plot = X.copy()
        df_plot["label"] = y.values

        for idx, feat in enumerate(X.columns):
            groups = [df_plot[df_plot["label"] == cls][feat].dropna()
                      for cls in sorted(y.unique())]
            axes[idx].boxplot(groups, labels=sorted(y.unique()), vert=True)
            axes[idx].set_title(feat, fontsize=8)
            axes[idx].tick_params(axis='x', rotation=45, labelsize=7)

        for j in range(idx + 1, len(axes)):
            axes[j].set_visible(False)

        plt.suptitle("Per-class feature distributions", fontsize=12, y=1.01)
        plt.tight_layout()
        path = os.path.join(self.reports_dir, f"feature_distributions_{gran_tag}.png")
        plt.savefig(path, dpi=150, bbox_inches="tight")
        plt.close()
        print(f"\n[+] Feature distribution plot saved → {path}")

        return variances

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_model(self, model_path):
        """Serialises model + metadata to disk."""
        if self.model is None:
            print("[!] No model to save — call train_and_evaluate() first.")
            return
        payload = {
            "model":         self.model,
            "label_encoder": self.label_encoder,
            "feature_names": self.feature_names,
        }
        joblib.dump(payload, model_path)
        print(f"[+] Model saved to: {model_path}")

    def load_model(self, model_path):
        """Loads a previously saved model payload."""
        payload          = joblib.load(model_path)
        self.model         = payload["model"]
        self.label_encoder = payload["label_encoder"]
        self.feature_names = payload["feature_names"]
        print(f"[+] Model loaded from: {model_path}")