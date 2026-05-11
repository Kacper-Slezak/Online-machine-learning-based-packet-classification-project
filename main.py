# main.py

import os
import sys

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from config import DATA_RAW_DIR, DATA_CSV_DIR, MODELS_DIR, GRANULARITIES

from preprocessing.feature_extractor import FlowFeatureExtractor
from models.rf_trainer import RandomForestTrainer


def _ensure_dirs():
    for d in [DATA_RAW_DIR, DATA_CSV_DIR, MODELS_DIR, "reports"]:
        os.makedirs(d, exist_ok=True)


def _list_files(directory, ext=None):
    try:
        files = os.listdir(directory)
        if ext:
            files = [f for f in files if f.endswith(ext)]
        return sorted(files)
    except FileNotFoundError:
        return []


def menu_collect():
    app = input("Enter process name (e.g. spotify, firefox): ").strip()
    print(f"[*] Starting sniffer for '{app}'… (sniffing/sniffer_training.py — IN PROGRESS)")
    # sniffer = SnifferTraining(app)
    # sniffer.start()


def menu_extract():
    files = _list_files(DATA_RAW_DIR)
    if not files:
        print(f"[!] No files found in {DATA_RAW_DIR}. "
              "Use option 1 or place PCAP files there manually.")
        return

    print(f"\nAvailable files in {DATA_RAW_DIR}:")
    for f in files:
        print(f"  - {f}")

    pcap_file = input("\nEnter PCAP filename to process: ").strip()
    label     = input("Traffic class label (e.g. Spotify, YouTube, VoIP): ").strip()
    pcap_path = os.path.join(DATA_RAW_DIR, pcap_file)

    if not os.path.exists(pcap_path):
        print(f"[!] File not found: {pcap_path}")
        return

    print(f"\n[*] Extracting features for granularities: {GRANULARITIES}")
    for gran in GRANULARITIES:
        output_csv = os.path.join(DATA_CSV_DIR, f"rf_dataset_{gran}.csv")
        extractor  = FlowFeatureExtractor(pcap_path, label, granularity=gran)
        extractor.process_and_save(output_csv)

    print("\n[+] Feature extraction completed.")


def menu_validate_features():
    """Run feature-quality checks before training."""
    csv_files = _list_files(DATA_CSV_DIR, ext=".csv")
    if not csv_files:
        print(f"[!] No CSV files found in {DATA_CSV_DIR}. Run extraction first.")
        return

    print(f"\nAvailable datasets in {DATA_CSV_DIR}:")
    for i, f in enumerate(csv_files, 1):
        print(f"  {i}. {f}")

    choice = input("Select dataset number (or 'all'): ").strip()

    if choice.lower() == "all":
        selected = [os.path.join(DATA_CSV_DIR, f) for f in csv_files]
    else:
        try:
            idx = int(choice) - 1
            selected = [os.path.join(DATA_CSV_DIR, csv_files[idx])]
        except (ValueError, IndexError):
            print("[!] Invalid selection.")
            return

    for csv_path in selected:
        print(f"\n{'=' * 60}")
        print(f" Validating: {os.path.basename(csv_path)}")
        print("=" * 60)
        trainer = RandomForestTrainer(csv_path, reports_dir="reports")
        trainer.validate_features()


def menu_train():
    """Training sweep across all granularities with full evaluation."""
    print("\n[*] Starting training sweep across all granularities…")
    results = {}

    for gran in GRANULARITIES:
        csv_path = os.path.join(DATA_CSV_DIR, f"rf_dataset_{gran}.csv")
        if not os.path.exists(csv_path):
            print(f"[!] Dataset not found for granularity {gran}: {csv_path}")
            continue

        print(f"\n{'─' * 50}")
        print(f"  GRANULARITY: {gran} packets")
        print("─" * 50)

        trainer  = RandomForestTrainer(csv_path, reports_dir="reports")
        accuracy = trainer.train_and_evaluate()

        if accuracy is not None:
            results[gran] = accuracy
            model_path = os.path.join(MODELS_DIR, f"rf_model_{gran}.pkl")
            trainer.save_model(model_path)

    # ---- Summary table -----------------------------------------------
    if not results:
        print("\n[!] No models were trained (no datasets found).")
        return

    print("\n" + "=" * 50)
    print(" GRANULARITY EXPERIMENT SUMMARY")
    print("=" * 50)
    for g, acc in sorted(results.items()):
        bar  = "█" * int(acc * 40)
        mark = " ◄ BEST" if g == max(results, key=results.get) else ""
        print(f"  Gran {g:4d} pkt  {acc * 100:6.2f}%  {bar}{mark}")

    best = max(results, key=results.get)
    print(f"\n  Best granularity: {best} packets  ({results[best] * 100:.2f}%)")
    print("=" * 50)

    # ---- Granularity comparison plot --------------------------------
    grans   = sorted(results.keys())
    accs    = [results[g] * 100 for g in grans]

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.plot(grans, accs, marker="o", color="#2196F3", linewidth=2)
    ax.fill_between(grans, accs, alpha=0.15, color="#2196F3")
    ax.set_xlabel("Granularity (packets per window)")
    ax.set_ylabel("Test Accuracy (%)")
    ax.set_title("Accuracy vs. Granularity")
    ax.grid(True, alpha=0.3)
    for g, a in zip(grans, accs):
        ax.annotate(f"{a:.1f}%", (g, a), textcoords="offset points",
                    xytext=(0, 8), ha="center", fontsize=8)
    plt.tight_layout()
    plot_path = os.path.join("reports", "granularity_comparison.png")
    plt.savefig(plot_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"\n[+] Granularity comparison chart saved → {plot_path}")


def menu():
    """Main interactive menu — entry point for all pipeline stages."""
    _ensure_dirs()

    while True:
        print("\n" + "=" * 55)
        print("  ML NETWORK TRAFFIC CLASSIFIER — MAIN MENU")
        print("=" * 55)
        print("  1. Collect training data      (Sniffer → PCAP)")
        print("  2. Extract features           (PCAP → CSV)")
        print("  3. Validate features          (feature quality report)")
        print("  4. Train model                (Random Forest, all granularities)")
        print("  5. [TODO] Online classification (RF)")
        print("  6. [TODO] Launch GUI")
        print("  0. Exit")

        choice = input("\nSelect an option: ").strip()

        if   choice == '1': menu_collect()
        elif choice == '2': menu_extract()
        elif choice == '3': menu_validate_features()
        elif choice == '4': menu_train()
        elif choice == '5': print("[!] Online classification not yet implemented.")
        elif choice == '6': print("[!] GUI not yet implemented.")
        elif choice == '0':
            print("Goodbye!")
            sys.exit(0)
        else:
            print("[!] Unknown option — please enter a valid number.")


if __name__ == "__main__":
    menu()