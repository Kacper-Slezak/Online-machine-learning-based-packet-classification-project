import os
import sys

from config import DATA_RAW_DIR, DATA_CSV_DIR, MODELS_DIR, GRANULARITIES
from preprocessing.feature_extractor import FlowFeatureExtractor
from models.rf_trainer import RandomForestTrainer
from utils.filesystem import ensure_dirs, list_files
from visualization.granularity_plots import plot_granularity_results


def menu_collect():
    app = input("Enter process name (e.g. spotify, firefox): ").strip()
    print(f"[*] Starting sniffer for '{app}'… (sniffing/sniffer_training.py — IN PROGRESS)")
    # sniffer = SnifferTraining(app)
    # sniffer.start()


def menu_extract():
    files = list_files(DATA_RAW_DIR)

    if not files:
        print(f"[!] No files found in {DATA_RAW_DIR}. Use option 1 or place PCAP files there manually.")
        return

    print(f"\nAvailable files in {DATA_RAW_DIR}:")
    for f in files:
        print(f"  - {f}")

    pcap_file = input("\nEnter PCAP filename to process: ").strip()
    label = input("Traffic class label (e.g. Spotify, YouTube, VoIP): ").strip()

    pcap_path = os.path.join(DATA_RAW_DIR, pcap_file)

    if not os.path.exists(pcap_path):
        print(f"[!] File not found: {pcap_path}")
        return

    print(f"\n[*] Extracting features for granularities: {GRANULARITIES}")

    for gran in GRANULARITIES:
        output_csv = os.path.join(DATA_CSV_DIR, f"rf_dataset_{gran}.csv")
        extractor = FlowFeatureExtractor(pcap_path, label, granularity=gran)
        extractor.process_and_save(output_csv)

    print("\n[+] Feature extraction completed.")


def menu_validate_features():
    csv_files = list_files(DATA_CSV_DIR, ext=".csv")

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

        trainer = RandomForestTrainer(csv_path, reports_dir="reports")
        accuracy = trainer.train_and_evaluate()

        if accuracy is not None:
            results[gran] = accuracy
            model_path = os.path.join(MODELS_DIR, f"rf_model_{gran}.pkl")
            trainer.save_model(model_path)

    if not results:
        print("\n[!] No models were trained (no datasets found).")
        return

    print("\n" + "=" * 50)
    print(" GRANULARITY EXPERIMENT SUMMARY")
    print("=" * 50)

    for g, acc in sorted(results.items()):
        bar = "█" * int(acc * 40)
        mark = " ◄ BEST" if g == max(results, key=results.get) else ""
        print(f"  Gran {g:4d} pkt  {acc * 100:6.2f}%  {bar}{mark}")

    best = max(results, key=results.get)
    print(f"\n  Best granularity: {best} packets  ({results[best] * 100:.2f}%)")
    print("=" * 50)

    plot_granularity_results(results)


def menu():
    ensure_dirs(DATA_RAW_DIR, DATA_CSV_DIR, MODELS_DIR, "reports")

    while True:
        print("\n" + "=" * 55)
        print("  ML NETWORK TRAFFIC CLASSIFIER — MAIN MENU")
        print("=" * 55)
        print("  1. Collect training data      (Sniffer → PCAP)")
        print("  2. Extract features           (PCAP → CSV)")
        print("  3. Validate features          (feature quality report)")
        print("  4. Train model                (Random Forest)")
        print("  5. [TODO] Online classification")
        print("  6. [TODO] Launch GUI")
        print("  0. Exit")

        choice = input("\nSelect an option: ").strip()

        if choice == '1':
            menu_collect()
        elif choice == '2':
            menu_extract()
        elif choice == '3':
            menu_validate_features()
        elif choice == '4':
            menu_train()
        elif choice == '5':
            print("[!] Online classification not yet implemented.")
        elif choice == '6':
            print("[!] GUI not yet implemented.")
        elif choice == '0':
            print("Goodbye!")
            sys.exit(0)
        else:
            print("[!] Unknown option — please enter a valid number.")


if __name__ == "__main__":
    menu()