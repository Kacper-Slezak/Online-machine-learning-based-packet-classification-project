import os
import pandas as pd

APP_TO_CLASS = {
    "spotify": "audio",
    "netflix": "video",
    "disney": "video",
    # "discord": "voice",
    # "chrome": "browsing",
}

DEFAULT_CLASS = "inne"


def extract_app_name(filename):
    return filename.split("_")[0].lower()


def map_label(app):
    return APP_TO_CLASS.get(app, DEFAULT_CLASS)


def load_all_data(folder):
    dfs = []

    for file in os.listdir(folder):
        if file.endswith("_features.csv"):
            path = os.path.join(folder, file)

            df = pd.read_csv(path)

            app = extract_app_name(file)
            df["app_name"] = app
            df["label"] = map_label(app)

            dfs.append(df)

    return pd.concat(dfs, ignore_index=True)


def save_dataset(df, path="dataset.csv"):
    df.to_csv(path, index=False)
    print(f"[OK] Dataset saved: {path}")


if __name__ == "__main__":
    df = load_all_data("/folder_with_data") # folder with data
    save_dataset(df)