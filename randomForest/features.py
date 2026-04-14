import pandas as pd


def preprocess(df: pd.DataFrame):
    df = df.copy()

    # removing some columns to prevent overfitting
    df = df.drop(columns=[
        "src_ip",
        "dst_ip",
        "flow_id",
        "app_name"
    ], errors="ignore")

    # encoding
    df["direction"] = df["direction"].map({"out": 1, "in": 0})
    df["protocol"] = df["protocol"].map({"TCP": 1, "UDP": 0})

    df = df.fillna(0)

    return df


def aggregate_flows(df: pd.DataFrame):
    grouped = df.groupby("flow_id")

    agg = grouped.agg({
        "pkt_len": ["mean", "std", "max"],
        "payload_len": ["mean", "sum"],
        "inter_arrival_ms": ["mean", "std"],
        "tcp_window": ["mean"],
        "tcp_flags": ["mean"],
        "direction": ["mean"],
        "protocol": ["mean"],
    })

    agg.columns = ["_".join(col) for col in agg.columns]

    # label (ważne)
    agg["label"] = grouped["label"].first()

    return agg.reset_index(drop=True)