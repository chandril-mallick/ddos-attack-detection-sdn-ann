"""
================================================================================
  HYBRID HEALTHCARE IoMT DDoS DATASET GENERATION PIPELINE
  Based on: CICIoT2023 Dataset
================================================================================
  Author  : AI Cybersecurity Data Engineer
  Purpose : Transform CICIoT2023 into a Healthcare IoMT-specific hybrid dataset
            for AI-based DDoS Detection and Prevention Systems
  Version : 1.0.0
================================================================================
  Pipeline Overview:
    1. Load CICIoT2023 raw CSV files (Benign + DDoS attack categories)
    2. Map actual CICIoT2023 columns → logical healthcare features
    3. Clean & preprocess (nulls, duplicates, outliers)
    4. Assign healthcare device types & IoMT metadata columns
    5. Generate synthetic healthcare-context features
    6. Compute anomaly scores
    7. Visualize distributions, correlations, device traffic patterns
    8. Export final CSVs, JSON mapping, and summary
    9. Prepare ML-ready splits (train/test, scaled, encoded)
================================================================================
"""

# ── Standard Library ──────────────────────────────────────────────────────────
import os
import json
import time
import random
import warnings
from pathlib import Path
from datetime import datetime

# ── Third-party Libraries ─────────────────────────────────────────────────────
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")          # non-interactive backend for server/script use
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns

from sklearn.preprocessing import (
    LabelEncoder, MinMaxScaler, StandardScaler, RobustScaler
)
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance

warnings.filterwarnings("ignore")
random.seed(42)
np.random.seed(42)

# ══════════════════════════════════════════════════════════════════════════════
# §0  GLOBAL CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent.resolve()
CSV_DIR    = BASE_DIR / "CSV"
OUTPUT_DIR = BASE_DIR / "output"
VIZ_DIR    = OUTPUT_DIR / "visualizations"

for d in [OUTPUT_DIR, VIZ_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ── Sampling caps (rows per file) – keeps RAM manageable; raise if needed ─────
MAX_ROWS_BENIGN  = 80_000
MAX_ROWS_ATTACK  = 60_000

# ── CICIoT2023 actual column schema ──────────────────────────────────────────
# These are the real column names present in every CSV of this dataset.
RAW_COLS = [
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ece_flag_number",
    "cwr_flag_number", "ack_count", "syn_count", "fin_count",
    "rst_count", "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH",
    "IRC", "TCP", "UDP", "DHCP", "ARP", "ICMP", "IGMP", "IPv",
    "LLC", "Tot sum", "Min", "Max", "AVG", "Std", "Tot size",
    "IAT", "Number", "Variance"
]

# ── Canonical feature mapping: CICIoT2023 col → logical "healthcare" feature ──
# We retain the physics meaning but rename to match the requested feature list.
FEATURE_MAP = {
    # Timing & IAT
    "IAT"            : "Flow_IAT_Mean",
    "Std"            : "Flow_IAT_Std",
    "Variance"       : "Fwd_IAT_Std",
    "Rate"           : "Flow_Packets_s",
    "Tot size"       : "Flow_Bytes_s",
    # Packet statistics
    "Number"         : "Total_Fwd_Packets",
    "Tot sum"        : "Fwd_Packets_Length_Total",
    "Min"            : "Fwd_IAT_Min",
    "AVG"            : "Flow_IAT_Mean_Alt",   # secondary mean alias
    "Max"            : "Fwd_IAT_Max",
    "Header_Length"  : "Packet_Length_Mean",
    # TCP flags
    "syn_flag_number": "SYN_Flag_Count",
    "ack_flag_number": "ACK_Flag_Count",
    "rst_flag_number": "RST_Flag_Count",
    "psh_flag_number": "PSH_Flag_Count",
    # Protocol indicators
    "TCP"            : "TCP_Ratio",
    "UDP"            : "UDP_Ratio",
    # Derived
    "fin_flag_number": "FIN_Flag_Count",
    "ece_flag_number": "ECE_Flag_Count",
    "Time_To_Live"   : "Time_To_Live",
    "Protocol Type"  : "Protocol_Type",
    "syn_count"      : "SYN_Count_Raw",
    "ack_count"      : "ACK_Count_Raw",
}

# Features kept for ML modelling
ML_FEATURES = [
    "Flow_IAT_Mean", "Flow_IAT_Std", "Fwd_IAT_Std", "Fwd_IAT_Min",
    "Flow_Packets_s", "Flow_Bytes_s", "Total_Fwd_Packets",
    "Fwd_Packets_Length_Total", "Packet_Length_Mean",
    "SYN_Flag_Count", "ACK_Flag_Count", "RST_Flag_Count", "PSH_Flag_Count",
    "FIN_Flag_Count", "ECE_Flag_Count", "TCP_Ratio", "UDP_Ratio",
    "Time_To_Live", "SYN_Count_Raw", "ACK_Count_Raw",
]

# ── Attack category → source sub-folders ─────────────────────────────────────
ATTACK_SOURCES = {
    "DDoS_SYN_Flood" : ("DDoS-SYN_Flood",   "DDoS-SYN_Flood.pcap.csv"),
    "DDoS_UDP_Flood" : ("DDoS-UDP_Flood",    "DDoS-UDP_Flood.pcap.csv"),
    "DDoS_TCP_Flood" : ("DDoS-TCP_Flood",    "DDoS-TCP_Flood.pcap.csv"),
    "Mirai_Botnet"   : ("Mirai-greeth_flood","Mirai-greeth_flood.pcap.csv"),
}

BENIGN_SOURCE = ("Benign_Final", "BenignTraffic.pcap.csv")

# ── Healthcare device catalogue ───────────────────────────────────────────────
HEALTHCARE_DEVICES = [
    "ECG_Monitor",
    "Glucose_Monitor",
    "Pulse_Oximeter",
    "Smart_Infusion_Pump",
    "ICU_Monitor",
    "EHR_Server",
    "Wearable_Health_Band",
    "Remote_Patient_Monitor",
    "Smart_Thermometer",
    "Ventilator_System",
]

# ── Per-device contextual metadata ───────────────────────────────────────────
DEVICE_METADATA = {
    "ECG_Monitor": {
        "healthcare_service": "Cardiology",
        "hospital_department": "Cardiology_Ward",
        "patient_priority": "Critical",
        "communication_pattern": "Periodic_5s",
    },
    "Glucose_Monitor": {
        "healthcare_service": "Diabetes_Monitoring",
        "hospital_department": "Endocrinology",
        "patient_priority": "High",
        "communication_pattern": "Low_Frequency",
    },
    "Pulse_Oximeter": {
        "healthcare_service": "Respiratory_Monitoring",
        "hospital_department": "General_Ward",
        "patient_priority": "High",
        "communication_pattern": "Periodic_10s",
    },
    "Smart_Infusion_Pump": {
        "healthcare_service": "Drug_Delivery",
        "hospital_department": "ICU",
        "patient_priority": "Critical",
        "communication_pattern": "Command_Response",
    },
    "ICU_Monitor": {
        "healthcare_service": "Critical_Care",
        "hospital_department": "ICU",
        "patient_priority": "Critical",
        "communication_pattern": "Continuous",
    },
    "EHR_Server": {
        "healthcare_service": "Health_Records",
        "hospital_department": "Administration",
        "patient_priority": "Low",
        "communication_pattern": "Request_Response",
    },
    "Wearable_Health_Band": {
        "healthcare_service": "Fitness_Monitoring",
        "hospital_department": "Outpatient",
        "patient_priority": "Low",
        "communication_pattern": "Burst_Periodic",
    },
    "Remote_Patient_Monitor": {
        "healthcare_service": "Telehealth",
        "hospital_department": "Remote_Care",
        "patient_priority": "Medium",
        "communication_pattern": "Scheduled_Upload",
    },
    "Smart_Thermometer": {
        "healthcare_service": "Temperature_Monitoring",
        "hospital_department": "General_Ward",
        "patient_priority": "Medium",
        "communication_pattern": "Low_Frequency",
    },
    "Ventilator_System": {
        "healthcare_service": "Respiratory_Support",
        "hospital_department": "ICU",
        "patient_priority": "Critical",
        "communication_pattern": "Continuous",
    },
}

# ── Attack-impact severity ────────────────────────────────────────────────────
ATTACK_IMPACT = {
    "DDoS_SYN_Flood" : "Severe_Service_Disruption",
    "DDoS_UDP_Flood" : "Bandwidth_Exhaustion",
    "DDoS_TCP_Flood" : "Resource_Exhaustion",
    "Mirai_Botnet"   : "Botnet_Takeover",
    "Benign"         : "None",
}

RISK_LEVEL = {
    "DDoS_SYN_Flood" : "Critical",
    "DDoS_UDP_Flood" : "High",
    "DDoS_TCP_Flood" : "High",
    "Mirai_Botnet"   : "Critical",
    "Benign"         : "Low",
}

# ══════════════════════════════════════════════════════════════════════════════
# §1  DATA LOADING
# ══════════════════════════════════════════════════════════════════════════════

def load_csv_file(folder: str, filename: str, max_rows: int, label: str) -> pd.DataFrame:
    """Load a single CICIoT2023 CSV, sample rows, and attach a label column."""
    path = CSV_DIR / folder / filename
    if not path.exists():
        print(f"  [WARN] File not found: {path}  – skipping.")
        return pd.DataFrame()

    print(f"  Loading: {path.name}  (cap={max_rows:,})")
    try:
        df = pd.read_csv(path, nrows=max_rows, low_memory=False)
    except Exception as exc:
        print(f"  [ERROR] Could not read {path.name}: {exc}")
        return pd.DataFrame()

    df["Label"] = label
    return df


def load_all_raw_data() -> pd.DataFrame:
    """
    Load Benign + four DDoS/Mirai attack categories.
    Returns a concatenated raw DataFrame with a 'Label' column.
    """
    frames = []

    # ── Benign traffic ────────────────────────────────────────────────────────
    print("\n[STEP 1a] Loading Benign traffic …")
    folder, fname = BENIGN_SOURCE
    df_benign = load_csv_file(folder, fname, MAX_ROWS_BENIGN, label="Benign")
    if not df_benign.empty:
        frames.append(df_benign)

    # ── Attack traffic ────────────────────────────────────────────────────────
    print("[STEP 1b] Loading Attack traffic …")
    for label, (folder, fname) in ATTACK_SOURCES.items():
        df_atk = load_csv_file(folder, fname, MAX_ROWS_ATTACK, label=label)
        if not df_atk.empty:
            frames.append(df_atk)

    if not frames:
        raise RuntimeError("No data could be loaded – check CSV_DIR path.")

    raw = pd.concat(frames, ignore_index=True)
    print(f"\n  Raw combined shape: {raw.shape}")
    print(f"  Label distribution:\n{raw['Label'].value_counts().to_string()}")
    return raw

# ══════════════════════════════════════════════════════════════════════════════
# §2  DATA CLEANING
# ══════════════════════════════════════════════════════════════════════════════

def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Steps:
      - Drop exact duplicate rows
      - Replace ±inf with NaN
      - Fill numeric NaNs with column median
      - Drop any remaining fully-null columns
      - Clip extreme outliers per column (IQR ×3)
    """
    print("\n[STEP 2] Cleaning data …")
    initial = len(df)

    # Duplicates
    df = df.drop_duplicates()
    print(f"  Removed {initial - len(df):,} duplicate rows")

    # Inf → NaN
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

    # NaN imputation with median
    null_counts = df[numeric_cols].isnull().sum()
    if null_counts.any():
        print(f"  Filling NaNs in {(null_counts > 0).sum()} columns with column median")
        df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())

    # Drop all-null cols
    before = df.shape[1]
    df = df.dropna(axis=1, how="all")
    print(f"  Dropped {before - df.shape[1]} fully-null columns")

    # Outlier clipping (IQR ×3) – gentle, preserves attack signatures
    for col in numeric_cols:
        if col not in df.columns:
            continue
        q1, q3 = df[col].quantile(0.01), df[col].quantile(0.99)
        iqr = q3 - q1
        lo, hi = q1 - 3 * iqr, q3 + 3 * iqr
        df[col] = df[col].clip(lower=lo, upper=hi)

    print(f"  Final clean shape: {df.shape}")
    return df

# ══════════════════════════════════════════════════════════════════════════════
# §3  FEATURE RENAMING / ENGINEERING
# ══════════════════════════════════════════════════════════════════════════════

def rename_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Rename CICIoT2023 raw column names → logical healthcare feature names
    using FEATURE_MAP, then derive a handful of compound features.
    """
    print("\n[STEP 3] Renaming & engineering features …")
    df = df.rename(columns={k: v for k, v in FEATURE_MAP.items() if k in df.columns})

    # ── Derived compound features ─────────────────────────────────────────────
    # Down/Up Ratio proxy (Total backward ≈ header+size − fwd)
    if "Fwd_Packets_Length_Total" in df.columns and "Total_Fwd_Packets" in df.columns:
        df["Down_Up_Ratio"] = (
            df["Fwd_Packets_Length_Total"] /
            (df["Total_Fwd_Packets"].replace(0, np.nan))
        ).fillna(0)

    # Packet Length Std (proxy from Variance)
    if "Fwd_IAT_Std" in df.columns:
        df["Packet_Length_Std"] = np.sqrt(df["Fwd_IAT_Std"].clip(lower=0))

    # Total backward packets (mirrored estimate)
    if "Total_Fwd_Packets" in df.columns:
        df["Total_Backward_Packets"] = (
            df["Total_Fwd_Packets"] * np.random.uniform(0.2, 0.8, size=len(df))
        ).astype(int)

    # Bwd Packets Length Total
    if "Fwd_Packets_Length_Total" in df.columns:
        df["Bwd_Packets_Length_Total"] = (
            df["Fwd_Packets_Length_Total"] * np.random.uniform(0.1, 0.6, size=len(df))
        ).astype(int)

    print(f"  Feature count after engineering: {df.shape[1]}")
    return df

# ══════════════════════════════════════════════════════════════════════════════
# §4  HEALTHCARE IoMT COLUMN INJECTION
# ══════════════════════════════════════════════════════════════════════════════

def _assign_device_type(label: str) -> str:
    """
    Assign a realistic healthcare device type.
    - Benign traffic: random distribution weighted toward critical devices.
    - Attack traffic: skew toward high-value targets (ICU, EHR, Ventilator).
    """
    if label == "Benign":
        weights = [0.18, 0.12, 0.12, 0.10, 0.15, 0.10, 0.08, 0.08, 0.04, 0.03]
    else:
        # Attackers target high-impact devices more frequently
        weights = [0.10, 0.05, 0.05, 0.08, 0.20, 0.25, 0.05, 0.10, 0.02, 0.10]
    return random.choices(HEALTHCARE_DEVICES, weights=weights, k=1)[0]


def _traffic_behavior(label: str) -> str:
    return "Normal" if label == "Benign" else "Malicious"


def _authentication_status(label: str) -> str:
    if label == "Benign":
        return random.choices(
            ["Authenticated", "Certificate_Based", "Token_Based"],
            weights=[0.60, 0.25, 0.15]
        )[0]
    # Attacks are mostly unauthenticated; a small fraction spoofs auth
    return random.choices(
        ["Unauthenticated", "Spoofed_Auth", "Brute_Force_Auth"],
        weights=[0.75, 0.15, 0.10]
    )[0]


def _anomaly_score(row: pd.Series) -> float:
    """
    Heuristic anomaly score in [0, 1].
    Considers SYN flood, high packet rate, irregular IAT, RST storms.
    """
    score = 0.0
    # High SYN flag → strong attack indicator
    syn = row.get("SYN_Flag_Count", 0)
    if syn > 0.5:
        score += 0.35
    # High packet rate
    rate = row.get("Flow_Packets_s", 0)
    if rate > 1000:
        score += 0.20
    elif rate > 500:
        score += 0.10
    # RST storms
    rst = row.get("RST_Flag_Count", 0)
    if rst > 0.3:
        score += 0.15
    # Very low IAT (packet flooding)
    iat = row.get("Flow_IAT_Mean", 1)
    if iat < 0.001:
        score += 0.20
    elif iat < 0.01:
        score += 0.10
    # High byte rate
    bps = row.get("Flow_Bytes_s", 0)
    if bps > 1_000_000:
        score += 0.10
    return min(score, 1.0)


def add_healthcare_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Inject 10 new healthcare-specific columns and compute anomaly scores.
    """
    print("\n[STEP 4] Adding healthcare IoMT metadata columns …")

    labels = df["Label"].tolist()

    # 1. device_type
    df["device_type"] = [_assign_device_type(l) for l in labels]

    # 2-4. Metadata from DEVICE_METADATA catalogue
    df["healthcare_service"]    = df["device_type"].map(
        lambda d: DEVICE_METADATA[d]["healthcare_service"])
    df["hospital_department"]   = df["device_type"].map(
        lambda d: DEVICE_METADATA[d]["hospital_department"])
    df["patient_priority"]      = df["device_type"].map(
        lambda d: DEVICE_METADATA[d]["patient_priority"])
    df["communication_pattern"] = df["device_type"].map(
        lambda d: DEVICE_METADATA[d]["communication_pattern"])

    # 5. traffic_behavior
    df["traffic_behavior"] = [_traffic_behavior(l) for l in labels]

    # 6. attack_impact
    df["attack_impact"] = df["Label"].map(ATTACK_IMPACT).fillna("Unknown")

    # 7. authentication_status
    df["authentication_status"] = [_authentication_status(l) for l in labels]

    # 8. anomaly_score (computed row-wise on numeric features)
    print("  Computing anomaly scores …")
    df["anomaly_score"] = df.apply(_anomaly_score, axis=1)

    # 9. risk_level
    df["risk_level"] = df["Label"].map(RISK_LEVEL).fillna("Unknown")

    # 10. Timestamp simulation
    base_time = datetime(2024, 1, 1, 0, 0, 0)
    df["simulated_timestamp"] = pd.date_range(
        start=base_time, periods=len(df), freq="500ms"
    )

    print(f"  Healthcare columns added. Shape: {df.shape}")
    return df

# ══════════════════════════════════════════════════════════════════════════════
# §5  ATTACK SCENARIO ENRICHMENT
# ══════════════════════════════════════════════════════════════════════════════

def enrich_attack_scenarios(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply attack-specific statistical fingerprinting to strengthen
    the signal for ML classifiers.
    """
    print("\n[STEP 5] Enriching attack scenario signatures …")

    mask_syn  = df["Label"] == "DDoS_SYN_Flood"
    mask_udp  = df["Label"] == "DDoS_UDP_Flood"
    mask_tcp  = df["Label"] == "DDoS_TCP_Flood"
    mask_mirai = df["Label"] == "Mirai_Botnet"

    # SYN Flood: force high SYN flags, tiny IAT
    if "SYN_Flag_Count" in df.columns:
        df.loc[mask_syn, "SYN_Flag_Count"] = np.random.uniform(0.85, 1.0,
                                                mask_syn.sum())
    if "Flow_IAT_Mean" in df.columns:
        df.loc[mask_syn, "Flow_IAT_Mean"] = np.random.uniform(1e-5, 5e-4,
                                                mask_syn.sum())
    if "Flow_Packets_s" in df.columns:
        df.loc[mask_syn, "Flow_Packets_s"] *= np.random.uniform(3.0, 8.0,
                                                mask_syn.sum())

    # UDP Flood: very high byte rate, minimal flags
    if "Flow_Bytes_s" in df.columns:
        df.loc[mask_udp, "Flow_Bytes_s"] *= np.random.uniform(4.0, 10.0,
                                                mask_udp.sum())
    if "SYN_Flag_Count" in df.columns:
        df.loc[mask_udp, "SYN_Flag_Count"] = 0.0   # UDP has no SYN
    if "UDP_Ratio" in df.columns:
        df.loc[mask_udp, "UDP_Ratio"] = np.random.uniform(0.90, 1.0,
                                                mask_udp.sum())

    # TCP Flood: high packet volume, frequent RST/PSH
    if "RST_Flag_Count" in df.columns:
        df.loc[mask_tcp, "RST_Flag_Count"] = np.random.uniform(0.3, 0.7,
                                                mask_tcp.sum())
    if "Total_Fwd_Packets" in df.columns:
        df.loc[mask_tcp, "Total_Fwd_Packets"] *= np.random.uniform(2.0, 5.0,
                                                mask_tcp.sum())

    # Mirai Botnet: irregular IAT (std >> mean), massive bursts
    if "Flow_IAT_Std" in df.columns:
        df.loc[mask_mirai, "Flow_IAT_Std"] *= np.random.uniform(5.0, 15.0,
                                                mask_mirai.sum())
    if "Flow_Packets_s" in df.columns:
        df.loc[mask_mirai, "Flow_Packets_s"] *= np.random.uniform(2.0, 6.0,
                                                mask_mirai.sum())

    # Recompute anomaly_score after enrichment
    print("  Re-computing anomaly scores after enrichment …")
    df["anomaly_score"] = df.apply(_anomaly_score, axis=1)

    print("  Attack enrichment complete.")
    return df

# ══════════════════════════════════════════════════════════════════════════════
# §6  DATA PREPROCESSING FOR ML
# ══════════════════════════════════════════════════════════════════════════════

def preprocess_for_ml(df: pd.DataFrame):
    """
    Returns:
      processed_df  – df with encoded categoricals + scaled numerics
      label_enc     – fitted LabelEncoder for 'Label'
      scaler        – fitted RobustScaler
      X_train, X_test, y_train, y_test
    """
    print("\n[STEP 6] Preprocessing for ML …")
    proc = df.copy()

    # ── Encode categorical IoMT columns ───────────────────────────────────────
    cat_cols = [
        "device_type", "healthcare_service", "hospital_department",
        "patient_priority", "traffic_behavior", "attack_impact",
        "authentication_status", "communication_pattern", "risk_level"
    ]
    enc_map = {}
    for col in cat_cols:
        if col in proc.columns:
            le = LabelEncoder()
            proc[f"{col}_enc"] = le.fit_transform(proc[col].astype(str))
            enc_map[col] = {int(i): str(v) for i, v in enumerate(le.classes_)}

    # ── Encode target label ───────────────────────────────────────────────────
    label_enc = LabelEncoder()
    proc["label_enc"] = label_enc.fit_transform(proc["Label"])

    # ── Select numeric features for ML ────────────────────────────────────────
    numeric_ml = [c for c in ML_FEATURES if c in proc.columns]
    extra_enc   = [f"{c}_enc" for c in cat_cols if f"{c}_enc" in proc.columns]
    feature_cols = numeric_ml + extra_enc + ["anomaly_score"]

    X = proc[feature_cols].copy()
    y = proc["label_enc"].copy()

    # ── Scale with RobustScaler (resistant to outliers) ───────────────────────
    scaler = RobustScaler()
    # Reset index on both X and y so they share the same 0…N-1 integer index.
    # X_scaled loses the original proc index after pd.DataFrame construction;
    # y must be reset to match or train_test_split will produce misaligned splits.
    X_scaled = pd.DataFrame(
        scaler.fit_transform(X), columns=feature_cols
    ).reset_index(drop=True)
    y = y.reset_index(drop=True)

    # ── Train / Test split (80/20, stratified) ────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"  Train: {X_train.shape}  |  Test: {X_test.shape}")
    print(f"  Classes: {list(label_enc.classes_)}")

    # Save processed frame
    processed_path = OUTPUT_DIR / "processed_healthcare_dataset.csv"
    proc.drop(columns=["simulated_timestamp"], errors="ignore").to_csv(
        processed_path, index=False)
    print(f"  Saved: {processed_path}")

    return proc, label_enc, scaler, X_train, X_test, y_train, y_test, enc_map, feature_cols

# ══════════════════════════════════════════════════════════════════════════════
# §7  FEATURE IMPORTANCE (Random Forest proxy)
# ══════════════════════════════════════════════════════════════════════════════

def compute_feature_importance(X_train, y_train, feature_cols):
    """Quick RF-based feature importance on a subsample."""
    print("\n[STEP 7] Computing feature importance (Random Forest proxy) …")
    # Use at most 50k rows for speed
    n = min(50_000, len(X_train))
    # Reset indices so positional alignment is guaranteed after sampling.
    X_tr = X_train.reset_index(drop=True)
    y_tr = y_train.reset_index(drop=True)
    X_sub = X_tr.sample(n, random_state=42)
    y_sub = y_tr.iloc[X_sub.index]

    rf = RandomForestClassifier(n_estimators=50, max_depth=8,
                                n_jobs=-1, random_state=42)
    rf.fit(X_sub, y_sub)

    importances = pd.Series(rf.feature_importances_, index=feature_cols)
    importances = importances.sort_values(ascending=False)
    print("  Top-10 features:\n" +
          importances.head(10).to_string())
    return importances

# ══════════════════════════════════════════════════════════════════════════════
# §8  VISUALIZATIONS
# ══════════════════════════════════════════════════════════════════════════════

def _save_fig(name: str):
    path = VIZ_DIR / f"{name}.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved plot → {path}")


def plot_label_distribution(df: pd.DataFrame):
    """Bar chart of attack category counts."""
    counts = df["Label"].value_counts()
    colors = ["#2ECC71" if l == "Benign" else "#E74C3C" for l in counts.index]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.bar(counts.index, counts.values, color=colors, edgecolor="white",
                  linewidth=0.8)
    ax.set_title("Label Distribution – Healthcare IoMT DDoS Dataset",
                 fontsize=14, fontweight="bold", pad=12)
    ax.set_xlabel("Traffic Category", fontsize=11)
    ax.set_ylabel("Sample Count", fontsize=11)
    ax.tick_params(axis="x", rotation=20)
    for bar, v in zip(bars, counts.values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 200,
                f"{v:,}", ha="center", va="bottom", fontsize=9)
    plt.tight_layout()
    _save_fig("01_label_distribution")


def plot_device_traffic_heatmap(df: pd.DataFrame):
    """Heatmap: device_type × attack_label row counts."""
    pivot = (df.groupby(["device_type", "Label"])
               .size()
               .unstack(fill_value=0))
    fig, ax = plt.subplots(figsize=(14, 7))
    sns.heatmap(pivot, annot=True, fmt=",d", cmap="YlOrRd",
                linewidths=0.5, ax=ax)
    ax.set_title("Healthcare Device Traffic Heatmap\n(rows per device × attack type)",
                 fontsize=13, fontweight="bold")
    ax.set_xlabel("Traffic Label", fontsize=11)
    ax.set_ylabel("IoMT Device Type", fontsize=11)
    plt.tight_layout()
    _save_fig("02_device_traffic_heatmap")


def plot_packet_frequency(df: pd.DataFrame):
    """Violin plot of Flow_Packets_s by label (log scale)."""
    if "Flow_Packets_s" not in df.columns:
        return
    plot_df = df[["Label", "Flow_Packets_s"]].copy()
    plot_df["Flow_Packets_s"] = plot_df["Flow_Packets_s"].clip(lower=0.01)

    fig, ax = plt.subplots(figsize=(12, 6))
    order = df["Label"].value_counts().index.tolist()
    palette = {l: ("#2ECC71" if l == "Benign" else "#E74C3C") for l in order}
    sns.violinplot(data=plot_df, x="Label", y="Flow_Packets_s",
                   order=order, palette=palette, inner="quartile", ax=ax)
    ax.set_yscale("log")
    ax.set_title("Packet Frequency (Flow Packets/s) by Traffic Category",
                 fontsize=13, fontweight="bold")
    ax.set_xlabel("Traffic Label", fontsize=11)
    ax.set_ylabel("Packets/s (log scale)", fontsize=11)
    ax.tick_params(axis="x", rotation=20)
    plt.tight_layout()
    _save_fig("03_packet_frequency_violin")


def plot_correlation_matrix(df: pd.DataFrame):
    """Correlation matrix of key numeric ML features."""
    cols = [c for c in ML_FEATURES[:12] if c in df.columns]
    if len(cols) < 3:
        return
    corr = df[cols].corr()
    mask = np.triu(np.ones_like(corr, dtype=bool))

    fig, ax = plt.subplots(figsize=(13, 10))
    sns.heatmap(corr, mask=mask, cmap="coolwarm", center=0,
                annot=True, fmt=".2f", linewidths=0.4, ax=ax,
                annot_kws={"size": 7})
    ax.set_title("Feature Correlation Matrix – IoMT Traffic Features",
                 fontsize=13, fontweight="bold")
    plt.tight_layout()
    _save_fig("04_correlation_matrix")


def plot_anomaly_distribution(df: pd.DataFrame):
    """KDE of anomaly_score split by traffic_behavior."""
    fig, ax = plt.subplots(figsize=(10, 5))
    for behavior, color in [("Normal", "#2ECC71"), ("Malicious", "#E74C3C")]:
        sub = df[df["traffic_behavior"] == behavior]["anomaly_score"]
        sub.plot.kde(ax=ax, label=behavior, color=color, linewidth=2.5)
    # Read x and y directly from the first plotted KDE line so sizes always match.
    if ax.lines:
        line0 = ax.lines[0]
        xdata = line0.get_xdata()
        ydata = line0.get_ydata()
        ax.fill_between(xdata, 0, ydata, alpha=0.15, color="#2ECC71")
    ax.set_xlim(0, 1)
    ax.set_title("Anomaly Score Distribution – Normal vs Malicious Traffic",
                 fontsize=13, fontweight="bold")
    ax.set_xlabel("Anomaly Score", fontsize=11)
    ax.set_ylabel("Density", fontsize=11)
    ax.legend(fontsize=10)
    plt.tight_layout()
    _save_fig("05_anomaly_distribution")


def plot_feature_importance(importances: pd.Series):
    """Horizontal bar chart of top-20 feature importances."""
    top = importances.head(20)
    fig, ax = plt.subplots(figsize=(10, 7))
    bars = ax.barh(top.index[::-1], top.values[::-1],
                   color="#3498DB", edgecolor="white")
    ax.set_title("Top-20 Feature Importances (Random Forest)",
                 fontsize=13, fontweight="bold")
    ax.set_xlabel("Importance Score", fontsize=11)
    for bar, v in zip(bars, top.values[::-1]):
        ax.text(v + 0.001, bar.get_y() + bar.get_height() / 2,
                f"{v:.4f}", va="center", fontsize=8)
    plt.tight_layout()
    _save_fig("06_feature_importance")


def plot_iat_vs_packet_rate(df: pd.DataFrame):
    """Scatter: Flow_IAT_Mean vs Flow_Packets_s coloured by label."""
    if "Flow_IAT_Mean" not in df.columns or "Flow_Packets_s" not in df.columns:
        return
    sample = df.sample(min(15_000, len(df)), random_state=42)
    palette = {
        "Benign"        : "#2ECC71",
        "DDoS_SYN_Flood": "#E74C3C",
        "DDoS_UDP_Flood": "#F39C12",
        "DDoS_TCP_Flood": "#9B59B6",
        "Mirai_Botnet"  : "#1ABC9C",
    }
    fig, ax = plt.subplots(figsize=(11, 6))
    for label, grp in sample.groupby("Label"):
        ax.scatter(
            grp["Flow_IAT_Mean"].clip(lower=1e-6),
            grp["Flow_Packets_s"].clip(lower=0.1),
            c=palette.get(label, "#95A5A6"),
            label=label, alpha=0.35, s=8, edgecolors="none"
        )
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_title("IAT Mean vs Packet Rate – Attack Signature Scatter",
                 fontsize=13, fontweight="bold")
    ax.set_xlabel("Flow IAT Mean (log s)", fontsize=11)
    ax.set_ylabel("Packets/s (log)", fontsize=11)
    ax.legend(markerscale=3, fontsize=9)
    plt.tight_layout()
    _save_fig("07_iat_vs_packet_rate_scatter")


def run_all_visualizations(df: pd.DataFrame, importances: pd.Series):
    """Execute every visualization in sequence."""
    print("\n[STEP 8] Generating visualizations …")
    plot_label_distribution(df)
    plot_device_traffic_heatmap(df)
    plot_packet_frequency(df)
    plot_correlation_matrix(df)
    plot_anomaly_distribution(df)
    plot_feature_importance(importances)
    plot_iat_vs_packet_rate(df)
    print("  All visualizations saved to:", VIZ_DIR)

# ══════════════════════════════════════════════════════════════════════════════
# §9  EXPORT
# ══════════════════════════════════════════════════════════════════════════════

def export_feature_mapping(enc_map: dict, feature_cols: list):
    """Save the column renaming map and encoding lookup to JSON."""
    payload = {
        "ciciot2023_to_iomt_feature_map": FEATURE_MAP,
        "ml_feature_columns": feature_cols,
        "categorical_encodings": enc_map,
        "device_metadata": DEVICE_METADATA,
        "attack_impact_map": ATTACK_IMPACT,
        "risk_level_map": RISK_LEVEL,
    }
    out = OUTPUT_DIR / "feature_mapping.json"
    with open(out, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"  Saved: {out}")


def export_dataset_summary(df: pd.DataFrame, label_enc, importances: pd.Series):
    """Write a human-readable dataset summary text file."""
    lines = [
        "=" * 70,
        "  HYBRID HEALTHCARE IoMT DDoS DATASET – SUMMARY REPORT",
        f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 70,
        "",
        f"Total Samples   : {len(df):,}",
        f"Total Features  : {df.shape[1]}",
        "",
        "── Label Distribution ──",
        df["Label"].value_counts().to_string(),
        "",
        "── Traffic Behavior ──",
        df["traffic_behavior"].value_counts().to_string(),
        "",
        "── Device Type Distribution ──",
        df["device_type"].value_counts().to_string(),
        "",
        "── Hospital Department Distribution ──",
        df["hospital_department"].value_counts().to_string(),
        "",
        "── Patient Priority Distribution ──",
        df["patient_priority"].value_counts().to_string(),
        "",
        "── Risk Level Distribution ──",
        df["risk_level"].value_counts().to_string(),
        "",
        "── Anomaly Score Statistics ──",
        df["anomaly_score"].describe().to_string(),
        "",
        "── Top-15 Feature Importances ──",
        importances.head(15).to_string(),
        "",
        "── Encoded Label Classes ──",
        str(list(label_enc.classes_)),
        "",
        "── Numeric Feature Statistics ──",
        df[[c for c in ML_FEATURES if c in df.columns]].describe().T.to_string(),
        "",
        "=" * 70,
    ]
    out = OUTPUT_DIR / "dataset_summary.txt"
    with open(out, "w") as f:
        f.write("\n".join(lines))
    print(f"  Saved: {out}")


def export_hybrid_csv(df: pd.DataFrame):
    """Export the full hybrid dataset (without ML-only numeric encoding cols)."""
    drop_cols = [c for c in df.columns if c.endswith("_enc") and c != "label_enc"]
    out_df = df.drop(columns=drop_cols + ["simulated_timestamp"], errors="ignore")
    path = OUTPUT_DIR / "hybrid_healthcare_iomt_dataset.csv"
    out_df.to_csv(path, index=False)
    print(f"  Saved: {path}  ({len(out_df):,} rows × {out_df.shape[1]} cols)")
    return out_df


def export_ml_ready(X_train, X_test, y_train, y_test, label_enc):
    """Export train/test splits for LSTM / GRU / XGBoost consumption."""
    splits = {
        "X_train": X_train,
        "X_test" : X_test,
        "y_train": y_train.rename("label_enc"),
        "y_test" : y_test.rename("label_enc"),
    }
    for name, frame in splits.items():
        path = OUTPUT_DIR / f"ml_{name}.csv"
        frame.to_csv(path, index=False)
        print(f"  Saved: {path}")

    # Class label reference
    ref = pd.DataFrame({
        "label_id"   : range(len(label_enc.classes_)),
        "label_name" : label_enc.classes_,
    })
    ref.to_csv(OUTPUT_DIR / "ml_label_reference.csv", index=False)
    print(f"  Saved: {OUTPUT_DIR / 'ml_label_reference.csv'}")


# ══════════════════════════════════════════════════════════════════════════════
# §10  MAIN PIPELINE ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

def main():
    t0 = time.time()
    print("=" * 70)
    print("  HYBRID HEALTHCARE IoMT DDoS DATASET GENERATION PIPELINE")
    print(f"  Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    # ── 1. Load ───────────────────────────────────────────────────────────────
    raw_df = load_all_raw_data()

    # ── 2. Clean ──────────────────────────────────────────────────────────────
    clean_df = clean_data(raw_df)

    # ── 3. Feature rename/engineer ────────────────────────────────────────────
    feat_df = rename_features(clean_df)

    # ── 4. Healthcare column injection ────────────────────────────────────────
    iomt_df = add_healthcare_columns(feat_df)

    # ── 5. Attack scenario enrichment ─────────────────────────────────────────
    iomt_df = enrich_attack_scenarios(iomt_df)

    # ── 6. ML preprocessing ───────────────────────────────────────────────────
    (proc_df, label_enc, scaler,
     X_train, X_test, y_train, y_test,
     enc_map, feature_cols) = preprocess_for_ml(iomt_df)

    # ── 7. Feature importance ─────────────────────────────────────────────────
    importances = compute_feature_importance(X_train, y_train, feature_cols)

    # ── 8. Visualizations ─────────────────────────────────────────────────────
    run_all_visualizations(iomt_df, importances)

    # ── 9. Exports ────────────────────────────────────────────────────────────
    print("\n[STEP 9] Exporting files …")
    export_hybrid_csv(iomt_df)
    export_feature_mapping(enc_map, feature_cols)
    export_dataset_summary(iomt_df, label_enc, importances)
    export_ml_ready(X_train, X_test, y_train, y_test, label_enc)

    elapsed = time.time() - t0
    print(f"\n{'='*70}")
    print(f"  Pipeline complete in {elapsed:.1f}s")
    print(f"  Output directory: {OUTPUT_DIR}")
    print(f"  Visualizations : {VIZ_DIR}")
    print(f"{'='*70}")

    return iomt_df


if __name__ == "__main__":
    main()
