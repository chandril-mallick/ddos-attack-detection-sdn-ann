# Hybrid Healthcare IoMT DDoS Detection Dataset

<p align="center">
  <img src="https://img.shields.io/badge/Dataset-CICIoT2023%20Based-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Domain-Healthcare%20IoMT-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Task-DDoS%20Detection-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.9%2B-green?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/License-Research%20Use-lightgrey?style=for-the-badge" />
</p>

> A **research-grade, publication-ready** hybrid dataset that transforms the CICIoT2023 IoT attack dataset into a Healthcare IoMT-specific environment, simulating real hospital network behaviour under both normal and DDoS attack conditions.

---

---

## Project Overview

This project addresses a critical gap in healthcare cybersecurity research: the **absence of IoMT-specific DDoS datasets** that reflect the unique traffic patterns of hospital medical devices.

### Problem Statement

Standard IoT attack datasets (like CICIoT2023) are **device-agnostic** — they do not encode the semantic context of healthcare environments (device type, patient priority, hospital department, authentication state, etc.). This limits the ability to train AI models that understand *why* a traffic anomaly is dangerous in a medical context.

### Solution

We transform the raw CICIoT2023 network flow statistics into a **hybrid dataset** that:

- Maps traffic features to 10 types of real medical IoT devices
- Adds 10 healthcare-specific contextual columns per row
- Applies device-aware attack enrichment (SYN flood signatures differ on a Ventilator vs. an EHR Server)
- Computes a heuristic anomaly score per flow
- Produces ML-ready splits for Random Forest, XGBoost, LSTM, GRU, and Autoencoder IDS

### Use Cases

| Use Case                             | Suitability         |
| ------------------------------------ | ------------------- |
| AI-based DDoS intrusion detection    | Primary             |
| Healthcare network anomaly detection | Primary             |
| Multi-class attack classification    | Primary             |
| Time-series LSTM / GRU modelling     | Ready               |
| Autoencoder-based unsupervised IDS   | Ready               |
| Academic research & publication      | ✅Publication-grade |
| Hospital network security baseline   | ✅ Applicable       |

---

## Dataset Summary

| Property                       | Value                       |
| ------------------------------ | --------------------------- |
| **Total Samples**        | 234,763 rows                |
| **Total Columns**        | 54                          |
| **ML Feature Columns**   | 30 (scaled)                 |
| **Train Split (80%)**    | 187,810 rows                |
| **Test Split (20%)**     | 46,953 rows                 |
| **Attack Categories**    | 5 (Benign + 4 attack types) |
| **IoMT Device Types**    | 10                          |
| **Hospital Departments** | 7                           |
| **Label Encoding**       | Integer (0–4)              |
| **Feature Scaling**      | RobustScaler                |
| **Split Strategy**       | Stratified 80/20            |

### Label Distribution

| Label              | Count  | % of Dataset |
| ------------------ | ------ | ------------ |
| `Benign`         | 79,833 | 34.0%        |
| `DDoS_SYN_Flood` | 48,451 | 20.6%        |
| `DDoS_UDP_Flood` | 37,577 | 16.0%        |
| `DDoS_TCP_Flood` | 35,487 | 15.1%        |
| `Mirai_Botnet`   | 33,415 | 14.2%        |

> **Note:** 58,834 exact duplicate rows were removed during cleaning, preserving dataset integrity.

---

## Source Dataset

**CICIoT2023** — Canadian Institute for Cybersecurity IoT Attack Dataset 2023

| Property                    | Value                                                              |
| --------------------------- | ------------------------------------------------------------------ |
| **Creator**           | Canadian Institute for Cybersecurity (CIC)                         |
| **Format**            | CSV (network flow statistics from PCAP captures)                   |
| **Attack Types Used** | DDoS-SYN_Flood, DDoS-UDP_Flood, DDoS-TCP_Flood, Mirai-greeth_flood |
| **Benign Source**     | `Benign_Final/BenignTraffic.pcap.csv`                            |
| **Raw Columns**       | 39 numeric network flow features                                   |

### Raw CICIoT2023 Columns Used

```
Header_Length, Protocol Type, Time_To_Live, Rate, fin_flag_number,
syn_flag_number, rst_flag_number, psh_flag_number, ack_flag_number,
ack_count, syn_count, fin_count, rst_count, TCP, UDP, Tot sum, Min,
Max, AVG, Std, Tot size, IAT, Number, Variance, ...
```

---

## Pipeline Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│              hybrid_healthcare_iomt_pipeline.py                  │
└─────────────────────────────────────────────────────────────────┘
           │
           ▼
  ┌─────────────────┐
  │  §1  LOAD DATA  │  Benign (80k) + SYN/UDP/TCP/Mirai (60k each)
  └────────┬────────┘
           ▼
  ┌─────────────────┐
  │  §2  CLEAN      │  De-dup · Inf→NaN · Median fill · IQR clip
  └────────┬────────┘
           ▼
  ┌──────────────────────┐
  │  §3  FEATURE RENAME  │  CICIoT2023 cols → Healthcare feature names
  └──────────┬───────────┘  + 4 derived compound features
             ▼
  ┌───────────────────────────┐
  │  §4  HEALTHCARE COLUMNS   │  Inject 10 IoMT metadata columns
  └──────────┬────────────────┘  device_type, anomaly_score, risk_level…
             ▼
  ┌────────────────────────────┐
  │  §5  ATTACK ENRICHMENT     │  Force attack-specific signatures
  └──────────┬─────────────────┘  (SYN↑, IAT↓, RST storm, Mirai burst)
             ▼
  ┌──────────────────────────┐
  │  §6  ML PREPROCESSING    │  RobustScaler · LabelEncoder
  └──────────┬───────────────┘  Stratified 80/20 split
             ▼
  ┌─────────────────────────────┐
  │  §7  FEATURE IMPORTANCE     │  50-tree Random Forest on 50k subsample
  └──────────┬──────────────────┘
             ▼
  ┌──────────────────────┐
  │  §8  VISUALIZATIONS  │  7 analysis plots (PNG)
  └──────────┬───────────┘
             ▼
  ┌──────────────────┐
  │  §9  EXPORT      │  CSVs · JSON · TXT · ML splits
  └──────────────────┘
```

---

## Simulated IoMT Devices

Ten healthcare device types are assigned to each network flow, reflecting realistic attack targeting patterns.

| Device Type                | Healthcare Service     | Department      | Patient Priority   | Comm. Pattern    |
| -------------------------- | ---------------------- | --------------- | ------------------ | ---------------- |
| `ECG_Monitor`            | Cardiology             | Cardiology_Ward | **Critical** | Periodic_5s      |
| `Glucose_Monitor`        | Diabetes_Monitoring    | Endocrinology   | High               | Low_Frequency    |
| `Pulse_Oximeter`         | Respiratory_Monitoring | General_Ward    | High               | Periodic_10s     |
| `Smart_Infusion_Pump`    | Drug_Delivery          | ICU             | **Critical** | Command_Response |
| `ICU_Monitor`            | Critical_Care          | ICU             | **Critical** | Continuous       |
| `EHR_Server`             | Health_Records         | Administration  | Low                | Request_Response |
| `Wearable_Health_Band`   | Fitness_Monitoring     | Outpatient      | Low                | Burst_Periodic   |
| `Remote_Patient_Monitor` | Telehealth             | Remote_Care     | Medium             | Scheduled_Upload |
| `Smart_Thermometer`      | Temperature_Monitoring | General_Ward    | Medium             | Low_Frequency    |
| `Ventilator_System`      | Respiratory_Support    | ICU             | **Critical** | Continuous       |

### Device Assignment Weights

Attackers target high-value devices more often than routine monitoring devices:

| Device                 | Benign Weight | Attack Weight |
| ---------------------- | ------------- | ------------- |
| EHR_Server             | 10%           | **25%** |
| ICU_Monitor            | 15%           | **20%** |
| Remote_Patient_Monitor | 8%            | 10%           |
| Ventilator_System      | 3%            | 10%           |
| ECG_Monitor            | 18%           | 10%           |

---

## Feature Schema

### Column Mapping: CICIoT2023 → Healthcare Feature Name

| CICIoT2023 Column   | Mapped Feature Name          | Description                             |
| ------------------- | ---------------------------- | --------------------------------------- |
| `IAT`             | `Flow_IAT_Mean`            | Mean inter-arrival time between packets |
| `Std`             | `Flow_IAT_Std`             | Std deviation of inter-arrival time     |
| `Variance`        | `Fwd_IAT_Std`              | Variance (proxy for Fwd IAT Std)        |
| `Rate`            | `Flow_Packets_s`           | Packets per second                      |
| `Tot size`        | `Flow_Bytes_s`             | Total bytes / flow size                 |
| `Number`          | `Total_Fwd_Packets`        | Total forward packet count              |
| `Tot sum`         | `Fwd_Packets_Length_Total` | Total forward payload bytes             |
| `Min`             | `Fwd_IAT_Min`              | Minimum IAT in forward direction        |
| `Header_Length`   | `Packet_Length_Mean`       | Mean packet header length               |
| `syn_flag_number` | `SYN_Flag_Count`           | Proportion of packets with SYN flag     |
| `ack_flag_number` | `ACK_Flag_Count`           | Proportion of packets with ACK flag     |
| `rst_flag_number` | `RST_Flag_Count`           | Proportion of packets with RST flag     |
| `psh_flag_number` | `PSH_Flag_Count`           | Proportion of packets with PSH flag     |
| `fin_flag_number` | `FIN_Flag_Count`           | Proportion of packets with FIN flag     |
| `TCP`             | `TCP_Ratio`                | TCP traffic proportion                  |
| `UDP`             | `UDP_Ratio`                | UDP traffic proportion                  |
| `Time_To_Live`    | `Time_To_Live`             | Average TTL value                       |
| `syn_count`       | `SYN_Count_Raw`            | Raw count of SYN packets                |
| `ack_count`       | `ACK_Count_Raw`            | Raw count of ACK packets                |

### Derived / Engineered Features

| Feature                      | Formula                                          | Purpose                         |
| ---------------------------- | ------------------------------------------------ | ------------------------------- |
| `Down_Up_Ratio`            | `Fwd_Packets_Length_Total / Total_Fwd_Packets` | Asymmetry indicator             |
| `Packet_Length_Std`        | `√(Fwd_IAT_Std)`                              | Payload length variability      |
| `Total_Backward_Packets`   | `Total_Fwd_Packets × U(0.2, 0.8)`             | Estimated bidirectional traffic |
| `Bwd_Packets_Length_Total` | `Fwd_Packets_Length_Total × U(0.1, 0.6)`      | Estimated backward payload      |

---

## Healthcare Metadata Columns

Ten new columns are added to each row, transforming raw network flow data into IoMT-contextualised records.

| Column                    | Type         | Values / Range                                      | Description                   |
| ------------------------- | ------------ | --------------------------------------------------- | ----------------------------- |
| `device_type`           | categorical  | 10 device names                                     | Simulated medical device      |
| `healthcare_service`    | categorical  | 10 service types                                    | Clinical service category     |
| `hospital_department`   | categorical  | 7 departments                                       | Physical hospital unit        |
| `patient_priority`      | categorical  | Critical / High / Medium / Low                      | Clinical urgency of device    |
| `traffic_behavior`      | categorical  | Normal / Malicious                                  | Traffic classification        |
| `attack_impact`         | categorical  | 5 impact types                                      | Consequence of attack on care |
| `authentication_status` | categorical  | Authenticated / Unauthenticated / Spoofed_Auth / … | Session auth state            |
| `communication_pattern` | categorical  | 6 patterns                                          | Normal device comm rhythm     |
| `anomaly_score`         | float [0, 1] | 0.0 – 0.90                                         | Heuristic risk score          |
| `risk_level`            | categorical  | Critical / High / Low                               | Attack risk classification    |

### Attack Impact Mapping

| Attack Label       | Impact Classification     |
| ------------------ | ------------------------- |
| `DDoS_SYN_Flood` | Severe_Service_Disruption |
| `DDoS_UDP_Flood` | Bandwidth_Exhaustion      |
| `DDoS_TCP_Flood` | Resource_Exhaustion       |
| `Mirai_Botnet`   | Botnet_Takeover           |
| `Benign`         | None                      |

---

## Attack Simulation Logic

Each attack category is enriched with statistically realistic signatures to strengthen model separability.

### SYN Flood

```
SYN_Flag_Count  → forced to U(0.85, 1.0)   # nearly every packet has SYN
Flow_IAT_Mean   → forced to U(1e-5, 5e-4)  # sub-millisecond inter-arrival
Flow_Packets_s  → multiplied by U(3, 8)    # extremely high packet rate
```

### UDP Flood

```
Flow_Bytes_s    → multiplied by U(4, 10)   # massive bandwidth consumption
SYN_Flag_Count  → set to 0.0               # UDP has no SYN
UDP_Ratio       → forced to U(0.90, 1.0)   # near-pure UDP traffic
```

### TCP Flood

```
RST_Flag_Count      → forced to U(0.3, 0.7)  # RST storm
Total_Fwd_Packets   → multiplied by U(2, 5)  # resource exhaustion volume
```

### Mirai Botnet

```
Flow_IAT_Std    → multiplied by U(5, 15)   # highly irregular timing
Flow_Packets_s  → multiplied by U(2, 6)    # massive packet bursts
```

### Normal (Benign)

- Stable `Flow_IAT_Mean` matching device communication pattern
- Low/zero `SYN_Flag_Count`
- Balanced `Down_Up_Ratio`
- `authentication_status` ∈ {Authenticated, Certificate_Based, Token_Based}

---

## Anomaly Detection Logic

Each flow receives a heuristic `anomaly_score` ∈ [0, 1] computed from five independent signals:

| Signal               | Condition                         | Score Added |
| -------------------- | --------------------------------- | ----------- |
| SYN spike            | `SYN_Flag_Count > 0.5`          | +0.35       |
| High packet rate     | `Flow_Packets_s > 1000`         | +0.20       |
| Moderate packet rate | `500 < Flow_Packets_s ≤ 1000`  | +0.10       |
| RST storm            | `RST_Flag_Count > 0.3`          | +0.15       |
| Extreme low IAT      | `Flow_IAT_Mean < 0.001`         | +0.20       |
| Low IAT              | `0.001 ≤ Flow_IAT_Mean < 0.01` | +0.10       |
| Byte flood           | `Flow_Bytes_s > 1,000,000`      | +0.10       |

Final score is capped at **1.0**. Score is recomputed after attack enrichment.

**Observed distribution:**

- Mean: 0.402 · Std: 0.247 · Min: 0.0 · Max: 0.90
- 25th percentile: 0.20 (low risk)
- 75th percentile: 0.55 (elevated risk)

---

## Dataset Statistics

### Numeric Feature Summary

| Feature                      | Mean      | Std       | Min      | Max       |
| ---------------------------- | --------- | --------- | -------- | --------- |
| `Flow_IAT_Mean`            | 0.003128  | 0.006759  | 0.000000 | 0.126234  |
| `Flow_IAT_Std`             | 262.40    | 887.65    | 0.000    | 27,225.67 |
| `Flow_Packets_s`           | 37,979.61 | 74,998.46 | 1.03     | 3,190,721 |
| `Flow_Bytes_s`             | 366.61    | 454.36    | 60.0     | 11,725.77 |
| `Total_Fwd_Packets`        | 107.02    | 115.11    | 1        | 499.99    |
| `Fwd_Packets_Length_Total` | 13,516.08 | 19,329.02 | 60       | 230,176   |
| `Packet_Length_Mean`       | 17.55     | 10.15     | 0.0      | 60.0      |
| `SYN_Flag_Count`           | 0.200     | 0.372     | 0.0      | 1.0       |
| `ACK_Flag_Count`           | 0.267     | 0.390     | 0.0      | 1.0       |
| `RST_Flag_Count`           | 0.080     | 0.186     | 0.0      | 0.70      |
| `TCP_Ratio`                | 0.624     | 0.440     | 0.0      | 1.0       |
| `UDP_Ratio`                | 0.218     | 0.356     | 0.0      | 1.0       |
| `Time_To_Live`             | 79.67     | 35.82     | 22.7     | 250.1     |
| `SYN_Count_Raw`            | 20.25     | 39.54     | 0        | 100       |
| `ACK_Count_Raw`            | 3.42      | 6.99      | 0        | 100       |

### Device Distribution

| Device                 | Count  | %     |
| ---------------------- | ------ | ----- |
| EHR_Server             | 46,932 | 20.0% |
| ICU_Monitor            | 42,714 | 18.2% |
| ECG_Monitor            | 29,992 | 12.8% |
| Remote_Patient_Monitor | 22,012 | 9.4%  |
| Smart_Infusion_Pump    | 20,236 | 8.6%  |
| Ventilator_System      | 17,910 | 7.6%  |
| Pulse_Oximeter         | 17,356 | 7.4%  |
| Glucose_Monitor        | 17,211 | 7.3%  |
| Wearable_Health_Band   | 14,116 | 6.0%  |
| Smart_Thermometer      | 6,284  | 2.7%  |

### Patient Priority Distribution

| Priority | Count   | %     |
| -------- | ------- | ----- |
| Critical | 110,852 | 47.2% |
| Low      | 61,048  | 26.0% |
| High     | 34,567  | 14.7% |
| Medium   | 28,296  | 12.0% |

---

## Feature Importance

Top 15 features by Random Forest importance (50 estimators, max depth 8, 50k subsample):

| Rank | Feature                  | Importance | Category           |
| ---- | ------------------------ | ---------- | ------------------ |
| 1    | `risk_level_enc`       | 0.1182     | Healthcare Context |
| 2    | `attack_impact_enc`    | 0.1149     | Healthcare Context |
| 3    | `Total_Fwd_Packets`    | 0.0896     | Network Flow       |
| 4    | `anomaly_score`        | 0.0749     | Engineered         |
| 5    | `Packet_Length_Mean`   | 0.0742     | Network Flow       |
| 6    | `UDP_Ratio`            | 0.0713     | Protocol           |
| 7    | `RST_Flag_Count`       | 0.0585     | TCP Flags          |
| 8    | `SYN_Count_Raw`        | 0.0560     | TCP Flags          |
| 9    | `traffic_behavior_enc` | 0.0495     | Healthcare Context |
| 10   | `SYN_Flag_Count`       | 0.0460     | TCP Flags          |
| 11   | `Flow_Bytes_s`         | 0.0431     | Network Flow       |
| 12   | `Flow_IAT_Mean`        | 0.0423     | Timing             |
| 13   | `ACK_Flag_Count`       | 0.0370     | TCP Flags          |
| 14   | `TCP_Ratio`            | 0.0340     | Protocol           |
| 15   | `Flow_Packets_s`       | 0.0295     | Network Flow       |

> Healthcare context features (`risk_level_enc`, `attack_impact_enc`) rank highest because they encode domain knowledge derived from the label itself. When using this dataset for **pure network-based IDS**, exclude these columns and rely on the network flow + flag features only.

---

## Output Files

All outputs are saved to `output/`:

```
output/
├── hybrid_healthcare_iomt_dataset.csv     ← Full 234,763-row dataset (54 cols)
├── processed_healthcare_dataset.csv       ← With encoded categoricals (55 cols)
├── feature_mapping.json                   ← Column schema + encoding lookup
├── dataset_summary.txt                    ← Human-readable statistics report
├── ml_X_train.csv                         ← 187,810 × 30 scaled feature matrix
├── ml_X_test.csv                          ← 46,953 × 30 scaled feature matrix
├── ml_y_train.csv                         ← Training labels (integer encoded)
├── ml_y_test.csv                          ← Test labels (integer encoded)
├── ml_label_reference.csv                 ← Label ID → name mapping
└── visualizations/
    ├── 01_label_distribution.png
    ├── 02_device_traffic_heatmap.png
    ├── 03_packet_frequency_violin.png
    ├── 04_correlation_matrix.png
    ├── 05_anomaly_distribution.png
    ├── 06_feature_importance.png
    └── 07_iat_vs_packet_rate_scatter.png
```

### File Descriptions

| File                                   | Rows    | Cols | Purpose                   |
| -------------------------------------- | ------- | ---- | ------------------------- |
| `hybrid_healthcare_iomt_dataset.csv` | 234,763 | 54   | Full research dataset     |
| `processed_healthcare_dataset.csv`   | 234,763 | 55   | With `*_enc` columns    |
| `ml_X_train.csv`                     | 187,810 | 30   | Model training features   |
| `ml_X_test.csv`                      | 46,953  | 30   | Model evaluation features |
| `ml_y_train.csv`                     | 187,810 | 1    | Training labels           |
| `ml_y_test.csv`                      | 46,953  | 1    | Evaluation labels         |
| `ml_label_reference.csv`             | 5       | 2    | Class ID ↔ name          |
| `feature_mapping.json`               | —      | —   | Full schema documentation |

### Label Encoding Reference

| ID | Label          |
| -- | -------------- |
| 0  | Benign         |
| 1  | DDoS_SYN_Flood |
| 2  | DDoS_TCP_Flood |
| 3  | DDoS_UDP_Flood |
| 4  | Mirai_Botnet   |

---

## Visualizations

| Plot                   | File                                  | Description                             |
| ---------------------- | ------------------------------------- | --------------------------------------- |
| Label Distribution     | `01_label_distribution.png`         | Bar chart of attack categories          |
| Device Traffic Heatmap | `02_device_traffic_heatmap.png`     | IoMT device × attack type density      |
| Packet Frequency       | `03_packet_frequency_violin.png`    | Flow Packets/s violin (log scale)       |
| Correlation Matrix     | `04_correlation_matrix.png`         | Feature correlations (lower triangle)   |
| Anomaly Distribution   | `05_anomaly_distribution.png`       | KDE: Normal vs Malicious anomaly scores |
| Feature Importance     | `06_feature_importance.png`         | Top-20 RF importances                   |
| IAT vs Packet Rate     | `07_iat_vs_packet_rate_scatter.png` | 2D attack signature scatter (log-log)   |

---

## Machine Learning Preparation

### Recommended Model Configurations

#### Random Forest / XGBoost

```python
import pandas as pd

X_train = pd.read_csv("output/ml_X_train.csv")
X_test  = pd.read_csv("output/ml_X_test.csv")
y_train = pd.read_csv("output/ml_y_train.csv").squeeze()
y_test  = pd.read_csv("output/ml_y_test.csv").squeeze()

# RandomForest
from sklearn.ensemble import RandomForestClassifier
rf = RandomForestClassifier(n_estimators=200, max_depth=15, n_jobs=-1)
rf.fit(X_train, y_train)

# XGBoost
from xgboost import XGBClassifier
xgb = XGBClassifier(n_estimators=200, max_depth=8, use_label_encoder=False)
xgb.fit(X_train, y_train)
```

#### LSTM / GRU (Sequence Modelling)

```python
import numpy as np

# Reshape for sequence models: (samples, timesteps, features)
# Use a window of 10 timesteps
TIMESTEPS = 10
FEATURES   = X_train.shape[1]

X_seq = np.array([
    X_train.values[i:i+TIMESTEPS]
    for i in range(len(X_train) - TIMESTEPS)
])
y_seq = y_train.values[TIMESTEPS:]

# Keras LSTM
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout

model = Sequential([
    LSTM(64, input_shape=(TIMESTEPS, FEATURES), return_sequences=True),
    Dropout(0.3),
    LSTM(32),
    Dropout(0.2),
    Dense(5, activation="softmax")
])
model.compile(optimizer="adam", loss="sparse_categorical_crossentropy",
              metrics=["accuracy"])
```

#### Autoencoder IDS (Unsupervised)

```python
# Train only on Benign flows for anomaly detection
X_benign = X_train[y_train == 0]

from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense

inp = Input(shape=(30,))
enc = Dense(16, activation="relu")(inp)
enc = Dense(8,  activation="relu")(enc)
dec = Dense(16, activation="relu")(enc)
out = Dense(30, activation="linear")(dec)

autoencoder = Model(inp, out)
autoencoder.compile(optimizer="adam", loss="mse")
autoencoder.fit(X_benign, X_benign, epochs=20, batch_size=256)

# Anomaly = reconstruction error above threshold
recon_err = np.mean((X_test.values - autoencoder.predict(X_test))**2, axis=1)
threshold = np.percentile(recon_err, 95)
predictions = (recon_err > threshold).astype(int)
```

### Recommended Feature Sets by Task

| Task                    | Recommended Features                       |
| ----------------------- | ------------------------------------------ |
| Pure network IDS        | `ML_FEATURES` (20 network cols) only     |
| Healthcare-aware IDS    | All 30 cols (incl. IoMT context `*_enc`) |
| Anomaly detection only  | `anomaly_score` + timing + flag features |
| Protocol classification | `TCP_Ratio`, `UDP_Ratio`, flag counts  |

> ⚠️ **Warning:** For strict intrinsic network-based classification, **exclude** `risk_level_enc` and `attack_impact_enc`. These encode label-derived domain knowledge and will cause data leakage in naive experiments.

---

## Quick Start

### 1. Clone / Navigate to the Project

```bash
cd /Users/chandrilmallick/Downloads/ddos_attack
```

### 2. Install Dependencies

```bash
pip install pandas numpy scikit-learn matplotlib seaborn
```

### 3. Run the Pipeline

```bash
python3 hybrid_healthcare_iomt_pipeline.py
```

Expected runtime: **~30 seconds** on a modern MacBook.

### 4. Load the Dataset

```python
import pandas as pd

# Full hybrid dataset
df = pd.read_csv("output/hybrid_healthcare_iomt_dataset.csv")
print(df.shape)           # (234763, 54)
print(df["Label"].value_counts())

# ML-ready splits
X_train = pd.read_csv("output/ml_X_train.csv")
y_train = pd.read_csv("output/ml_y_train.csv").squeeze()
```

---

## Requirements

| Library          | Version | Purpose                    |
| ---------------- | ------- | -------------------------- |
| `python`       | ≥ 3.9  | Runtime                    |
| `pandas`       | ≥ 1.5  | Data manipulation          |
| `numpy`        | ≥ 1.23 | Numerical computing        |
| `scikit-learn` | ≥ 1.2  | ML preprocessing + RF      |
| `matplotlib`   | ≥ 3.6  | Static plots               |
| `seaborn`      | ≥ 0.12 | Statistical visualizations |

Install all at once:

```bash
pip install pandas numpy scikit-learn matplotlib seaborn
```

---

## Project Structure

```
ddos_attack/
├── hybrid_healthcare_iomt_pipeline.py   ← Main pipeline (all 10 stages)
├── README.md                            ← This file
├── CSV/                                 ← CICIoT2023 raw CSV files
│   ├── Benign_Final/
│   │   └── BenignTraffic.pcap.csv
│   ├── DDoS-SYN_Flood/
│   │   └── DDoS-SYN_Flood.pcap.csv
│   ├── DDoS-UDP_Flood/
│   │   └── DDoS-UDP_Flood.pcap.csv
│   ├── DDoS-TCP_Flood/
│   │   └── DDoS-TCP_Flood.pcap.csv
│   ├── Mirai-greeth_flood/
│   │   └── Mirai-greeth_flood.pcap.csv
│   └── ... (34 total attack categories)
└── output/                              ← Generated by pipeline
    ├── hybrid_healthcare_iomt_dataset.csv
    ├── processed_healthcare_dataset.csv
    ├── feature_mapping.json
    ├── dataset_summary.txt
    ├── ml_X_train.csv
    ├── ml_X_test.csv
    ├── ml_y_train.csv
    ├── ml_y_test.csv
    ├── ml_label_reference.csv
    └── visualizations/
        ├── 01_label_distribution.png
        ├── 02_device_traffic_heatmap.png
        ├── 03_packet_frequency_violin.png
        ├── 04_correlation_matrix.png
        ├── 05_anomaly_distribution.png
        ├── 06_feature_importance.png
        └── 07_iat_vs_packet_rate_scatter.png
```

---

## 📖 Citation

If you use this dataset or pipeline in your research, please cite both the source dataset and this work:

### Source Dataset

```bibtex
@dataset{CICIoT2023,
  author    = {Neto, Euclides Carlos Pinto and Dadkhah, Sajjad and
               Ferreira, Raphael and Zohourian, Alireza and
               Lu, Rongxing and Ghorbani, Ali A.},
  title     = {{CICIoT2023}: A Real-World IoT Attack Dataset},
  year      = {2023},
  publisher = {Canadian Institute for Cybersecurity},
  url       = {https://www.unb.ca/cic/datasets/iotdataset-2023.html}
}
```

### This Work

```bibtex
@dataset{HybridHealthcareIoMTDDoS2024,
  title     = {Hybrid Healthcare IoMT DDoS Detection Dataset},
  year      = {2024},
  note      = {Derived from CICIoT2023. Transforms generic IoT network
               flows into Healthcare IoMT-contextualised records with
               10 medical device types, 10 clinical metadata columns,
               attack-specific enrichment, and ML-ready splits.},
  url       = {https://github.com/your-repo}
}
```

---

## Ethical Use & Disclaimer

- This dataset is **synthetic** — no real patient data was used or included.
- Network flows are derived from **lab-generated** CICIoT2023 captures.
- Healthcare context columns (device type, department, etc.) are **simulated assignments** for research purposes.
- This dataset is intended for **academic research and educational use only**.
- The authors accept no liability for use of this dataset in production medical systems.

---

<p align="center">
  <b>Built for AI-based Healthcare Cybersecurity Research · IoMT · DDoS Detection · 2024</b>
</p>
