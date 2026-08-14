# DDoS Attack Detection in Software-Defined Networks (SDN) using Artificial Neural Networks

<p align="center">
  <img src="https://img.shields.io/badge/Dataset-CICIoT2023%20Based-blue?style=for-the-badge" />

  <img src="https://img.shields.io/badge/Task-DDoS%20Detection-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.9%2B-green?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/License-Research%20Use-lightgrey?style=for-the-badge" />
</p>




## Project Overview
This project focuses on developing an efficient and accurate Intrusion Detection System (IDS) for Software-Defined Networks (SDN) to identify Distributed Denial of Service (DDoS) attacks in real-time. Leveraging machine learning, specifically Artificial Neural Networks (ANNs), the system analyzes network flow telemetry to distinguish between legitimate traffic and malicious DDoS patterns.

## Dataset
The project utilizes a dataset (`dataset_sdn.csv`) containing various network flow features, including packet counts, byte counts, durations, and protocol information, along with a `label` indicating whether the flow is 'Normal' (0) or a 'DDoS Attack' (1).

## Methodology

### 1. Data Loading and Exploratory Data Analysis (EDA)
- The dataset is loaded and inspected for its structure, shape, and initial statistics.
- Comprehensive EDA is performed to identify:
    - Missing values (imputed for `rx_kbps` and `tot_kbps` using median).
    - Duplicate records (found 5091 duplicates, 4.88%).
    - Target class distribution (imbalanced, with 'Normal' being the majority class).
    - Correlation of features with the target label.

### 2. Data Preprocessing
- **Missing Value Imputation**: Median imputation is applied to `rx_kbps` and `tot_kbps`.
- **Feature Dropping**: Non-predictive or identifier columns such as `dt`, `src`, `dst`, and `switch` are removed.
- **Categorical Encoding**: The `Protocol` feature is label encoded.
- **Feature Scaling**: All numerical features are standardized using `StandardScaler`.
- **Train-Test Split**: The dataset is split into 80% training and 20% testing sets using stratified sampling to maintain class distribution.

### 3. Model Architecture (Improved ANN)
An Artificial Neural Network (ANN) is constructed with the following layers to enhance stability and performance:
- Input Dense Layer (128 units, ReLU activation)
- **Batch Normalization**
- **Dropout** (0.3 rate) for regularization
- Hidden Dense Layer (64 units, ReLU activation)
- **Batch Normalization**
- Hidden Dense Layer (32 units, ReLU activation)
- **Batch Normalization**
- Output Dense Layer (1 unit, Sigmoid activation for binary classification)

The model is compiled with the Adam optimizer (learning rate 0.001) and `binary_crossentropy` loss.

### 4. Model Training
The ANN is trained with advanced callbacks to optimize the training process:
- **Early Stopping**: Monitors `val_loss` with a patience of 7 epochs, restoring the best weights.
- **Model Checkpoint**: Saves the best model weights based on `val_loss`.
- **ReduceLROnPlateau**: Reduces the learning rate by a factor of 0.5 when `val_loss` plateaus, with a patience of 3 epochs and minimum LR of 0.00001.

## Results
The trained ANN model achieved excellent performance on the test set:
- **Test Accuracy**: 99.17%
- **Test Precision**: 98.60%
- **Test Recall**: 99.28%
- **Test F1-Score**: 98.94%
- **Test ROC AUC Score**: 0.9998
- **Total Prediction Time**: 0.74 seconds for 20,869 samples (sub-millisecond inference per sample)

### Classification Report
```
                 precision    recall  f1-score   support

     Normal (0)     0.9953    0.9910    0.9931     12712
DDoS Attack (1)     0.9860    0.9928    0.9894      8157

       accuracy                         0.9917     20869
      macro avg     0.9907    0.9919    0.9913     20869
   weighted avg     0.9917    0.9917    0.9917     20869
```

## Key Takeaways
1.  **Stability**: The implemented Batch Normalization and Dropout layers contribute to a robust and stable model architecture, resistant to training fluctuations.
2.  **Efficiency**: The ANN offers a lightweight solution suitable for deployment within SDN controllers, balancing high accuracy with computational efficiency.
3.  **Deployment Readiness**: With high precision (98.60%) and recall (99.28%), the model effectively minimizes false positives, ensuring minimal disruption to legitimate network traffic while efficiently neutralizing DDoS attack flows.

## How to Run
1.  Ensure you have the `dataset_sdn.csv` file in the same directory as the notebook.
2.  Run all cells sequentially in the provided Jupyter/Colab notebook.
3.  The notebook will perform data loading, preprocessing, model training, and evaluation.
"""

