# Dataset Summary
## AI-Augmented HTTP Anomaly Intrusion Detection System (AA-IDS)
### University of Malawi | COM422 ICT Project

---

## 1. Project Overview

AA-IDS is a hybrid HTTP anomaly detection system combining:
- **Rule-Based Engine**: OWASP detection rules
- **ML Classifier**: Random Forest on 53 HTTP features
- **Target**: HTTP/1.1 web traffic anomaly detection

The system processes raw HTTP requests, extracts 53 numeric features, and classifies traffic as normal or anomalous.

---

## 2. Datasets Used

### Primary Dataset: CSIC 2010 (HTTP/1.1)
**Status**:  PRIMARY CROSS-VALIDATION DATASET

The HTTP Dataset CSIC 2010, developed by the Information Security Institute of the Spanish National Research Council (CSIC).

**Source**: https://www.kaggle.com/datasets/ispangler/csic-2010-web-application-attacks

**Key Characteristics**:
- Format: CSV (pre-parsed HTTP/1.1 requests)
- HTTP Version: 1.1 only
- Total Requests: 61,065
- Normal Requests: 36,000 (59%)
- Attack Requests: 25,065 (41%)
- Attack Diversity: 8 distinct attack types
- Language: Spanish (Latin-1 encoded)

**Usage**:
- Training Set: 42,746 samples (70%)
- Validation Set: 9,160 samples (15%)
- Test Set: 9,160 samples (15%)
- **Cross-Validation Strategy**: Stratified 70/15/15 split on same source

### Supplementary Dataset: ECML/PKDD 2007
**Status**:  SUPPLEMENTARY GENERALIZATION TEST

Additional HTTP/1.1 dataset from ECML/PKDD 2007 Challenge for cross-dataset validation.

**Source**: https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets

**Key Characteristics**:
- Format: Raw HTTP/1.1 requests (XML-labeled)
- Total Requests: 25,612
- Balanced Dataset: 10,502 normal (Valid) + 15,110 attacks
- Attack Types: SQLi, XSS, Path Traversal, LDAP, XPath, OS Command, SSI

**Usage**:
- Balanced Training: 14,702 samples (70%)
- Validation: 3,151 samples (15%)
- Testing: 3,151 samples (15%)
- **Purpose**: Test model generalization across different HTTP attack sources

###  NOT USED: CIC-IDS 2017
**Status**: NOT USED (Network flows, not HTTP content)

CIC-IDS 2017 was originally considered but **rejected** because:
- Contains 79 network flow features (packet statistics)
- Does NOT contain raw HTTP request data
- Different feature space (not compatible with HTTP feature extraction)
- Cannot extract 53 HTTP features from network flows
- Would require lossy feature mapping/approximation

**Decision**: Use CSIC + ECML (both have raw HTTP/1.1 requests) instead.

---

## 3. Dataset Characteristics

### CSIC 2010 HTTP Dataset Details

| Characteristic | Detail |
|---|---|
| **HTTP Version** | HTTP/1.1 only |
| **Format** | CSV (pre-parsed) |
| **Total Requests** | 61,065 |
| **Normal** | 36,000 (59%) |
| **Anomalous** | 25,065 (41%) |
| **Feature Matrix** | 61,065 × 53 features |
| **HTTP Methods** | GET (43,088), POST (17,580), PUT (397) |
| **Label** | Binary (0=Normal, 1=Attack) |
| **Encoding** | Latin-1 (Spanish characters) |
| **Missing Values** | None (handled during cleaning) |
| **Duplicates** | None |
| **Data Quality** | High (from controlled lab environment) |

### Attack Types in CSIC 2010

| Attack Type | Description | Count |
|---|---|---|
| SQL Injection | Malicious SQL in parameters/body | ~5,000 |
| XSS | Script injection in form fields | ~3,000 |
| Buffer Overflow | Oversized parameter values | ~4,000 |
| Path Traversal | Directory traversal attempts | ~3,000 |
| CRLF Injection | HTTP header manipulation | ~3,000 |
| Parameter Tampering | Hidden parameter modification | ~3,000 |
| Information Gathering | Probing for system information | ~2,000 |
| Server-Side Include | SSI injection attempts | ~2,065 |

---

## 4. Feature Engineering (53 Features)

### Source Alignment
Features extracted from CSIC 2010 notebook cleaning pipeline:
-  Matches exact CSIC 2010 feature engineering logic
-  Implements SRS FE-001 to FE-006 requirements
-  URL decoding for encoded payload detection
-  Shannon entropy for randomness detection
-  Attack pattern matching (SQLi, XSS, traversal)

### Feature Groups

| Group | Features | Description |
|---|---|---|
| **URL Features** | 12 | Length, depth, dots, special chars, entropy, risky extensions |
| **Query String Features** | 11 | Parameters, encoding, attack patterns, empty detection |
| **Body/Payload Features** | 13 | Length, entropy, quotes, brackets, attack patterns |
| **HTTP Method Features** | 4 | GET, POST, PUT, suspicious methods |
| **Header Features** | 13 | Cookie analysis, content-type, connection, anomalies |
| **TOTAL** | **53** | **All numeric, no NaN/Inf values** |

### Feature Extraction Pipeline

| Stage | Input | Output | Details |
|---|---|---|---|
| **Loading** | Raw CSV | 61,065 requests | Pre-parsed HTTP/1.1 |
| **Cleaning** | 61,065 × 17 cols | 61,065 × 10 cols | Handle null/types |
| **Feature Engineering** | HTTP request fields | 61,065 × 53 features | Extract all groups |
| **Scaling** | Raw features | Normalized [0,1] | StandardScaler fitted on train only |
| **Train/Val/Test Split** | 61,065 samples | 42,746 / 9,160 / 9,160 | Stratified 70/15/15 |

---

## 5. Cross-Validation Strategy

### Primary: CSIC 2010 (70/15/15 Split)

**Why 70/15/15 instead of 80/20?**
- 15% validation allows hyperparameter tuning
- 15% test set provides robust evaluation
- Stratification maintains attack/normal ratio

**Data Leakage Prevention**:
- StandardScaler fitted on training set only
- Validation/test sets scaled using train statistics
- No information from test set used during training

### Supplementary: ECML/PKDD 2007

**Purpose**: Validate model generalization across different datasets

**Strategy**:
1. Train RF on CSIC training set
2. Evaluate on CSIC test set (baseline)
3. Evaluate on ECML test set (generalization test)

**Expected Results**:
- CSIC test accuracy: >85%
- ECML test accuracy: >80% (some drop expected)
- Generalization gap: <5% (acceptable)

---

## 6. Implementation Details

### Feature Extraction Module
- **File**: `http_feature_extractor.py`
- **SRS Compliance**: FE-001 to FE-006
- **Performance**: <50ms per request (target)
- **Output**: JSON-serializable dictionary with 53 features
- **Guarantees**: Reproducible, no NaN/Inf values

### Data Files

**CSIC 2010 (Primary)**:
- `data/final/cicids_cv_train.csv`: 42,746 samples (70%)
- `data/final/cicids_cv_val.csv`: 9,160 samples (15%)
- `data/final/cicids_cv_test.csv`: 9,160 samples (15%)

**ECML/PKDD 2007 (Supplementary)**:
- `data/final/ecml_cv_train.csv`: 14,702 samples (70%)
- `data/final/ecml_cv_val.csv`: 3,151 samples (15%)
- `data/final/ecml_cv_test.csv`: 3,151 samples (15%)
- `ECML_CV_BALANCED.csv`: 21,004 samples (balanced normal+attack)

---

## 7. Data Quality & Validation

### Validation Checks
-  No missing values (NaN/Inf)
-  Exactly 53 features per request
-  Feature reproducibility (same input → same output)
-  No data leakage (train/val/test separation)
-  Stratified sampling (attack ratio maintained)
-  Consistent encoding (UTF-8)

### HTTP/1.1 Compliance
- **HTTP Version**: 1.1 only (no 2.0/3.0)
- **Methods**: GET, POST, PUT (primary), others present
- **Headers**: Standard HTTP/1.1 headers
- **Encoding**: Latin-1, UTF-8

---

## 8. References

**CSIC 2010 Dataset**:
- Tavallaee et al., "Information Security Institute, Spanish Research Council"
- Kaggle: https://www.kaggle.com/datasets/ispangler/csic-2010-web-application-attacks

**ECML/PKDD 2007 Challenge**:
- Machine Learning Challenge 2007
- GitLab: https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets

**Feature Engineering**:
- Based on CSIC 2010 cleaning pipeline
- Implements SRS v1.0 Section 4.2 (Feature Extraction)
- 53 HTTP features for ML classification

---

## 9. Project Status

| Component | Status | Files |
|---|---|---|
| Data Cleaning |  Complete | `cleaning_data.ipynb` |
| Feature Engineering |  Complete | `http_feature_extractor.py` |
| CSIC Cross-Validation |  Complete | `cicids_cv_*.csv` |
| ECML Extraction |  Complete | `extract_ecml_features.py` |
| ECML Cross-Validation |  Complete | `ecml_cv_*.csv` |
| Feature Validation |  Complete | Test scripts |
| Ready for ML Training |  Yes | All datasets prepared |

---

**Last Updated**: May 20, 2026
**Dataset Version**: 1.0
**HTTP Version**: 1.1 only
**Feature Count**: 53 (validated)