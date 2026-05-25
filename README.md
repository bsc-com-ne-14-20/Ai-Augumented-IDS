# AI-Augmented HTTP Anomaly Intrusion Detection System (AA-IDS)
## Project Documentation — Chunk 1: Introduction & Project Overview

### 1.1 Project Meta-Information
* **Project Title:** AI-Augmented HTTP Anomaly Intrusion Detection System (AA-IDS)
* **Institution:** University of Malawi — School of Natural & Applied Sciences, Computing Department
* **Course:** ICT Project — COM422
* **Supervisor:** Mr. Martin Thodi

### 1.2 Project Team & Roles

| Name | Registration Number | Primary Responsibility |
| :--- | :--- | :--- |
| **Memory Lukhere** | BSC-COM-NE-14-20 | Project Manager |
| **Rashid Sidreck** | BSC-COM-NE-10-22 | ML Pipeline & API Development |
| **Yewo Mkandawire** | BSC-COM-NE-07-22 | Rule Engine & Django Middleware |
| **Dennis Bakaya** | BSC-32-22 | Flutter Dashboard Frontend |

---

### 1.3 Project Overview
The **AI-Augmented HTTP Anomaly Intrusion Detection System (AA-IDS)** is a hybrid web application intrusion detection architecture designed to detect, analyze, and classify malicious HTTP traffic in real time. 

To optimize computational efficiency and maintain high detection accuracy, the system employs a sequential pipeline consisting of three complementary detection layers. Each layer acts as a gate; traffic only proceeds to subsequent machine learning models if the previous stage requires deeper analysis.

```text
Incoming HTTP Request
       │
       ▼
┌────────────────────────────────────────┐
│  Layer 1: OWASP CRS Rule Engine        │ ──(Attack Detected)──► [Block / Log]
└────────────────────────────────────────┐
       │ (Ambiguous / Cleared)
       ▼
┌────────────────────────────────────────┐
│  Layer 2: Random Forest Binary         │ ──(Normal)───────────► [Allow Traffic]
└────────────────────────────────────────┐
       │ (Attack Confirmed)
       ▼
┌────────────────────────────────────────┐
│  Layer 3: XGBoost Multi-Class Forensic │ ──► [Categorize & Log]
└────────────────────────────────────────┘     (SQLi, XSS, Path Traversal, etc.)