\# Dataset Summary

\## AI-Leveraged Hybrid HTTP Intrusion Detection System

\### University of Malawi | COM422 ICT Project



\---



\## 1. What is a Dataset?



A dataset is a structured collection of related data organised in a

consistent format for analysis and processing. In the context of

machine learning and intrusion detection, a dataset serves as the

foundation for training, validating and evaluating detection models.

It contains labelled or unlabeled examples that represent real or

simulated behaviour, enabling models to learn patterns that distinguish

normal activity from malicious activity.



\---



\## 2. Source of Dataset



\### Primary Dataset

The primary dataset used is the HTTP Dataset CSIC 2010, developed by

the Information Security Institute of the Spanish National Research

Council (CSIC). It was obtained from Kaggle at:



https://www.kaggle.com/datasets/ispangler/csic-2010-web-application-attacks



\### Validation Dataset

For cross-dataset validation our system will additionally be evaluated

using the CICIDS 2017 dataset developed by the Canadian Institute for

Cybersecurity, available at:



Primary source: Canadian Institute for Cybersecurity

https://www.unb.ca/cic/datasets/ids-2017.html



Downloaded from Kaggle at:

https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset

File used: Thursday-WorkingHours-Morning-WebAttacks.pcap\_ISCX.csv





Both datasets were automatically generated in controlled environments

and are among the most widely cited datasets in cybersecurity research.



\---



\## 3. Dataset Characteristics



\### CSIC 2010 HTTP Dataset



The CSIC 2010 HTTP Dataset contains automatically generated HTTP

traffic targeted at an e-commerce web application.



| Characteristic | Detail |

|---------------|--------|

| Format | CSV (Pre-parsed HTTP requests) |

| Total Requests | 61,065 |

| Normal Requests | 36,000 (59%) |

| Anomalous Requests | 25,065 (41%) |

| Original Features | 17 columns |

| Features After Engineering | 53 features |

| HTTP Methods | GET (43,088) / POST (17,580) / PUT (397) |

| Label Column | Binary (0=Normal, 1=Anomalous) |

| Missing Values | Handled during cleaning |

| Duplicates | None |

| Language | Spanish (Latin characters present) |



\### Attack Categories



| Attack Type | Description |

|------------|-------------|

| SQL Injection | Malicious SQL queries in parameters |

| Cross Site Scripting (XSS) | Script injection in form fields |

| Buffer Overflow | Oversized parameter values |

| Path Traversal | Directory traversal attempts |

| CRLF Injection | HTTP header manipulation |

| Parameter Tampering | Modification of hidden parameters |

| Information Gathering | Probing for system information |

| Server Side Include | SSI injection attempts |



\---



\## 4. Data Pipeline Summary



| Stage | Action | Result |

|-------|--------|--------|

| Loading | Imported CSV into Jupyter Notebooks | 61,065 rows × 17 columns |

| Cleaning | Removed nulls, fixed types, dropped zero variance columns | 61,065 rows × 10 columns |

| Feature Engineering | Extracted 53 features across 5 groups | 61,065 rows × 53 features |

| Train/Test Split | 80/20 stratified split | Train: 48,852 / Test: 12,213 |

| Scaling | StandardScaler fitted on train only | Normalised feature matrix |



\### Feature Engineering Summary



| Group | Description | Count |

|-------|-------------|-------|

| URL Features | Length, depth, entropy, special characters | 12 |

| Query String Features | Parameters, attack flags, encoding detection | 11 |

| Body/Payload Features | Length, entropy, SQLi/XSS/traversal flags | 13 |

| HTTP Method Features | GET/POST/PUT flags | 4 |

| Header Features | Cookie analysis, content type, consistency checks | 13 |

| \*\*Total\*\* | | \*\*53\*\* |

