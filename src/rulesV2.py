import pandas as pd
import re
import urllib.parse
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# 1. Load the dataset
df = pd.read_csv('../data/cleaned/csic_cleaned_final.csv')

# 2. Reconstruct the full request payload
df['full_request'] = df['url_path'].fillna('') + '?' + df['query_string'].fillna('') + ' ' + df['body'].fillna('')

# 3. Expanded Ruleset (V2)
rules = {
    "SQL Injection": [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"(?i)(union\s+select)",
        r"(?i)(or\s+1=1)",
        r"(?i)(select\s+.*\s+from|insert\s+into|drop\s+table|update\s+.*\s+set|exec(\s|\()|declare(\s|\())" # Advanced SQLi
    ],
    "XSS": [
        r"(<script>)",
        r"(?i)(javascript:)",
        r"(<img.*onerror=)",
        r"(?i)(<svg|<iframe|<body|<input)",    # Advanced XSS tags
        r"(?i)(alert\(|prompt\(|confirm\()",   # Direct JS execution
        r"(?i)(\s+on[a-z]+={1})"               # Event handlers
    ],
    "CRLF Injection": [
        r"(?i)(%0d|%0a|\r|\n)(set-cookie:|content-length:|location:)" # HTTP Splitting
    ],
    "Parameter Tampering": [
        r"(\.\*\?)",      # Regex injection
        r"id=\d+[^0-9&]"  # Tampering with expected integer structures
    ],
    "Path Traversal": [
        r"(\.\./)",
        r"(\.\.\\)",
        r"(%2e%2e%2f)"
    ]
}

# Compile regexes for speed
compiled_rules = [re.compile(pattern) for patterns in rules.values() for pattern in patterns]

def detect_attack(request):
    # STEP 1: Decode the payload first to catch obfuscated/encoded attacks
    try:
        decoded_request = urllib.parse.unquote(request)
    except Exception:
        decoded_request = request

    # STEP 2: Scan BOTH the raw request and the decoded request
    for pattern in compiled_rules:
        if pattern.search(request) or pattern.search(decoded_request):
            return 1 # Attack found
            
    return 0 # No attack found

# 4. Run the Engine against the dataset
print("Applying V2 rule-based engine...")
df['predicted_label'] = df['full_request'].apply(detect_attack)
df['label'] = df['label'].astype(int)

# 5. Evaluate the results
print("\n--- V2 Engine Evaluation Results ---")

# Evaluate metrics
cm = confusion_matrix(df['label'], df['predicted_label'])
print("Confusion Matrix:")
print(cm)

# Plot confusion matrix
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal (0)', 'Attack (1)'], yticklabels=['Normal (0)', 'Attack (1)'])
plt.title('Confusion Matrix')
plt.ylabel('Actual')
plt.xlabel('Predicted')
plt.tight_layout()
plt.savefig('confusion_matrix.png')
plt.close()

print("\nClassification Report:")
print(classification_report(df['label'], df['predicted_label'], target_names=['Normal (0)', 'Attack (1)']))