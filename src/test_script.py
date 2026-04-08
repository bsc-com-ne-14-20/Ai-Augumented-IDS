import pandas as pd
import re
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# Load the dataset
df = pd.read_csv('csic_cleaned_final.csv')

# Reconstruct the request payload string to test against the rules
# We combine path, query string, and body to ensure all vectors are scanned
df['full_request'] = df['url_path'].fillna('') + '?' + df['query_string'].fillna('') + ' ' + df['body'].fillna('')

rules = {
    "SQL Injection": [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"(?i)(union\s+select)",
        r"(?i)(or\s+1=1)"
    ],
    "XSS": [
        r"(<script>)",
        r"(?i)(javascript:)",
        r"(<img.*onerror=)"
    ]
}

# Compile regexes for performance
compiled_rules = [re.compile(pattern) for patterns in rules.values() for pattern in patterns]

def is_attack(request):
    for pattern in compiled_rules:
        if pattern.search(request):
            return 1 # Attack found
    return 0 # No attack found

# Apply the engine
df['predicted_label'] = df['full_request'].apply(is_attack)
df['label'] = df['label'].astype(int)

# Evaluate metrics
print("Confusion Matrix:")
print(confusion_matrix(df['label'], df['predicted_label']))

print("\nClassification Report:")
print(classification_report(df['label'], df['predicted_label'], target_names=['Normal (0)', 'Attack (1)']))