import re

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

def detect_attack(request):
    alerts = []
    for attack_type, patterns in rules.items():
        for pattern in patterns:
            if re.search(pattern, request):
                alerts.append(attack_type)
    return alerts

request = "GET /login.php?user=admin' OR 1=1 --"
print(detect_attack(request))