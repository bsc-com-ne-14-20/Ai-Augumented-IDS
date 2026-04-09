import json, random, numpy as np, joblib, config, urllib.parse
from pipeline.preprocessor import extract_features
from pathlib import Path

MODEL = joblib.load('models/rf_model.joblib')
fcols = Path('data/final/feature_names.txt').read_text().splitlines()

base_log = {
    'method': 'GET',
    'url': 'http://localhost:8080/tienda1/index.jsp',
    'path': '/tienda1/index.jsp',
    'query_string': '',
    'headers': {
        'User-Agent': 'Mozilla/5.0',
        'Accept': 'text/html',
        'Connection': 'close',
        'Cookie': 'JSESSIONID=12345678901234567890123456789012'
    },
    'body': '',
    'response_code': 200,
    'content_length': 0,
    'timestamp': '2026-04-09T10:25:00Z'
}

for i in range(100):
    log = dict(base_log)
    log['url'] = f"http://localhost:8080/tienda1/publico/anadir.jsp?id={i}"
    log['path'] = "/tienda1/publico/anadir.jsp"
    log['query_string'] = f"id={i}"
    feats = extract_features(log)
    row = np.array([feats[c] for c in fcols]).reshape(1,-1)
    conf = MODEL.predict_proba(row)[0][1]
    if conf < 0.5:
        print(f"FOUND: conf={conf} url={log['url']}")
        with open("found_clean.json", "w") as f:
            json.dump(log, f)
        break
else:
    print("Could not find!")
