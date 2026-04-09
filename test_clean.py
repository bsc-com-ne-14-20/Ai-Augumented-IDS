import json, sys
from pathlib import Path
sys.path.insert(0, str(Path("aa_ids_backend").absolute()))

from pipeline.orchestrator import run_pipeline
from engines.rule_adapter import adapt_rule_engine
from engines.ml_adapter import adapt_ml_model
from pipeline.preprocessor import extract_features

with open("aa_ids_backend/tests/fixtures/sample_logs.json") as f:
    clean = json.load(f)["clean_request"]

features = extract_features(clean)
rule_res = adapt_rule_engine(features)
ml_res = adapt_ml_model(features)

print("Rule Result:", rule_res)
print("ML Result:", ml_res)
print("Keys with values > 0.0 in features:")
for k, v in features.items():
    if v > 0.0:
        print(f"  {k}: {v}")
