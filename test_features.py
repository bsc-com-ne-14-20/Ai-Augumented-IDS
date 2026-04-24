from api.feature_extractor import extract_features
import pandas as pd

# Normal request
normal = {
    "method": "GET",
    "url": "/products",
    "query_string": "",
    "body": "",
    "headers": {"content-type": "text/html"}
}

features = extract_features(normal)
print("Normal request features:")
print(features.iloc[0].describe())
print("\nMin:", features.min().min())
print("Max:", features.max().max())
