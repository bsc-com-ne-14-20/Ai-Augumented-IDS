from api.feature_extractor import extract_features

normal = {
    "method": "GET",
    "url": "/products",
    "query_string": "",
    "body": "",
    "headers": {"content-type": "text/html"}
}

features = extract_features(normal)
df = features.iloc[0]

# Find the outlier
outliers = df[df < -10]
print("Outlier features:")
for col, val in outliers.items():
    print(f"  {col}: {val}")

# Show all features
print("\nAll features:")
print(df.to_dict())
