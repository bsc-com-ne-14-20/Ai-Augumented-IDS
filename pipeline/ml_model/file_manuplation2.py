import pandas as pd

df1 = pd.read_csv('/home/rashid/Documents/FYP/Ai-Augumented-IDS/data/final/train.csv')   
df2 = pd.read_csv('/home/rashid/Documents/FYP/Ai-Augumented-IDS/data/final/test.csv')   

print(f"File1 rows : {len(df1)}")
print(f"File2 rows : {len(df2)}")

attacks_df1 = df1[df1['label'] == 1].copy()
attacks_df2 = df2[df2['label'] == 1].copy()

print("Train - Original rows :", len(df1))
print("Test - Original rows :", len(df2))
print("Train - Malicious rows kept :", len(attacks_df1))
print("Test - Malicious rows kept :", len(attacks_df2))

print("Normal rows removed :", len(df1) - len(attacks_df1))
print("Normal rows removed :", len(df2) - len(attacks_df2))

attacks_df1.to_csv('/home/rashid/Documents/FYP/Ai-Augumented-IDS/train_attacks_only.csv', index=False)
attacks_df2.to_csv('/home/rashid/Documents/FYP/Ai-Augumented-IDS/test_attacks_only.csv', index=False)

print("Done New file creation")