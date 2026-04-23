import pandas as pd


df1 = pd.read_csv('/home/rashid/Documents/FYP/Ai-Augumented-IDS/data/final/train.csv')   
df2 = pd.read_csv('/home/rashid/Documents/FYP/Ai-Augumented-IDS/data/final/test.csv')   


combined = pd.concat([df1, df2], ignore_index=True)


combined.to_csv('merged_combined.csv', index=False)

print(f"File1 rows : {len(df1)}")
print(f"File2 rows : {len(df2)}")
print(f"Total rows in new file: {len(combined)}")
print("New file created: merged_combined.csv")


df = pd.read_csv('/home/rashid/Documents/FYP/Ai-Augumented-IDS/merged_combined.csv')


attacks_df = df[df['label'] == 1].copy()


print("Original rows :", len(df))
print("Malicious rows kept :", len(attacks_df))
print("Normal rows removed :", len(df) - len(attacks_df))


attacks_df.to_csv('attacks_only.csv', index=False)

print("Done New file created: attacks_only.csv")
print(f"Total rows in new file: {len(attacks_df)}")