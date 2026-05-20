"""
Fixed: Create Balanced ECML Cross-Validation Dataset=
=====================================================

Uses attack_class column to separate:
- "Valid" = Normal samples (label 0)
- Everything else = Attack samples (label 1)
"""

import pandas as pd
from sklearn.model_selection import train_test_split


def create_balanced_ecml_cv(ecml_file, output_file):
    """Create balanced ECML dataset by separating Valid (normal) from attacks"""
    
    print("="*80)
    print("CREATING BALANCED ECML CROSS-VALIDATION DATASET (FIXED)")
    print("="*80)
    
    print(f"\nLoading: {ecml_file}")
    ecml = pd.read_csv(ecml_file)
    
    print(f"Total samples: {len(ecml)}")
    print(f"\nAttack class distribution:")
    print(ecml['attack_class'].value_counts())
    
    # FIXED: Separate using attack_class, not label
    print("\n" + "-"*80)
    print("Separating samples by attack_class...")
    print("-"*80)
    
    # Normal = "Valid"
    ecml_normal = ecml[ecml['attack_class'] == 'Valid'].copy()
    ecml_normal['label'] = 0
    
    # Attacks = everything except "Valid"
    ecml_attacks = ecml[ecml['attack_class'] != 'Valid'].copy()
    ecml_attacks['label'] = 1
    
    print(f"\n✓ Normal samples (Valid): {len(ecml_normal)}")
    print(f"✓ Attack samples (non-Valid): {len(ecml_attacks)}")
    
    if len(ecml_normal) == 0:
        print("\n ERROR: No normal samples found!")
        return None
    
    # Balance the dataset
    print("\n" + "-"*80)
    print("Balancing dataset...")
    print("-"*80)
    
    # Use the smaller count for both
    min_count = min(len(ecml_normal), len(ecml_attacks))
    
    print(f"\nOriginal: Normal={len(ecml_normal)}, Attacks={len(ecml_attacks)}")
    print(f"Balancing to: {min_count} each")
    
    ecml_normal = ecml_normal.sample(n=min_count, random_state=42)
    ecml_attacks = ecml_attacks.sample(n=min_count, random_state=42)
    
    # Combine and shuffle
    ecml_balanced = pd.concat([ecml_normal, ecml_attacks], ignore_index=True)
    ecml_balanced = ecml_balanced.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"\n✓ Balanced dataset created:")
    print(f"  Total: {len(ecml_balanced)}")
    print(f"  Normal (0): {(ecml_balanced['label'] == 0).sum()}")
    print(f"  Attack (1): {(ecml_balanced['label'] == 1).sum()}")
    print(f"  Ratio: 1:1 (perfectly balanced)")
    
    # Save
    print(f"\nSaving to: {output_file}")
    ecml_balanced.to_csv(output_file, index=False)
    print(f"✓ Saved!")
    
    return ecml_balanced


def create_cv_splits(ecml_balanced, train_file, val_file, test_file):
    """Create 70/15/15 splits"""
    
    print("\n" + "="*80)
    print("CREATING 70/15/15 CROSS-VALIDATION SPLITS")
    print("="*80)
    
    # Get features and labels
    feature_cols = [col for col in ecml_balanced.columns if col not in ['label', 'attack_class', 'request_id']]
    X = ecml_balanced[feature_cols]
    y = ecml_balanced['label']
    
    print(f"\nFeatures: {len(feature_cols)}")
    print(f"Total samples: {len(X)}")
    
    # Split 70/30
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    
    # Split 30 into 15/15
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
    )
    
    # Create dataframes with labels
    train_df = X_train.copy()
    train_df['label'] = y_train.values
    if 'attack_class' in ecml_balanced.columns:
        # Get attack_class from original indices
        train_indices = X_train.index
        train_df['attack_class'] = ecml_balanced.loc[train_indices, 'attack_class'].values
    
    val_df = X_val.copy()
    val_df['label'] = y_val.values
    if 'attack_class' in ecml_balanced.columns:
        val_indices = X_val.index
        val_df['attack_class'] = ecml_balanced.loc[val_indices, 'attack_class'].values
    
    test_df = X_test.copy()
    test_df['label'] = y_test.values
    if 'attack_class' in ecml_balanced.columns:
        test_indices = X_test.index
        test_df['attack_class'] = ecml_balanced.loc[test_indices, 'attack_class'].values
    
    # Save files
    train_df.to_csv(train_file, index=False)
    val_df.to_csv(val_file, index=False)
    test_df.to_csv(test_file, index=False)
    
    print(f"\n Train ({len(train_df)}, 70%):")
    print(f"  Normal: {(train_df['label'] == 0).sum()}")
    print(f"  Attack: {(train_df['label'] == 1).sum()}")
    print(f"  Saved: {train_file}")
    
    print(f"\n Validation ({len(val_df)}, 15%):")
    print(f"  Normal: {(val_df['label'] == 0).sum()}")
    print(f"  Attack: {(val_df['label'] == 1).sum()}")
    print(f"  Saved: {val_file}")
    
    print(f"\n Test ({len(test_df)}, 15%):")
    print(f"  Normal: {(test_df['label'] == 0).sum()}")
    print(f"  Attack: {(test_df['label'] == 1).sum()}")
    print(f"  Saved: {test_file}")


if __name__ == "__main__":
    
    # File paths
    ecml_input = r"C:\Users\USER\Desktop\aa-ids-project\ECML_CV_TEST.csv"
    ecml_balanced = r"C:\Users\USER\Desktop\aa-ids-project\ECML_CV_BALANCED.csv"
    
    ecml_train = r"C:\Users\USER\Desktop\aa-ids-project\data\final\ecml_cv_train.csv"
    ecml_val = r"C:\Users\USER\Desktop\aa-ids-project\data\final\ecml_cv_val.csv"
    ecml_test = r"C:\Users\USER\Desktop\aa-ids-project\data\final\ecml_cv_test.csv"
    
    # Step 1: Create balanced dataset
    df_balanced = create_balanced_ecml_cv(ecml_input, ecml_balanced)
    
    if df_balanced is not None:
        # Step 2: Create splits
        create_cv_splits(df_balanced, ecml_train, ecml_val, ecml_test)
        
        print("\n" + "="*80)
        print("  BALANCED ECML CROSS-VALIDATION DATASET CREATED")
        print("="*80)
        print("\nFiles created:")
        print(f"  {ecml_balanced}")
        print(f"  {ecml_train}")
        print(f"  {ecml_val}")
        print(f"  {ecml_test}")
        print("\n Ready for cross-validation testing!")
        print("="*80)
    else:
        print("\n Failed to create balanced dataset")
