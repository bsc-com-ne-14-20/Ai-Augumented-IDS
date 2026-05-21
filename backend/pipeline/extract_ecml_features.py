"""
Extract HTTP Features from ECML/PKDD 2007 Dataset
===================================================

Parses raw ECML/PKDD HTTP requests and extracts 53 features
for cross-validation against CSIC 2010 trained model.

Input: xml_test.txt (ECML/PKDD format)
Output: ECML_CV_TEST.csv (53 features + label)
"""

import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse


class ECMLParser:
    """Parse ECML/PKDD format HTTP requests"""
    
    @staticmethod
    def parse_ecml_file(file_path):
        """
        Parse ECML/PKDD dataset file.
        
        Format:
        Start - Id: [ID]
        class: [CLASS]
        [HTTP_REQUEST]
        End - Id: [ID]
        """
        
        print(f"Loading ECML/PKDD dataset from: {file_path}")
        
        requests = []
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Split by request blocks
        blocks = content.split('Start - Id:')[1:]  # Skip the first empty part
        
        print(f"Found {len(blocks)} request blocks")
        
        for i, block in enumerate(blocks):
            if (i + 1) % 5000 == 0:
                print(f"  Parsing: {i + 1}/{len(blocks)}")
            
            try:
                lines = block.strip().split('\n')
                if len(lines) < 3:
                    continue
                
                # Extract ID
                id_line = lines[0].strip()
                request_id = id_line.split()[0] if id_line else str(i)
                
                # Extract class/label
                class_line = lines[1].strip()
                attack_class = class_line.replace('class:', '').strip()
                
                # Parse HTTP request
                http_lines = [l for l in lines[2:] if l.strip() and not l.startswith('End -')]
                
                if not http_lines:
                    continue
                
                # Parse request line (GET/POST /path HTTP/1.1)
                request_line = http_lines[0].strip()
                parts = request_line.split()
                
                if len(parts) < 2:
                    continue
                
                method = parts[0]
                url_part = parts[1]
                
                # Extract query string from URL
                if '?' in url_part:
                    url, query_string = url_part.split('?', 1)
                else:
                    url = url_part
                    query_string = ''
                
                # Parse headers and body
                headers = {}
                body = ''
                body_start = False
                
                for line in http_lines[1:]:
                    if line.strip() == '':
                        body_start = True
                        continue
                    
                    if body_start:
                        body += line + '\n'
                    elif ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()
                
                body = body.strip()
                
                # Create request dict
                request = {
                    'request_id': request_id,
                    'url': url,
                    'method': method.upper(),
                    'query_string': query_string,
                    'body': body,
                    'cookie': headers.get('cookie', ''),
                    'content_type': headers.get('content-type', ''),
                    'connection': headers.get('connection', 'close'),
                    'accept': headers.get('accept', '*/*'),
                    'content_length': int(headers.get('content-length', 0)) if headers.get('content-length', '').isdigit() else len(body),
                    'attack_class': attack_class,
                    'label': 1,  # All ECML is attacks in test set (based on format)
                }
                
                requests.append(request)
            
            except Exception as e:
                continue
        
        df = pd.DataFrame(requests)
        print(f"✓ Parsed {len(df)} requests")
        
        return df


class HTTPFeatureExtractorECML:
    """Extract 53 CSIC features from ECML requests"""
    
    @staticmethod
    def calculate_entropy(s):
        """Calculate Shannon entropy"""
        if not s or len(s) == 0:
            return 0.0
        probs = [s.count(c) / len(s) for c in set(s)]
        return round(-sum(p * np.log2(p) for p in probs if p > 0), 4)
    
    @staticmethod
    def extract_features(request_dict):
        """Extract all 53 features from single request"""
        
        features = {}
        
        url = str(request_dict.get('url', ''))
        query = str(request_dict.get('query_string', ''))
        body = str(request_dict.get('body', ''))
        method = str(request_dict.get('method', 'GET')).upper()
        cookie = str(request_dict.get('cookie', ''))
        content_type = str(request_dict.get('content_type', ''))
        connection = str(request_dict.get('connection', ''))
        accept = str(request_dict.get('accept', ''))
        
        # ===== URL FEATURES (12) =====
        features['url_length'] = len(url)
        features['url_path_depth'] = url.count('/')
        features['url_num_dots'] = url.count('.')
        features['url_num_special'] = len(re.findall(r'[<>\'";(){}\[\]]', url))
        features['url_num_hyphens'] = url.count('-')
        features['url_num_underscores'] = url.count('_')
        features['url_num_percent'] = url.count('%')
        features['url_num_equal'] = url.count('=')
        features['url_num_ampersand'] = url.count('&')
        features['url_entropy'] = HTTPFeatureExtractorECML.calculate_entropy(url)
        features['url_has_risky_ext'] = int(bool(re.search(r'\.(php|asp|aspx|jsp|cgi|exe|sh|bat|cmd|pl|py)$', url, re.IGNORECASE)))
        features['url_has_double_encoding'] = int('%25' in url.lower())
        
        # ===== QUERY FEATURES (11) =====
        features['query_length'] = len(query)
        features['query_num_params'] = query.count('=')
        features['query_num_equals'] = query.count('=')
        features['query_num_special'] = len(re.findall(r'[<>\'";(){}\[\]]', query))
        features['query_num_percent'] = query.count('%')
        features['query_entropy'] = HTTPFeatureExtractorECML.calculate_entropy(query)
        features['query_has_sqli'] = int(bool(re.search(r"(\'|--|;|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bDELETE\b)", query, re.IGNORECASE)))
        features['query_has_xss'] = int(bool(re.search(r'(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)', query, re.IGNORECASE)))
        features['query_has_traversal'] = int(bool(re.search(r'(\.\./|%2e%2e|/etc/passwd)', query, re.IGNORECASE)))
        features['query_has_encoding'] = int('%' in query or 'encoded' in query.lower())
        features['query_is_empty'] = int(query == '')
        
        # ===== BODY FEATURES (13) =====
        features['body_length'] = len(body)
        features['body_entropy'] = HTTPFeatureExtractorECML.calculate_entropy(body)
        features['body_num_params'] = body.count('=')
        features['body_num_special'] = len(re.findall(r'[<>\'";(){}\[\]]', body))
        features['body_num_percent'] = body.count('%')
        features['body_num_quotes'] = body.count('"') + body.count("'")
        features['body_num_semicolons'] = body.count(';')
        features['body_num_brackets'] = body.count('[') + body.count(']') + body.count('{') + body.count('}')
        features['body_has_sqli'] = int(bool(re.search(r"(\'|--|;|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b)", body, re.IGNORECASE)))
        features['body_has_xss'] = int(bool(re.search(r'(<script|javascript:|onerror=|onload=|alert\()', body, re.IGNORECASE)))
        features['body_has_traversal'] = int(bool(re.search(r'(\.\./|%2e%2e|/etc/)', body, re.IGNORECASE)))
        features['body_has_encoding'] = int('%' in body or 'encoded' in body.lower())
        features['body_is_empty'] = int(body == '')
        
        # ===== METHOD FEATURES (4) =====
        features['method_get'] = int(method == 'GET')
        features['method_post'] = int(method == 'POST')
        features['method_put'] = int(method == 'PUT')
        features['method_suspicious'] = int(method in ['DELETE', 'TRACE', 'CONNECT', 'PATCH'])
        
        # ===== COOKIE & HEADER FEATURES (9) =====
        features['cookie_length'] = len(cookie)
        features['cookie_has_sqli'] = int(bool(re.search(r"(\'|--|;|\bOR\b|\bAND\b)", cookie, re.IGNORECASE)))
        features['cookie_has_xss'] = int(bool(re.search(r'(<script|javascript:|alert\()', cookie, re.IGNORECASE)))
        features['cookie_is_present'] = int(cookie != '')
        features['content_type_is_form'] = int('form' in content_type.lower())
        features['content_type_is_json'] = int('json' in content_type.lower())
        features['content_type_is_none'] = int(content_type in ['', 'none', 'missing'])
        features['connection_is_close'] = int('close' in connection.lower())
        features['connection_keep_alive'] = int('keep-alive' in connection.lower())
        
        # ===== ANOMALY FEATURES (4) =====
        features['post_no_content_type'] = int(method == 'POST' and content_type in ['', 'none'])
        features['get_with_body'] = int(method == 'GET' and len(body.strip()) > 0)
        features['post_empty_body'] = int(method == 'POST' and len(body.strip()) == 0)
        features['content_length_mismatch'] = int(len(body) != request_dict.get('content_length', 0))
        
        return features


def extract_ecml_features(input_file, output_file):
    """Main function: Parse ECML and extract features"""
    
    print("\n" + "="*80)
    print("ECML/PKDD 2007 CROSS-VALIDATION DATASET EXTRACTION")
    print("="*80)
    
    # Parse ECML
    df_raw = ECMLParser.parse_ecml_file(input_file)
    
    if len(df_raw) == 0:
        print("ERROR: No requests parsed")
        return None
    
    # Extract features
    print("\nExtracting 53 features...")
    extractor = HTTPFeatureExtractorECML()
    
    features_list = []
    errors = 0
    
    for idx, row in df_raw.iterrows():
        if (idx + 1) % 2000 == 0:
            print(f"  Progress: {idx + 1}/{len(df_raw)}")
        
        try:
            features = extractor.extract_features(row.to_dict())
            features['label'] = row['label']
            features['attack_class'] = row['attack_class']
            features['request_id'] = row['request_id']
            features_list.append(features)
        except Exception as e:
            errors += 1
            if errors <= 5:
                print(f"  Warning: Error on request {row['request_id']}: {str(e)[:50]}")
    
    if len(features_list) == 0:
        print("ERROR: No features extracted")
        return None
    
    # Create DataFrame
    df_features = pd.DataFrame(features_list)
    
    print(f"\n✓ Features extracted: {len(df_features)} requests")
    print(f"  Errors: {errors}")
    print(f"  Total features: {df_features.shape[1]}")
    
    # Validation
    print("\nValidation:")
    print(f"  Shape: {df_features.shape}")
    print(f"  Columns: {list(df_features.columns[:10])}... (+more)")
    print(f"  Attack classes: {df_features['attack_class'].value_counts().to_dict()}")
    
    # Check for NaN/Inf
    nan_count = df_features.isnull().sum().sum()
    inf_count = df_features.isin([np.inf, -np.inf]).sum().sum()
    print(f"  NaN values: {nan_count}")
    print(f"  Inf values: {inf_count}")
    
    # Save
    print(f"\nSaving to: {output_file}")
    df_features.to_csv(output_file, index=False)
    print(f"✓ Saved!")
    
    print("\n" + "="*80)
    print("CROSS-VALIDATION DATASET READY")
    print("="*80)
    print(f"File: {output_file}")
    print(f"Samples: {len(df_features)}")
    print(f"Features: 53 (+ label, attack_class, request_id)")
    print(f"Use this for testing Random Forest trained on CSIC 2010")
    print("="*80 + "\n")
    
    return df_features


if __name__ == "__main__":
    import sys
    
    # Hardcoded paths - EDIT THESE
    input_file = r"C:\Users\USER\Desktop\aa-ids-project\web-application-attacks-datasets\ecml_pkdd\dataset_ecml_pkdd_train_test\xml_test.txt"
    output_file = r"C:\Users\USER\Desktop\aa-ids-project\ECML_CV_TEST.csv"
    
    print("ECML/PKDD Cross-Validation Dataset Extractor")
    print(f"Input:  {input_file}")
    print(f"Output: {output_file}")
    print()
    
    # Extract
    df = extract_ecml_features(input_file, output_file)
    
    if df is not None:
        print("\n✅ SUCCESS! Ready for cross-validation")
    else:
        print("\n❌ FAILED")
        sys.exit(1)
