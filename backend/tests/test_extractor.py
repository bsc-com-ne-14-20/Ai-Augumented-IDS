from backend.pipeline.http_feature_extractor import HTTPFeatureExtractor


def get_user_input():
    """Get HTTP request data from user input."""
    print("\n" + "="*70)
    print("HTTP REQUEST FEATURE EXTRACTOR - Interactive Input")
    print("="*70)
    
    request = {}
    
    request['url'] = input("\nEnter URL (e.g., /s?k=laptop): ").strip()
    request['method'] = input("Enter HTTP method (GET/POST/PUT): ").strip().upper() or 'GET'
    request['body'] = input("Enter request body (or press Enter for empty): ").strip()
    request['cookie'] = input("Enter cookies (or press Enter for none): ").strip()
    request['content_type'] = input("Enter content-type (or press Enter for default): ").strip()
    request['connection'] = input("Enter connection type (keep-alive/close): ").strip()
    request['accept'] = input("Enter accept header (or press Enter for default): ").strip()
    
    try:
        content_length = input("Enter content-length (or press Enter for 0): ").strip()
        request['content_length'] = int(content_length) if content_length else 0
    except ValueError:
        request['content_length'] = 0
    
    return request


def main():
    extractor = HTTPFeatureExtractor()
    
    while True:
        try:
            request = get_user_input()
            
            print("\n" + "-"*70)
            print("EXTRACTING FEATURES...")
            print("-"*70)
            
            features = extractor.extract_features(request)
            
            print("\nEXTRACTED FEATURES:")
            print("="*70)
            for feature_name, feature_value in features.items():
                print(f"  {feature_name:40} : {feature_value}")
            
            print("\n" + "="*70)
            print(f"✓ Total features extracted: {len(features)}")
            print("="*70)
            
            again = input("\nExtract features for another request? (y/n): ").strip().lower()
            if again != 'y':
                print("\nExiting feature extractor. Goodbye!")
                break
                
        except KeyboardInterrupt:
            print("\n\nExiting feature extractor. Goodbye!")
            break
        except Exception as e:
            print(f"\n✗ Error: {e}")
            print("Please try again.\n")


if __name__ == "__main__":
    main()