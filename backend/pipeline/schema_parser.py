"""
AA-IDS Feature Schema Parser
=============================

Implements Requirements 12.1, 12.2, 12.3, 12.4, 12.5, 12.6
- Parse FEATURE_SCHEMA.json into Python dataclass
- Validate schema contains exactly 53 features
- Validate feature names match expected patterns
- Format schema objects back into valid JSON (pretty printer)
- Ensure round-trip consistency (parse → print → parse)

"""

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
from pathlib import Path


@dataclass
class FeatureSchema:
    """
    Dataclass representing the FEATURE_SCHEMA.json structure.
    
    Attributes:
        schema_version: Version of the schema format
        project: Project name
        description: Schema description
        http_version: HTTP version supported
        total_features: Total number of features (must be 53)
        feature_groups: Dictionary mapping feature group names to counts
        features: List of feature names in canonical order
        srs_requirements: List of SRS requirement strings
        data_sources: Dictionary of data source information
        notes: Additional notes about the schema
    """
    schema_version: str
    project: str
    description: str
    http_version: str
    total_features: int
    feature_groups: Dict[str, int]
    features: List[str]
    srs_requirements: List[str]
    data_sources: Dict[str, str]
    notes: str = ""
    
    def __post_init__(self):
        """Validate schema after initialization."""
        self._validate()
    
    def _validate(self):
        """
        Validate schema integrity.
        
        Raises:
            ValueError: If validation fails
        """
        # Requirement 12.3: Validate exactly 53 features
        if self.total_features != 53:
            raise ValueError(
                f"Schema must define exactly 53 features, got {self.total_features}"
            )
        
        if len(self.features) != 53:
            raise ValueError(
                f"Feature list must contain exactly 53 features, got {len(self.features)}"
            )
        
        # Requirement 12.4: Validate feature names match expected patterns
        self._validate_feature_names()
        
        # Validate feature group counts sum to total
        group_sum = sum(self.feature_groups.values())
        if group_sum != self.total_features:
            raise ValueError(
                f"Feature group counts ({group_sum}) do not sum to total_features ({self.total_features})"
            )
    
    def _validate_feature_names(self):
        """
        Validate feature names follow expected naming patterns.
        
        Expected patterns:
        - Lowercase with underscores (snake_case)
        - Start with feature group prefix (url_, query_, body_, method_, cookie_, content_, connection_, etc.)
        - No special characters except underscores
        - No leading/trailing whitespace
        
        Raises:
            ValueError: If any feature name is invalid
        """
        # Valid feature name pattern: lowercase letters, numbers, underscores
        valid_pattern = re.compile(r'^[a-z][a-z0-9_]*$')
        
        # Expected prefixes based on feature groups
        expected_prefixes = {
            'url_', 'query_', 'body_', 'method_', 
            'cookie_', 'content_', 'connection_', 
            'post_', 'get_'
        }
        
        for i, feature_name in enumerate(self.features):
            # Check for whitespace
            if feature_name != feature_name.strip():
                raise ValueError(
                    f"Feature name at index {i} has leading/trailing whitespace: '{feature_name}'"
                )
            
            # Check pattern
            if not valid_pattern.match(feature_name):
                raise ValueError(
                    f"Feature name at index {i} does not match expected pattern (lowercase snake_case): '{feature_name}'"
                )
            
            # Check prefix (at least one expected prefix should match)
            has_valid_prefix = any(feature_name.startswith(prefix) for prefix in expected_prefixes)
            if not has_valid_prefix:
                raise ValueError(
                    f"Feature name at index {i} does not start with expected prefix: '{feature_name}'"
                )
    
    def get_feature_index(self, feature_name: str) -> int:
        """
        Get the index of a feature by name.
        
        Args:
            feature_name: Name of the feature
            
        Returns:
            Index of the feature in the canonical order
            
        Raises:
            ValueError: If feature name not found
        """
        try:
            return self.features.index(feature_name)
        except ValueError:
            raise ValueError(f"Feature '{feature_name}' not found in schema")
    
    def get_features_by_group(self, group_name: str) -> List[str]:
        """
        Get all feature names belonging to a specific group.
        
        Args:
            group_name: Name of the feature group (e.g., 'url_features')
            
        Returns:
            List of feature names in that group
            
        Raises:
            ValueError: If group name not found
        """
        if group_name not in self.feature_groups:
            raise ValueError(f"Feature group '{group_name}' not found in schema")
        
        # Map group names to prefixes
        group_prefix_map = {
            'url_features': 'url_',
            'query_string_features': 'query_',
            'body_payload_features': 'body_',
            'http_method_features': 'method_',
            'header_features': ['cookie_', 'content_', 'connection_', 'post_', 'get_']
        }
        
        prefixes = group_prefix_map.get(group_name, [])
        if isinstance(prefixes, str):
            prefixes = [prefixes]
        
        return [
            feature for feature in self.features
            if any(feature.startswith(prefix) for prefix in prefixes)
        ]


class SchemaParser:
    """
    Parser for FEATURE_SCHEMA.json files.
    
    Implements Requirements 12.1, 12.2, 12.5, 12.6
    """
    
    @staticmethod
    def parse_file(file_path: str) -> FeatureSchema:
        """
        Parse FEATURE_SCHEMA.json from file.
        
        Args:
            file_path: Path to FEATURE_SCHEMA.json file
            
        Returns:
            FeatureSchema object
            
        Raises:
            FileNotFoundError: If file does not exist
            json.JSONDecodeError: If file contains invalid JSON
            ValueError: If schema validation fails
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Schema file not found: {file_path}")
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(
                f"Invalid JSON in schema file: {e.msg}",
                e.doc,
                e.pos
            )
        
        return SchemaParser.parse_dict(data)
    
    @staticmethod
    def parse_dict(data: Dict) -> FeatureSchema:
        """
        Parse FEATURE_SCHEMA from dictionary.
        
        Args:
            data: Dictionary containing schema data
            
        Returns:
            FeatureSchema object
            
        Raises:
            ValueError: If required fields are missing or validation fails
        """
        required_fields = [
            'schema_version', 'project', 'description', 'http_version',
            'total_features', 'feature_groups', 'features', 'srs_requirements',
            'data_sources'
        ]
        
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            raise ValueError(
                f"Schema missing required fields: {', '.join(missing_fields)}"
            )
        
        return FeatureSchema(
            schema_version=data['schema_version'],
            project=data['project'],
            description=data['description'],
            http_version=data['http_version'],
            total_features=data['total_features'],
            feature_groups=data['feature_groups'],
            features=data['features'],
            srs_requirements=data['srs_requirements'],
            data_sources=data['data_sources'],
            notes=data.get('notes', '')
        )
    
    @staticmethod
    def to_dict(schema: FeatureSchema) -> Dict:
        """
        Convert FeatureSchema to dictionary.
        
        Args:
            schema: FeatureSchema object
            
        Returns:
            Dictionary representation
        """
        return asdict(schema)
    
    @staticmethod
    def to_json(schema: FeatureSchema, pretty: bool = True) -> str:
        """
        Convert FeatureSchema to JSON string (pretty printer).
        
        Implements Requirement 12.5
        
        Args:
            schema: FeatureSchema object
            pretty: If True, format with indentation
            
        Returns:
            JSON string representation
        """
        data = SchemaParser.to_dict(schema)
        
        if pretty:
            return json.dumps(data, indent=2, ensure_ascii=False)
        else:
            return json.dumps(data, ensure_ascii=False)
    
    @staticmethod
    def write_file(schema: FeatureSchema, file_path: str, pretty: bool = True):
        """
        Write FeatureSchema to JSON file.
        
        Args:
            schema: FeatureSchema object
            file_path: Output file path
            pretty: If True, format with indentation
        """
        json_str = SchemaParser.to_json(schema, pretty=pretty)
        
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(json_str)
    
    @staticmethod
    def verify_round_trip(file_path: str) -> bool:
        """
        Verify round-trip consistency: parse → print → parse.
        
        Implements Requirement 12.6
        
        Args:
            file_path: Path to FEATURE_SCHEMA.json file
            
        Returns:
            True if round-trip produces equivalent object
            
        Raises:
            AssertionError: If round-trip fails
        """
        # First parse
        schema1 = SchemaParser.parse_file(file_path)
        
        # Convert to JSON and parse again
        json_str = SchemaParser.to_json(schema1)
        data = json.loads(json_str)
        schema2 = SchemaParser.parse_dict(data)
        
        # Compare
        dict1 = SchemaParser.to_dict(schema1)
        dict2 = SchemaParser.to_dict(schema2)
        
        if dict1 != dict2:
            raise AssertionError(
                "Round-trip consistency check failed: "
                "parse → print → parse did not produce equivalent object"
            )
        
        return True


# Convenience functions

def load_schema(file_path: str = "FEATURE_SCHEMA.json") -> FeatureSchema:
    """
    Load FEATURE_SCHEMA.json from file.
    
    Args:
        file_path: Path to schema file (default: FEATURE_SCHEMA.json in current directory)
        
    Returns:
        FeatureSchema object
    """
    return SchemaParser.parse_file(file_path)


def validate_features(features: Dict[str, float], schema: FeatureSchema) -> bool:
    """
    Validate that extracted features match schema.
    
    Args:
        features: Dictionary of extracted features
        schema: FeatureSchema object
        
    Returns:
        True if features are valid
        
    Raises:
        ValueError: If validation fails
    """
    # Check feature count
    if len(features) != schema.total_features:
        raise ValueError(
            f"Expected {schema.total_features} features, got {len(features)}"
        )
    
    # Check feature names and order
    feature_names = list(features.keys())
    if feature_names != schema.features:
        missing = set(schema.features) - set(feature_names)
        extra = set(feature_names) - set(schema.features)
        
        error_msg = "Feature validation failed:\n"
        if missing:
            error_msg += f"  Missing features: {missing}\n"
        if extra:
            error_msg += f"  Extra features: {extra}\n"
        if feature_names != schema.features:
            error_msg += "  Feature order does not match schema"
        
        raise ValueError(error_msg)
    
    return True


if __name__ == "__main__":
    """Test the schema parser."""
    print("AA-IDS Feature Schema Parser - Test Suite")
    print("=" * 80)
    
    # Test 1: Parse FEATURE_SCHEMA.json
    print("\n[Test 1] Parse FEATURE_SCHEMA.json")
    try:
        schema = load_schema("FEATURE_SCHEMA.json")
        print(f"✓ Schema loaded successfully")
        print(f"  Project: {schema.project}")
        print(f"  Version: {schema.schema_version}")
        print(f"  Total features: {schema.total_features}")
        print(f"  Feature groups: {len(schema.feature_groups)}")
    except Exception as e:
        print(f"✗ Failed: {e}")
    
    # Test 2: Validate feature count
    print("\n[Test 2] Validate feature count")
    try:
        assert schema.total_features == 53, f"Expected 53 features, got {schema.total_features}"
        assert len(schema.features) == 53, f"Expected 53 feature names, got {len(schema.features)}"
        print(f"✓ Feature count validation passed")
    except AssertionError as e:
        print(f"✗ Failed: {e}")
    
    # Test 3: Validate feature names
    print("\n[Test 3] Validate feature names")
    try:
        schema._validate_feature_names()
        print(f"✓ Feature name validation passed")
        print(f"  Sample features: {schema.features[:3]}")
    except ValueError as e:
        print(f"✗ Failed: {e}")
    
    # Test 4: Pretty printer (to_json)
    print("\n[Test 4] Pretty printer (to_json)")
    try:
        json_str = SchemaParser.to_json(schema, pretty=True)
        print(f"✓ JSON serialization successful")
        print(f"  JSON length: {len(json_str)} characters")
    except Exception as e:
        print(f"✗ Failed: {e}")
    
    # Test 5: Round-trip consistency
    print("\n[Test 5] Round-trip consistency")
    try:
        SchemaParser.verify_round_trip("FEATURE_SCHEMA.json")
        print(f"✓ Round-trip consistency verified")
    except Exception as e:
        print(f"✗ Failed: {e}")
    
    # Test 6: Get feature by index
    print("\n[Test 6] Get feature by index")
    try:
        idx = schema.get_feature_index('url_length')
        print(f"✓ Feature 'url_length' found at index {idx}")
    except ValueError as e:
        print(f"✗ Failed: {e}")
    
    # Test 7: Get features by group
    print("\n[Test 7] Get features by group")
    try:
        url_features = schema.get_features_by_group('url_features')
        print(f"✓ Found {len(url_features)} URL features")
        print(f"  Sample: {url_features[:3]}")
    except ValueError as e:
        print(f"✗ Failed: {e}")
    
    print("\n" + "=" * 80)
    print("Schema parser test suite completed")
    print("=" * 80)
