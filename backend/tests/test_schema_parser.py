"""
Unit tests for schema_parser module.

Tests Requirements 12.1, 12.2, 12.3, 12.4, 12.5, 12.6
"""

import json
import pytest
from pathlib import Path
from backend.pipeline.schema_parser import (
    SchemaParser,
    FeatureSchema,
    load_schema,
    validate_features
)


class TestSchemaParser:
    """Test suite for SchemaParser class."""
    
    def test_parse_valid_schema(self):
        """Test parsing valid FEATURE_SCHEMA.json (Requirement 12.1)."""
        schema = SchemaParser.parse_file("FEATURE_SCHEMA.json")
        
        assert isinstance(schema, FeatureSchema)
        assert schema.schema_version == "1.0"
        assert schema.total_features == 53
        assert len(schema.features) == 53
        assert schema.http_version == "1.1"
    
    def test_parse_invalid_json(self, tmp_path):
        """Test parsing invalid JSON raises descriptive error (Requirement 12.2)."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("{ invalid json }")
        
        with pytest.raises(json.JSONDecodeError) as exc_info:
            SchemaParser.parse_file(str(invalid_file))
        
        assert "Invalid JSON" in str(exc_info.value)
    
    def test_parse_missing_file(self):
        """Test parsing non-existent file raises FileNotFoundError (Requirement 12.2)."""
        with pytest.raises(FileNotFoundError) as exc_info:
            SchemaParser.parse_file("nonexistent.json")
        
        assert "Schema file not found" in str(exc_info.value)
    
    def test_validate_feature_count(self):
        """Test validation of exactly 53 features (Requirement 12.3)."""
        schema = load_schema("FEATURE_SCHEMA.json")
        
        # Should have exactly 53 features
        assert schema.total_features == 53
        assert len(schema.features) == 53
    
    def test_validate_feature_count_mismatch(self):
        """Test validation fails when feature count is wrong (Requirement 12.3)."""
        invalid_data = {
            "schema_version": "1.0",
            "project": "Test",
            "description": "Test schema",
            "http_version": "1.1",
            "total_features": 50,  # Wrong count
            "feature_groups": {"test": 50},
            "features": ["feature_" + str(i) for i in range(50)],
            "srs_requirements": [],
            "data_sources": {}
        }
        
        with pytest.raises(ValueError) as exc_info:
            SchemaParser.parse_dict(invalid_data)
        
        assert "exactly 53 features" in str(exc_info.value)
    
    def test_validate_feature_names(self):
        """Test validation of feature name patterns (Requirement 12.4)."""
        schema = load_schema("FEATURE_SCHEMA.json")
        
        # All feature names should be valid snake_case with expected prefixes
        for feature in schema.features:
            assert feature == feature.strip()  # No whitespace
            assert feature.islower() or '_' in feature  # Lowercase or has underscore
            assert not feature.startswith('_')  # No leading underscore
    
    def test_validate_invalid_feature_name(self):
        """Test validation fails for invalid feature names (Requirement 12.4)."""
        invalid_data = {
            "schema_version": "1.0",
            "project": "Test",
            "description": "Test schema",
            "http_version": "1.1",
            "total_features": 53,
            "feature_groups": {"test": 53},
            "features": ["InvalidFeature"] + ["url_feature_" + str(i) for i in range(52)],
            "srs_requirements": [],
            "data_sources": {}
        }
        
        with pytest.raises(ValueError) as exc_info:
            SchemaParser.parse_dict(invalid_data)
        
        # The validation catches pattern mismatch (uppercase) before prefix check
        assert "does not match expected pattern" in str(exc_info.value) or "does not start with expected prefix" in str(exc_info.value)
    
    def test_to_json_pretty_printer(self):
        """Test pretty printer formats schema to JSON (Requirement 12.5)."""
        schema = load_schema("FEATURE_SCHEMA.json")
        
        # Test pretty printing
        json_str = SchemaParser.to_json(schema, pretty=True)
        assert isinstance(json_str, str)
        assert len(json_str) > 0
        
        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed["total_features"] == 53
        assert len(parsed["features"]) == 53
    
    def test_to_json_compact(self):
        """Test compact JSON formatting (Requirement 12.5)."""
        schema = load_schema("FEATURE_SCHEMA.json")
        
        # Test compact printing
        json_str = SchemaParser.to_json(schema, pretty=False)
        assert isinstance(json_str, str)
        assert '\n' not in json_str or json_str.count('\n') < 5  # Minimal newlines
    
    def test_round_trip_consistency(self):
        """Test parse → print → parse produces equivalent object (Requirement 12.6)."""
        # This should not raise an exception
        result = SchemaParser.verify_round_trip("FEATURE_SCHEMA.json")
        assert result is True
    
    def test_round_trip_manual(self):
        """Test manual round-trip consistency (Requirement 12.6)."""
        # First parse
        schema1 = load_schema("FEATURE_SCHEMA.json")
        
        # Convert to JSON and parse again
        json_str = SchemaParser.to_json(schema1)
        data = json.loads(json_str)
        schema2 = SchemaParser.parse_dict(data)
        
        # Compare
        dict1 = SchemaParser.to_dict(schema1)
        dict2 = SchemaParser.to_dict(schema2)
        
        assert dict1 == dict2
    
    def test_get_feature_index(self):
        """Test getting feature index by name."""
        schema = load_schema("FEATURE_SCHEMA.json")
        
        # First feature should be at index 0
        idx = schema.get_feature_index("url_length")
        assert idx == 0
        
        # Test another feature
        idx = schema.get_feature_index("query_length")
        assert idx > 0
    
    def test_get_feature_index_not_found(self):
        """Test getting index for non-existent feature raises error."""
        schema = load_schema("FEATURE_SCHEMA.json")
        
        with pytest.raises(ValueError) as exc_info:
            schema.get_feature_index("nonexistent_feature")
        
        assert "not found in schema" in str(exc_info.value)
    
    def test_get_features_by_group(self):
        """Test getting features by group name."""
        schema = load_schema("FEATURE_SCHEMA.json")
        
        # Test URL features
        url_features = schema.get_features_by_group("url_features")
        assert len(url_features) == 12
        assert all(f.startswith("url_") for f in url_features)
        
        # Test query features
        query_features = schema.get_features_by_group("query_string_features")
        assert len(query_features) == 11
        assert all(f.startswith("query_") for f in query_features)
    
    def test_get_features_by_invalid_group(self):
        """Test getting features for non-existent group raises error."""
        schema = load_schema("FEATURE_SCHEMA.json")
        
        with pytest.raises(ValueError) as exc_info:
            schema.get_features_by_group("nonexistent_group")
        
        assert "not found in schema" in str(exc_info.value)
    
    def test_validate_features_helper(self):
        """Test validate_features helper function."""
        schema = load_schema("FEATURE_SCHEMA.json")
        
        # Create valid feature dictionary
        features = {name: 0.0 for name in schema.features}
        
        # Should not raise exception
        result = validate_features(features, schema)
        assert result is True
    
    def test_validate_features_wrong_count(self):
        """Test validate_features fails with wrong feature count."""
        schema = load_schema("FEATURE_SCHEMA.json")
        
        # Create feature dictionary with wrong count
        features = {name: 0.0 for name in schema.features[:10]}
        
        with pytest.raises(ValueError) as exc_info:
            validate_features(features, schema)
        
        assert "Expected 53 features" in str(exc_info.value)
    
    def test_validate_features_wrong_names(self):
        """Test validate_features fails with wrong feature names."""
        schema = load_schema("FEATURE_SCHEMA.json")
        
        # Create feature dictionary with wrong names
        features = {f"wrong_feature_{i}": 0.0 for i in range(53)}
        
        with pytest.raises(ValueError) as exc_info:
            validate_features(features, schema)
        
        assert "Feature validation failed" in str(exc_info.value)
    
    def test_write_and_read_file(self, tmp_path):
        """Test writing schema to file and reading it back."""
        schema = load_schema("FEATURE_SCHEMA.json")
        
        # Write to temporary file
        output_file = tmp_path / "test_schema.json"
        SchemaParser.write_file(schema, str(output_file))
        
        # Read it back
        schema2 = SchemaParser.parse_file(str(output_file))
        
        # Should be equivalent
        assert SchemaParser.to_dict(schema) == SchemaParser.to_dict(schema2)


class TestFeatureSchema:
    """Test suite for FeatureSchema dataclass."""
    
    def test_feature_schema_initialization(self):
        """Test FeatureSchema can be initialized with valid data."""
        schema = load_schema("FEATURE_SCHEMA.json")
        
        assert schema.schema_version == "1.0"
        assert schema.total_features == 53
        assert len(schema.features) == 53
        assert len(schema.feature_groups) == 5
    
    def test_feature_groups_sum_to_total(self):
        """Test feature group counts sum to total_features."""
        schema = load_schema("FEATURE_SCHEMA.json")
        
        group_sum = sum(schema.feature_groups.values())
        assert group_sum == schema.total_features
    
    def test_all_features_have_valid_prefixes(self):
        """Test all features start with expected prefixes."""
        schema = load_schema("FEATURE_SCHEMA.json")
        
        expected_prefixes = {
            'url_', 'query_', 'body_', 'method_', 
            'cookie_', 'content_', 'connection_', 
            'post_', 'get_'
        }
        
        for feature in schema.features:
            has_valid_prefix = any(feature.startswith(prefix) for prefix in expected_prefixes)
            assert has_valid_prefix, f"Feature '{feature}' has invalid prefix"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
