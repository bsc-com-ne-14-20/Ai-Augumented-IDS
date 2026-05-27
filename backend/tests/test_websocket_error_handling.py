"""
test_websocket_error_handling.py
=================================
Unit tests for WebSocket error handling in backend/sockets/events.py

Tests verify:
- WebSocket emission errors are logged without crashing
- Application continues processing on WebSocket failures
- Client disconnections are handled gracefully
- Various types of WebSocket failures are properly handled

Requirements: 9.7, 18.5
"""

import pytest
import logging
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from backend.sockets.events import (
    init_socketio, emit_alert, broadcast_alert, _safe_emit,
    _register_connection_handlers
)


class TestWebSocketErrorHandling:
    """Test WebSocket error handling functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        # Reset global socketio instance
        import backend.sockets.events
        backend.sockets.events._socketio = None

    def test_safe_emit_with_no_socketio_initialized(self, caplog):
        """Test _safe_emit when Socket.IO is not initialized."""
        with caplog.at_level(logging.WARNING):
            result = _safe_emit("test_event", {"data": "test"}, context="test context")
        
        assert result is False
        assert "Cannot emit test_event event (test context): Socket.IO not initialized" in caplog.text

    def test_safe_emit_success(self, caplog):
        """Test _safe_emit with successful emission."""
        mock_socketio = Mock()
        
        # Initialize socketio
        init_socketio(mock_socketio)
        
        with caplog.at_level(logging.DEBUG):
            result = _safe_emit("test_event", {"data": "test"}, context="test context")
        
        assert result is True
        mock_socketio.emit.assert_called_once_with("test_event", {"data": "test"})
        assert "Socket.IO test_event event emitted successfully (test context)" in caplog.text

    def test_safe_emit_with_room(self):
        """Test _safe_emit with room parameter."""
        mock_socketio = Mock()
        init_socketio(mock_socketio)
        
        result = _safe_emit("test_event", {"data": "test"}, room="room123")
        
        assert result is True
        mock_socketio.emit.assert_called_once_with("test_event", {"data": "test"}, room="room123")

    def test_safe_emit_failure(self, caplog):
        """Test _safe_emit when emission fails."""
        mock_socketio = Mock()
        mock_socketio.emit.side_effect = Exception("Connection lost")
        
        init_socketio(mock_socketio)
        
        with caplog.at_level(logging.ERROR):
            result = _safe_emit("test_event", {"data": "test"}, context="test context")
        
        assert result is False
        assert "Socket.IO test_event event emission failed (test context): Connection lost" in caplog.text
        assert "Application will continue processing remaining requests" in caplog.text

    def test_emit_alert_no_socketio_initialized(self, caplog):
        """Test emit_alert when Socket.IO is not initialized."""
        verdict_payload = {
            "verdict": "ATTACK",
            "alert_id": "test-123",
            "timestamp": "2024-01-01T00:00:00Z",
            "detection_source": "rule_engine"
        }
        
        with caplog.at_level(logging.WARNING):
            emit_alert(verdict_payload)
        
        assert "emit_alert called before Socket.IO was initialised — skipping alert emission for alert_id=test-123" in caplog.text

    def test_emit_alert_missing_verdict(self, caplog):
        """Test emit_alert with missing verdict in payload."""
        mock_socketio = Mock()
        init_socketio(mock_socketio)
        
        verdict_payload = {
            "alert_id": "test-123",
            "timestamp": "2024-01-01T00:00:00Z"
            # Missing verdict
        }
        
        with caplog.at_level(logging.ERROR):
            emit_alert(verdict_payload)
        
        assert "Cannot emit alert: missing verdict in payload (alert_id=test-123)" in caplog.text
        assert "Skipping WebSocket emission" in caplog.text
        mock_socketio.emit.assert_not_called()

    @patch('backend.sockets.events._safe_emit')
    def test_emit_alert_attack_verdict(self, mock_safe_emit, caplog):
        """Test emit_alert with ATTACK verdict."""
        mock_socketio = Mock()
        init_socketio(mock_socketio)
        mock_safe_emit.return_value = True
        
        verdict_payload = {
            "verdict": "ATTACK",
            "alert_id": "test-123",
            "timestamp": "2024-01-01T00:00:00Z",
            "detection_source": "rule_engine",
            "attack_type": "SQLi",
            "confidence": 0.95,
            "request_summary": {"method": "POST", "url": "/login"},
            "rule_triggered": "rule_001"
        }
        
        with caplog.at_level(logging.INFO):
            emit_alert(verdict_payload)
        
        # Verify _safe_emit was called with correct parameters
        mock_safe_emit.assert_called_once()
        call_args = mock_safe_emit.call_args
        assert call_args[0][0] == "alert"  # event_name
        assert call_args[1]["context"] == "verdict=ATTACK attack_type=SQLi alert_id=test-123"
        
        # Verify success logging
        assert "Socket.IO alert emitted: verdict=ATTACK attack_type=SQLi confidence=0.95 alert_id=test-123" in caplog.text

    @patch('backend.sockets.events._safe_emit')
    def test_emit_alert_clean_verdict(self, mock_safe_emit, caplog):
        """Test emit_alert with CLEAN verdict."""
        mock_socketio = Mock()
        init_socketio(mock_socketio)
        mock_safe_emit.return_value = True
        
        verdict_payload = {
            "verdict": "CLEAN",
            "alert_id": "test-456",
            "timestamp": "2024-01-01T00:00:00Z",
            "detection_source": "ml_engine",
            "request_summary": {"method": "GET", "url": "/api/data"}
        }
        
        with caplog.at_level(logging.DEBUG):
            emit_alert(verdict_payload)
        
        # Verify _safe_emit was called with correct parameters
        mock_safe_emit.assert_called_once()
        call_args = mock_safe_emit.call_args
        assert call_args[0][0] == "clean_request"  # event_name
        assert call_args[1]["context"] == "alert_id=test-456 source=ml_engine"
        
        # Verify success logging
        assert "Socket.IO clean_request emitted: alert_id=test-456 source=ml_engine" in caplog.text

    def test_emit_alert_error_verdict(self, caplog):
        """Test emit_alert with ERROR verdict (should be silently ignored)."""
        mock_socketio = Mock()
        init_socketio(mock_socketio)
        
        verdict_payload = {
            "verdict": "ERROR",
            "alert_id": "test-789",
            "timestamp": "2024-01-01T00:00:00Z"
        }
        
        with caplog.at_level(logging.DEBUG):
            emit_alert(verdict_payload)
        
        # Verify no emission occurred
        mock_socketio.emit.assert_not_called()
        assert "Skipping Socket.IO emission for ERROR verdict (alert_id=test-789)" in caplog.text

    def test_broadcast_alert_no_socketio_initialized(self, caplog):
        """Test broadcast_alert when Socket.IO is not initialized."""
        verdict_payload = {
            "verdict": "ATTACK",
            "alert_id": "test-123"
        }
        
        with caplog.at_level(logging.WARNING):
            broadcast_alert(verdict_payload)
        
        assert "broadcast_alert called before Socket.IO was initialised — skipping alert broadcast for alert_id=test-123" in caplog.text

    @patch('backend.sockets.events.emit_alert')
    def test_broadcast_alert_success(self, mock_emit_alert):
        """Test broadcast_alert with successful emission."""
        mock_socketio = Mock()
        init_socketio(mock_socketio)
        
        verdict_payload = {
            "verdict": "ATTACK",
            "alert_id": "test-123"
        }
        
        broadcast_alert(verdict_payload)
        
        mock_emit_alert.assert_called_once_with(verdict_payload)

    @patch('backend.sockets.events.emit_alert')
    def test_broadcast_alert_unexpected_error(self, mock_emit_alert, caplog):
        """Test broadcast_alert with unexpected error in emit_alert."""
        mock_socketio = Mock()
        init_socketio(mock_socketio)
        mock_emit_alert.side_effect = Exception("Unexpected error")
        
        verdict_payload = {
            "verdict": "ATTACK",
            "alert_id": "test-123"
        }
        
        with caplog.at_level(logging.ERROR):
            broadcast_alert(verdict_payload)
        
        assert "Unexpected error during alert broadcast (alert_id=test-123, verdict=ATTACK): Unexpected error" in caplog.text
        assert "Application will continue processing remaining requests" in caplog.text

    def test_connection_handler_success(self, caplog):
        """Test WebSocket connection handler success."""
        from flask import Flask, request
        app = Flask(__name__)
        mock_socketio = Mock()
        
        with app.test_request_context():
            request.sid = "client-123"
            request.environ["REMOTE_ADDR"] = "192.168.1.100"
            
            # Mock _safe_emit to return success
            with patch('backend.sockets.events._safe_emit', return_value=True):
                init_socketio(mock_socketio)
        
        # Verify connection handler was registered
        assert mock_socketio.on.call_count >= 2  # connect and disconnect handlers

    def test_connection_handler_error(self, caplog):
        """Test WebSocket connection handler with error."""
        from flask import Flask, request
        app = Flask(__name__)
        mock_socketio = Mock()
        
        with app.test_request_context():
            request.sid = "client-123"
            request.environ["REMOTE_ADDR"] = "192.168.1.100"
            
            # Mock _safe_emit to return failure
            with patch('backend.sockets.events._safe_emit', return_value=False):
                init_socketio(mock_socketio)
        
        # Verify handlers were still registered despite emission failure
        assert mock_socketio.on.call_count >= 2

    def test_init_socketio_registers_handlers(self):
        """Test that init_socketio properly registers connection handlers."""
        mock_socketio = Mock()
        
        init_socketio(mock_socketio)
        
        # Verify that connection and disconnection handlers were registered
        assert mock_socketio.on.call_count >= 2
        
        # Verify the handlers were registered for 'connect' and 'disconnect' events
        call_args_list = [call[0][0] for call in mock_socketio.on.call_args_list]
        assert 'connect' in call_args_list
        assert 'disconnect' in call_args_list