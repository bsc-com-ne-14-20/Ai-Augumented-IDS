import 'dart:io';
import 'package:socket_io_client/socket_io_client.dart' as IO;
import 'package:aa_ids_dashboard/api/endpoints.dart';
import 'package:aa_ids_dashboard/models/dashboard_models.dart';

/// Socket.IO Service for real-time live alert feed
/// Connects to the Flask-SocketIO backend to receive live detection alerts
class AlertSocketService {
  late IO.Socket socket;
  final String socketUrl = ApiEndpoints.socketUrl;
  bool _isConnected = false;
  
  Function(DetectionResult)? _onNewAlert;

  bool get isConnected => _isConnected;

  /// Initialize and connect to the Flask-SocketIO backend
  /// 
  /// [onNewAlert] - Callback function triggered when a new alert arrives
  /// The callback receives a DetectionResult object with the alert data
  void initializeSocket(Function(DetectionResult) onNewAlert) {
    _onNewAlert = onNewAlert;
    
    socket = IO.io(socketUrl, <String, dynamic>{
      'transports': ['websocket', 'polling'],
      'autoConnect': false,
      'reconnection': true,
      'reconnectionDelay': 1000,
      'reconnectionDelayMax': 5000,
      'reconnectionAttempts': 10,
      'secure': socketUrl.startsWith('https'),
      'rejectUnauthorized': false,
    });

    // Connection established
    socket.onConnect((_) {
      _isConnected = true;
      print('[AlertSocket] Connected to AA-IDS Alert Socket');
    });

    // Listen to the 'alert' event emitted from Backend
    socket.on('alert', (data) {
      try {
        // The backend may send data wrapped in a 'data' field or directly
        final alertData = data is Map && data.containsKey('data') 
            ? data['data'] 
            : data;
        
        final result = DetectionResult.fromJson(alertData);
        _onNewAlert?.call(result);
        print('[AlertSocket] New alert received: ${result.alertId}');
      } catch (e) {
        print("[AlertSocket] Error parsing socket alert data: $e");
      }
    });

    // Connection error
    socket.onError((error) {
      print('[AlertSocket] Socket error: $error');
      _isConnected = false;
    });

    // Disconnection
    socket.onDisconnect((_) {
      _isConnected = false;
      print('[AlertSocket] Disconnected from Socket');
    });

    // Reconnection attempts
    socket.on('reconnect_attempt', (_) {
      print('[AlertSocket] Attempting to reconnect...');
    });

    socket.on('reconnect_failed', (_) {
      print('[AlertSocket] Reconnection failed');
      _isConnected = false;
    });

    socket.connect();
  }

  /// Manually connect to socket
  void connect() {
    if (!_isConnected) {
      socket.connect();
    }
  }

  /// Disconnect from socket
  void disconnect() {
    if (_isConnected) {
      socket.disconnect();
      _isConnected = false;
    }
  }

  /// Dispose and cleanup socket resources
  void dispose() {
    disconnect();
    socket.dispose();
  }

  /// Emit custom event to backend (if needed)
  void emit(String eventName, dynamic data) {
    if (_isConnected) {
      socket.emit(eventName, data);
    } else {
      print('[AlertSocket] Cannot emit $eventName - socket not connected');
    }
  }

  /// Request alerts for a specific severity
  void requestAlertsForSeverity(String severity) {
    emit('request_alerts', {'severity': severity});
  }

  /// Subscribe to a specific alert type
  void subscribeToAlertType(String alertType) {
    emit('subscribe', {'type': alertType});
  }

  /// Unsubscribe from a specific alert type
  void unsubscribeFromAlertType(String alertType) {
    emit('unsubscribe', {'type': alertType});
  }
}
