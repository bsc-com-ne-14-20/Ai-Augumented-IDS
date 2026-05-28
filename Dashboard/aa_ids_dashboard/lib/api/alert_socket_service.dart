import 'package:socket_io_client/socket_io_client.dart' as IO;
import 'package:aa_ids_dashboard/api/endpoints.dart';
import 'package:aa_ids_dashboard/models/dashboard_models.dart';
import 'dart:async';

/// Socket.IO Service for real-time live alert feed
/// Connects to the Flask-SocketIO backend to receive live detection alerts
class AlertSocketService {
  late IO.Socket socket;
  final String socketUrl = ApiEndpoints.socketUrl;
  bool _isConnected = false;
  
  // Socket timeout configuration
  static const Duration socketTimeout = Duration(seconds: 30);
  Timer? _connectionTimeoutTimer;
  Timer? _heartbeatTimer;
  
  Function(DetectionResult)? _onNewAlert;
  Function(bool)? _onConnectionStatusChanged; // Callback for connection status changes

  bool get isConnected => _isConnected;

  /// Initialize and connect to the Flask-SocketIO backend
  /// 
  /// [onNewAlert] - Callback function triggered when a new alert arrives
  /// The callback receives a DetectionResult object with the alert data
  /// [onConnectionStatusChanged] - Optional callback for connection status changes (true = connected, false = disconnected)
  void initializeSocket(
    Function(DetectionResult) onNewAlert, {
    Function(bool)? onConnectionStatusChanged,
  }) {
    _onNewAlert = onNewAlert;
    _onConnectionStatusChanged = onConnectionStatusChanged;
    
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
      _cancelConnectionTimeout();
      _startHeartbeat();
      print('[AlertSocket] Connected to AA-IDS Alert Socket');
      _onConnectionStatusChanged?.call(true);
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
      _cancelConnectionTimeout();
      _stopHeartbeat();
      _onConnectionStatusChanged?.call(false);
    });

    // Disconnection
    socket.onDisconnect((_) {
      _isConnected = false;
      _cancelConnectionTimeout();
      _stopHeartbeat();
      print('[AlertSocket] Disconnected from Socket');
      _onConnectionStatusChanged?.call(false);
    });

    // Reconnection attempts
    socket.on('reconnect_attempt', (_) {
      print('[AlertSocket] Attempting to reconnect...');
      _startConnectionTimeout();
    });

    socket.on('reconnect_failed', (_) {
      print('[AlertSocket] Reconnection failed');
      _isConnected = false;
      _cancelConnectionTimeout();
      _stopHeartbeat();
      _onConnectionStatusChanged?.call(false);
    });

    socket.connect();
  }

  /// Start connection timeout timer
  void _startConnectionTimeout() {
    _cancelConnectionTimeout();
    _connectionTimeoutTimer = Timer(socketTimeout, () {
      if (!_isConnected) {
        print('[AlertSocket] Connection timeout after ${socketTimeout.inSeconds}s. Forcing disconnect...');
        disconnect();
        // Attempt to reconnect
        Future.delayed(const Duration(seconds: 2), () {
          connect();
        });
      }
    });
  }

  /// Cancel connection timeout timer
  void _cancelConnectionTimeout() {
    _connectionTimeoutTimer?.cancel();
    _connectionTimeoutTimer = null;
  }

  /// Start heartbeat to keep connection alive
  void _startHeartbeat() {
    _stopHeartbeat();
    _heartbeatTimer = Timer.periodic(const Duration(seconds: 60), (_) {
      if (_isConnected) {
        socket.emit('ping');
        print('[AlertSocket] Heartbeat ping sent');
      }
    });
  }

  /// Stop heartbeat timer
  void _stopHeartbeat() {
    _heartbeatTimer?.cancel();
    _heartbeatTimer = null;
  }

  /// Manually connect to socket
  void connect() {
    if (!_isConnected) {
      _startConnectionTimeout();
      socket.connect();
    }
  }

  /// Disconnect from socket
  void disconnect() {
    if (_isConnected) {
      _cancelConnectionTimeout();
      _stopHeartbeat();
      socket.disconnect();
      _isConnected = false;
      _onConnectionStatusChanged?.call(false);
    }
  }

  /// Dispose and cleanup socket resources
  void dispose() {
    disconnect();
    _cancelConnectionTimeout();
    _stopHeartbeat();
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
