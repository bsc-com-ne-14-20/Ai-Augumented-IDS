import 'dart:async';
import 'package:flutter/material.dart';
import 'package:aa_ids_dashboard/api/dashboard_api.dart';
import 'package:aa_ids_dashboard/api/alert_socket_service.dart';
import 'package:aa_ids_dashboard/models/dashboard_models.dart';

class DashboardProvider extends ChangeNotifier {
  // API instances
  final DashboardApi _dashboardApi = DashboardApi();
  late final AlertSocketService _socketService;

  // ═══════════════════════════════════════════════════════════════════════════
  // STATE VARIABLES
  // ═══════════════════════════════════════════════════════════════════════════

  // Incidents/Alerts List (from socket)
  List<Incident> _incidents = [];

  // Socket/Real-time
  bool _socketConnected = false;
  bool _socketEnabled = false;
  String? _socketError;
  
  // Global loading state
  bool _isAppLoading = false;
  Timer? _loadingTimeout;

  // ═══════════════════════════════════════════════════════════════════════════
  // GETTERS
  // ═══════════════════════════════════════════════════════════════════════════

  // Incidents/Alerts
  List<Incident> get incidents => _incidents;

  // Socket/Real-time
  bool get socketConnected => _socketConnected;
  bool get socketEnabled => _socketEnabled;
  String? get socketError => _socketError;
  
  // Global loading
  bool get isAppLoading => _isAppLoading;

  // ═══════════════════════════════════════════════════════════════════════════
  // INITIALIZATION
  // ═══════════════════════════════════════════════════════════════════════════

  /// Initialize dashboard - connect to real-time alert socket
  /// Call this when the dashboard mounts
  Future<void> loadInitialDashboardData() async {
    initializeRealtimeAlerts();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SOCKET.IO REAL-TIME METHODS
  // ═══════════════════════════════════════════════════════════════════════════

  /// Initialize and connect to real-time alert socket
  void initializeRealtimeAlerts() {
    if (_socketEnabled) {
      return;
    }

    try {
      _socketService = AlertSocketService();
      _socketService.initializeSocket(
        _handleNewAlert,
        onConnectionStatusChanged: _handleSocketConnectionStatusChange,
      );
      _socketEnabled = true;
      _socketError = null;
      notifyListeners();
    } catch (e) {
      _socketError = e.toString();
      _socketEnabled = false;
      notifyListeners();
    }
  }

  /// Handle socket connection status changes
  void _handleSocketConnectionStatusChange(bool isConnected) {
    _socketConnected = isConnected;
    notifyListeners();
  }

  /// Handle new alert from socket and add to incidents list
  void _handleNewAlert(DetectionResult result) {
    try {
      _socketConnected = _socketService.isConnected;
      
      // Convert to Incident and prepend to list
      final incident = _dashboardApi.detectionResultToIncident(result);
      _incidents.insert(0, incident);
      notifyListeners();
    } catch (e) {
      // Silent catch for malformed alerts
    }
  }

  /// Connect to real-time alert stream
  void connectRealtimeAlerts() {
    if (_socketEnabled) {
      _socketService.connect();
    }
  }

  /// Disconnect from real-time alert stream
  void disconnectRealtimeAlerts() {
    if (_socketEnabled) {
      _socketService.disconnect();
      _socketConnected = false;
      notifyListeners();
    }
  }

  /// Subscribe to alerts of specific severity
  void subscribeToSeverity(String severity) {
    if (_socketEnabled && _socketService.isConnected) {
      _socketService.requestAlertsForSeverity(severity);
    }
  }

  /// Subscribe to alerts of specific type
  void subscribeToAlertType(String alertType) {
    if (_socketEnabled && _socketService.isConnected) {
      _socketService.subscribeToAlertType(alertType);
    }
  }

  /// Unsubscribe from specific alert type
  void unsubscribeFromAlertType(String alertType) {
    if (_socketEnabled && _socketService.isConnected) {
      _socketService.unsubscribeFromAlertType(alertType);
    }
  }

  /// Mark incident as reviewed
  void markIncidentAsReviewed(String incidentId) {
    final index = _incidents.indexWhere((inc) => inc.id == incidentId);
    if (index != -1) {
      _incidents[index] = _incidents[index].copyWith(reviewedStatus: 'Yes');
      notifyListeners();
    }
  }

  /// Get specific incident by ID
  Incident? getIncidentById(String incidentId) {
    try {
      return _incidents.firstWhere((inc) => inc.id == incidentId);
    } catch (e) {
      return null;
    }
  }

  /// Clear all data
  void clearAll() {
    _incidents = [];
    notifyListeners();
  }

  /// Dispose of all resources including socket connection
  void dispose() {
    _loadingTimeout?.cancel();
    if (_socketEnabled) {
      _socketService.dispose();
    }
    super.dispose();
  }
}
