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

  // Health Status
  HealthStatus? _healthStatus;
  bool _healthCheckLoading = false;
  String? _healthError;

  // Incidents/Alerts List
  List<Incident> _incidents = [];
  final bool _incidentsLoading = false;
  String? _incidentsError;

  // Metrics
  MetricsData? _metrics;
  bool _metricsLoading = false;
  String? _metricsError;

  // Analysis
  AnalysisResponse? _lastAnalysisResponse;
  bool _analysisLoading = false;
  String? _analysisError;

  // Detection Results
  List<DetectionResult> _detectionResults = [];
  bool _detectionResultsLoading = false;
  String? _detectionResultsError;

  // Pagination
  int _currentPage = 1;
  int _pageSize = 50;
  int _totalAlerts = 0;

  // Filtering
  String? _verdictFilter;
  String? _severityFilter;

  // Socket/Real-time
  bool _socketConnected = false;
  bool _socketEnabled = false;
  String? _socketError;
  
  // Global loading state - shows when any critical operation is pending
  bool _isAppLoading = false;
  Timer? _loadingTimeout;

  // ═══════════════════════════════════════════════════════════════════════════
  // GETTERS
  // ═══════════════════════════════════════════════════════════════════════════

  // Health
  HealthStatus? get healthStatus => _healthStatus;
  bool get healthCheckLoading => _healthCheckLoading;
  String? get healthError => _healthError;

  // Incidents/Alerts
  List<Incident> get incidents => _incidents;
  bool get incidentsLoading => _incidentsLoading;
  String? get incidentsError => _incidentsError;

  // Metrics
  MetricsData? get metrics => _metrics;
  bool get metricsLoading => _metricsLoading;
  String? get metricsError => _metricsError;

  // Analysis
  AnalysisResponse? get lastAnalysisResponse => _lastAnalysisResponse;
  bool get analysisLoading => _analysisLoading;
  String? get analysisError => _analysisError;

  // Detection Results
  List<DetectionResult> get detectionResults => _detectionResults;
  bool get detectionResultsLoading => _detectionResultsLoading;
  String? get detectionResultsError => _detectionResultsError;

  // Pagination
  int get currentPage => _currentPage;
  int get pageSize => _pageSize;
  int get totalAlerts => _totalAlerts;
  int get totalPages => (_totalAlerts / _pageSize).ceil();

  // Filters
  String? get verdictFilter => _verdictFilter;
  String? get severityFilter => _severityFilter;

  // Socket/Real-time
  bool get socketConnected => _socketConnected;
  bool get socketEnabled => _socketEnabled;
  String? get socketError => _socketError;
  
  // Global loading
  bool get isAppLoading => _isAppLoading;

  // ═══════════════════════════════════════════════════════════════════════════
  // API METHODS
  // ═══════════════════════════════════════════════════════════════════════════

  /// Check backend health status
  Future<void> checkHealth() async {
    _healthCheckLoading = true;
    _healthError = null;
    _setAppLoading(true);
    print('[Provider] checkHealth() - Request started');
    notifyListeners();

    try {
      _healthStatus = await _dashboardApi.checkHealth();
      print('[Provider] checkHealth() - Success: ${_healthStatus?.status}');
    } catch (e) {
      _healthError = e.toString().replaceAll('Exception: ', '');
      _healthStatus = null;
      print('[Provider] checkHealth() - Error: $_healthError');
    } finally {
      _healthCheckLoading = false;
      _clearAppLoadingIfAllDone();
      notifyListeners();
    }
  }

  /// Analyze logs and get detection results
  Future<void> analyzeLogs(List<LogEntry> logs) async {
    _analysisLoading = true;
    _analysisError = null;
    _detectionResults = [];
    _incidents = [];
    notifyListeners();

    try {
      _lastAnalysisResponse = await _dashboardApi.analyzeLogs(logs);
      _detectionResults = _lastAnalysisResponse?.results ?? [];
      
      // Convert DetectionResults to Incidents for display
      _incidents = _detectionResults
          .map((result) => _dashboardApi.detectionResultToIncident(result))
          .toList();
    } catch (e) {
      _analysisError = e.toString().replaceAll('Exception: ', '');
      _detectionResults = [];
      _incidents = [];
    } finally {
      _analysisLoading = false;
      notifyListeners();
    }
  }

  /// Fetch metrics for dashboard visualizations
  Future<void> fetchMetrics() async {
    _metricsLoading = true;
    _metricsError = null;
    _setAppLoading(true);
    print('[Provider] fetchMetrics() - Request started');
    notifyListeners();

    try {
      _metrics = await _dashboardApi.fetchMetrics();
      print('[Provider] fetchMetrics() - Success: totalAttacksDetected=${_metrics?.totalAttactsDetected}, totalRequestsAnalyzed=${_metrics?.totalRequestsAnalyzed}');
    } catch (e) {
      _metricsError = e.toString().replaceAll('Exception: ', '');
      _metrics = null;
      print('[Provider] fetchMetrics() - Error: $_metricsError');
    } finally {
      _metricsLoading = false;
      _clearAppLoadingIfAllDone();
      notifyListeners();
    }
  }

  /// Fetch alerts with optional filtering and pagination
  Future<void> fetchAlerts({
    int? page,
    int? pageSize,
    String? verdict,
    String? severity,
    bool resetPagination = false,
  }) async {
    _detectionResultsLoading = true;
    _detectionResultsError = null;
    _setAppLoading(true);
    
    if (resetPagination) {
      _currentPage = 1;
    }
    
    final pageNum = page ?? _currentPage;
    final pageSizeNum = pageSize ?? _pageSize;
    
    if (verdict != null) _verdictFilter = verdict;
    if (severity != null) _severityFilter = severity;
    
    print('[Provider] fetchAlerts() - Request started (page=$pageNum, pageSize=$pageSizeNum, verdict=$_verdictFilter, severity=$_severityFilter)');
    notifyListeners();

    try {
      final response = await _dashboardApi.fetchAlerts(
        page: pageNum,
        pageSize: pageSizeNum,
        verdict: _verdictFilter,
        severity: _severityFilter,
      );
      
      _detectionResults = response.alerts;
      _totalAlerts = response.total;
      _currentPage = response.page;
      _pageSize = pageSizeNum;
      
      // Convert to Incidents for compatibility
      _incidents = _detectionResults
          .map((result) => _dashboardApi.detectionResultToIncident(result))
          .toList();
      
      print('[Provider] fetchAlerts() - Success: loaded ${_incidents.length} incidents (total: $_totalAlerts)');
    } catch (e) {
      _detectionResultsError = e.toString().replaceAll('Exception: ', '');
      _detectionResults = [];
      _incidents = [];
      print('[Provider] fetchAlerts() - Error: $_detectionResultsError');
    } finally {
      _detectionResultsLoading = false;
      _clearAppLoadingIfAllDone();
      notifyListeners();
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SOCKET.IO REAL-TIME METHODS
  // ═══════════════════════════════════════════════════════════════════════════

  /// Initialize and connect to real-time alert socket
  /// Call this in your main app initialization (e.g., in initState of root widget)
  void initializeRealtimeAlerts() {
    try {
      _socketService = AlertSocketService();
      _socketService.initializeSocket(
        _handleNewAlert,
        onConnectionStatusChanged: _handleSocketConnectionStatusChange,
      );
      _socketEnabled = true;
      _socketError = null;
      print('[Provider] Real-time alerts initialized');
      notifyListeners();
    } catch (e) {
      _socketError = e.toString();
      _socketEnabled = false;
      print('[Provider] Error initializing real-time alerts: $e');
      notifyListeners();
    }
  }

  /// Handle socket connection status changes
  void _handleSocketConnectionStatusChange(bool isConnected) {
    _socketConnected = isConnected;
    print('[Provider] Socket connection status changed: $_socketConnected');
    
    // Socket connected - clear loading state after a brief delay to allow UI to settle
    if (isConnected) {
      Future.delayed(const Duration(milliseconds: 500), () {
        _clearAppLoadingIfAllDone();
        notifyListeners();
      });
    }
    
    notifyListeners();
  }
  
  /// Set app loading state with automatic timeout
  void _setAppLoading(bool value) {
    _isAppLoading = value;
    if (value) {
      // Auto-clear loading state after 15 seconds (safety timeout)
      _loadingTimeout?.cancel();
      _loadingTimeout = Timer(const Duration(seconds: 15), () {
        print('[Provider] ⚠️ Loading timeout - clearing loading state');
        _clearAppLoadingIfAllDone();
        notifyListeners();
      });
    }
  }
  
  /// Clear app loading state if all critical operations are done
  void _clearAppLoadingIfAllDone() {
    if (!_healthCheckLoading && !_metricsLoading && !_detectionResultsLoading) {
      _isAppLoading = false;
      _loadingTimeout?.cancel();
      print('[Provider] All critical operations completed - clearing loading state');
    }
  }

  /// Handle new alert from socket and add to incidents list
  void _handleNewAlert(DetectionResult result) {
    try {
      _socketConnected = _socketService.isConnected;
      
      // Convert to Incident and prepend to list
      final incident = _dashboardApi.detectionResultToIncident(result);
      _incidents.insert(0, incident);
      _detectionResults.insert(0, result);
      _totalAlerts++;

      print('[Provider] New alert added to incidents list: ${result.alertId}');
      notifyListeners();

      // Optional: Show notification for high/critical severity
      if (result.severity != null && 
          (result.severity!.toLowerCase() == 'critical' || 
           result.severity!.toLowerCase() == 'high')) {
        print('[Provider] ⚠️ HIGH SEVERITY ALERT: ${result.severity}');
      }
    } catch (e) {
      print('[Provider] Error handling new alert: $e');
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

  // ═══════════════════════════════════════════════════════════════════════════

  /// Go to next page
  Future<void> nextPage() async {
    if (_currentPage < totalPages) {
      await fetchAlerts(page: _currentPage + 1);
    }
  }

  /// Go to previous page
  Future<void> previousPage() async {
    if (_currentPage > 1) {
      await fetchAlerts(page: _currentPage - 1);
    }
  }

  /// Go to specific page
  Future<void> goToPage(int page) async {
    if (page > 0 && page <= totalPages) {
      await fetchAlerts(page: page);
    }
  }

  /// Clear all filters and reset pagination
  Future<void> clearFilters() async {
    _verdictFilter = null;
    _severityFilter = null;
    await fetchAlerts(resetPagination: true);
  }

  /// Set verdict filter
  Future<void> setVerdictFilter(String? verdict) async {
    _verdictFilter = verdict;
    await fetchAlerts(resetPagination: true, verdict: verdict);
  }

  /// Set severity filter
  Future<void> setSeverityFilter(String? severity) async {
    _severityFilter = severity;
    await fetchAlerts(resetPagination: true, severity: severity);
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
    _detectionResults = [];
    _metrics = null;
    _healthStatus = null;
    _lastAnalysisResponse = null;
    _analysisError = null;
    _detectionResultsError = null;
    _metricsError = null;
    _healthError = null;
    _incidentsError = null;
    _currentPage = 1;
    _totalAlerts = 0;
    _verdictFilter = null;
    _severityFilter = null;
    notifyListeners();
  }

  /// Dispose of all resources including socket connection
  /// Call this when the provider is being destroyed
  void dispose() {
    _loadingTimeout?.cancel();
    if (_socketEnabled) {
      _socketService.dispose();
    }
    super.dispose();
  }
}
