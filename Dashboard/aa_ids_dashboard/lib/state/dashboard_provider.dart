import 'package:flutter/material.dart';
import 'package:aa_ids_dashboard/api/dashboard_api.dart';
import 'package:aa_ids_dashboard/models/dashboard_models.dart';

class DashboardProvider extends ChangeNotifier {
  // API instance
  final DashboardApi _dashboardApi = DashboardApi();

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

  // ═══════════════════════════════════════════════════════════════════════════
  // API METHODS
  // ═══════════════════════════════════════════════════════════════════════════

  /// Check backend health status
  Future<void> checkHealth() async {
    _healthCheckLoading = true;
    _healthError = null;
    notifyListeners();

    try {
      _healthStatus = await _dashboardApi.checkHealth();
    } catch (e) {
      _healthError = e.toString().replaceAll('Exception: ', '');
      _healthStatus = null;
    } finally {
      _healthCheckLoading = false;
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
    notifyListeners();

    try {
      _metrics = await _dashboardApi.fetchMetrics();
    } catch (e) {
      _metricsError = e.toString().replaceAll('Exception: ', '');
      _metrics = null;
    } finally {
      _metricsLoading = false;
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
    
    if (resetPagination) {
      _currentPage = 1;
    }
    
    final pageNum = page ?? _currentPage;
    final pageSizeNum = pageSize ?? _pageSize;
    
    if (verdict != null) _verdictFilter = verdict;
    if (severity != null) _severityFilter = severity;
    
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
    } catch (e) {
      _detectionResultsError = e.toString().replaceAll('Exception: ', '');
      _detectionResults = [];
      _incidents = [];
    } finally {
      _detectionResultsLoading = false;
      notifyListeners();
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HELPER METHODS
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
}
