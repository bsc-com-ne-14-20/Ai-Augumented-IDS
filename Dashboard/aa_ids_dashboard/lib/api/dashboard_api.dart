import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:aa_ids_dashboard/api/endpoints.dart';
import 'package:aa_ids_dashboard/models/dashboard_models.dart';
import 'dart:async';

class DashboardApi {

  // ── GET /health ────────────────────────────────────────────────────────────

  /// Check backend health status
  Future<HealthStatus> checkHealth() async {
    try {
      final response = await http.get(Uri.parse(ApiEndpoints.health))
          .timeout(const Duration(seconds: 15));
      
      if (response.statusCode == 200) {
        final jsonData = json.decode(response.body);
        return HealthStatus.fromJson(jsonData);
      } else {
        throw Exception('Failed to load health status: ${response.statusCode}');
      }
    } on TimeoutException catch (_) {
      throw Exception('Health check timeout - server not responding');
    } catch (e) {
      throw Exception('Health check error: $e');
    }
  }

  // ── POST /analyze ─────────────────────────────────────────────────────────

  /// Analyze a list of log entries for security threats
  Future<AnalysisResponse> analyzeLogs(List<LogEntry> logs) async {
    try {
      final body = json.encode({
        "logs": logs.map((l) => l.toJson()).toList(),
      });

      final response = await http.post(
        Uri.parse(ApiEndpoints.analyze),
        headers: {'Content-Type': 'application/json'},
        body: body,
      ).timeout(const Duration(seconds: 30));

      if (response.statusCode == 200) {
        final jsonData = json.decode(response.body);
        return AnalysisResponse.fromJson(jsonData);
      } else if (response.statusCode == 422) {
        final error = json.decode(response.body);
        throw Exception('Validation Error: ${error['detail']}');
      } else {
        throw Exception('Server Error: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Analysis error: $e');
    }
  }

  // ── GET /metrics ───────────────────────────────────────────────────────────

  /// Fetch dashboard metrics for visualizations
  /// Required to populate overview cards, charts, and indicators
  Future<MetricsData> fetchMetrics() async {
    try {
      final response = await http.get(Uri.parse(ApiEndpoints.metrics))
          .timeout(const Duration(seconds: 15));
      
      if (response.statusCode == 200) {
        final jsonData = json.decode(response.body);
        return MetricsData.fromJson(jsonData);
      } else {
        throw Exception('Failed to load metrics: ${response.statusCode}');
      }
    } on TimeoutException catch (_) {
      throw Exception('Metrics fetch timeout - server not responding');
    } catch (e) {
      throw Exception('Metrics fetch error: $e');
    }
  }

  // ── GET /alerts ────────────────────────────────────────────────────────────

  /// Fetch paginated alerts with optional filtering
  /// 
  /// Parameters:
  /// - [page] - Page number (1-indexed), default 1
  /// - [pageSize] - Results per page, default 50
  /// - [verdict] - Filter by verdict: "CLEAN", "ATTACK", or "ANOMALY" (optional)
  /// - [severity] - Filter by severity: "low", "medium", "high", "critical" (optional)
  Future<AlertsResponse> fetchAlerts({
    int page = 1,
    int pageSize = 50,
    String? verdict,
    String? severity,
  }) async {
    try {
      final queryParams = {
        'page': page.toString(),
        'limit': pageSize.toString(),
      };
      
      if (verdict != null && verdict.isNotEmpty) {
        queryParams['verdict'] = verdict;
      }
      if (severity != null && severity.isNotEmpty) {
        queryParams['severity'] = severity;
      }

      final uri = Uri.parse(ApiEndpoints.alerts)
          .replace(queryParameters: queryParams);
      
      final response = await http.get(uri)
          .timeout(const Duration(seconds: 10));
      
      if (response.statusCode == 200) {
        final jsonData = json.decode(response.body);
        return AlertsResponse.fromJson(jsonData);
      } else {
        throw Exception('Failed to load alerts: ${response.statusCode}');
      }
    } catch (e) {
      throw Exception('Alerts fetch error: $e');
    }
  }

  // ── Helper Methods ─────────────────────────────────────────────────────────

  /// Convert a DetectionResult to an Incident for display in the dashboard
  /// ════════════════════════════════════════════════════════════════════════════
  /// SINGLE SOURCE OF TRUTH: This is the ONLY place where DetectionResult 
  /// (API response) is converted to Incident (UI model).
  /// All field mappings must be documented here and stay in sync with both models.
  /// See Incident model comments for the complete mapping table.
  Incident detectionResultToIncident(DetectionResult result) {
    return Incident(
      id: result.alertId,
      time: _extractTime(result.timestamp),
      endpoint: result.requestSummary.path,
      method: result.requestSummary.method,
      threat: _severityToThreat(result.severity),
      reviewedStatus: 'No',
      name: result.attackType ?? 'Unknown',
      score: result.confidence ?? 0.0,
      sourceIp: result.sourceIp ?? 'N/A',  // Now from API, fallback to N/A if missing
      detector: result.detectionSource ?? 'Unknown',
      alertMessage: result.verdict,
      httpRequest: 'GET ${result.requestSummary.path}${result.requestSummary.queryString.isNotEmpty ? '?${result.requestSummary.queryString}' : ''}',
      attackType: result.attackType,
    );
  }

  /// Extract time from ISO 8601 timestamp
  String _extractTime(String timestamp) {
    try {
      final dateTime = DateTime.parse(timestamp);
      return '${dateTime.hour.toString().padLeft(2, '0')}:${dateTime.minute.toString().padLeft(2, '0')}:${dateTime.second.toString().padLeft(2, '0')}';
    } catch (e) {
      return 'N/A';
    }
  }

  /// Map severity to threat level display
  String _severityToThreat(String? severity) {
    switch (severity?.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'High';
      case 'medium':
        return 'Med';
      case 'low':
        return 'Low';
      default:
        return 'Med';
    }
  }
}
