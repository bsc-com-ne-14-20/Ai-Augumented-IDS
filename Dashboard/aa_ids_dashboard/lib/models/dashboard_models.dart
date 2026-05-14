class Incident {
  final String id;
  final String time;
  final String endpoint;
  final String method;
  final String threat;           // "High", "Med", "Low"
  final String reviewedStatus;   // "Yes" or "Pending"  ← Changed/renamed

  // Detail panel fields
  final String name;
  final double score;
  final String sourceIp;
  final String detector;
  final String alertMessage;
  final String httpRequest;

  final int flagStep;

  Incident({
    required this.id,
    required this.time,
    required this.endpoint,
    required this.method,
    required this.threat,
    required this.reviewedStatus,        // New main field for Reviewed column
    required this.name,
    required this.score,
    required this.sourceIp,
    required this.detector,
    required this.alertMessage,
    required this.httpRequest,
    this.flagStep = 3,
  });

  // Copy constructor to create a modified copy of the incident
  Incident copyWith({
    String? id,
    String? time,
    String? endpoint,
    String? method,
    String? threat,
    String? reviewedStatus,
    String? name,
    double? score,
    String? sourceIp,
    String? detector,
    String? alertMessage,
    String? httpRequest,
    int? flagStep,
  }) {
    return Incident(
      id: id ?? this.id,
      time: time ?? this.time,
      endpoint: endpoint ?? this.endpoint,
      method: method ?? this.method,
      threat: threat ?? this.threat,
      reviewedStatus: reviewedStatus ?? this.reviewedStatus,
      name: name ?? this.name,
      score: score ?? this.score,
      sourceIp: sourceIp ?? this.sourceIp,
      detector: detector ?? this.detector,
      alertMessage: alertMessage ?? this.alertMessage,
      httpRequest: httpRequest ?? this.httpRequest,
      flagStep: flagStep ?? this.flagStep,
    );
  }

  factory Incident.fromJson(Map<String, dynamic> json) {
    double parseScore(dynamic value) {
      if (value is double) return value;
      if (value is int) return value.toDouble();
      if (value is String) return double.tryParse(value) ?? 0.0;
      return 0.0;
    }

    return Incident(
      id: json['id']?.toString() ?? '',
      time: json['time']?.toString() ?? '',
      endpoint: json['endpoint']?.toString() ?? '',
      method: json['method']?.toString() ?? '',
      threat: json['threat']?.toString() ?? '',
      reviewedStatus: json['reviewedStatus']?.toString() ?? 'Pending',
      name: json['name']?.toString() ?? '',
      score: parseScore(json['score']),
      sourceIp: json['sourceIp']?.toString() ?? '',
      detector: json['detector']?.toString() ?? '',
      alertMessage: json['alertMessage']?.toString() ?? '',
      httpRequest: json['httpRequest']?.toString() ?? '',
      flagStep: json['flagStep'] is int ? json['flagStep'] as int : int.tryParse(json['flagStep']?.toString() ?? '') ?? 3,
    );
  }
}

// ════════════════════════════════════════════════════════════════════════════
// API Contract Models (from frontend_api_contract.md)
// ════════════════════════════════════════════════════════════════════════════

/// LogEntry - Incoming request data for analysis
class LogEntry {
  final String method;
  final String url;
  final String path;
  final String queryString;
  final Map<String, dynamic> headers;
  final String body;
  final int responseCode;
  final int contentLength;
  final String timestamp;

  LogEntry({
    required this.method,
    required this.url,
    required this.path,
    required this.queryString,
    required this.headers,
    required this.body,
    required this.responseCode,
    required this.contentLength,
    required this.timestamp,
  });

  Map<String, dynamic> toJson() => {
    "method": method,
    "url": url,
    "path": path,
    "query_string": queryString,
    "headers": headers,
    "body": body,
    "response_code": responseCode,
    "content_length": contentLength,
    "timestamp": timestamp,
  };
}

/// RequestSummary - Contained in detection results
class RequestSummary {
  final String method;
  final String path;
  final String queryString;

  RequestSummary({
    required this.method,
    required this.path,
    required this.queryString,
  });

  factory RequestSummary.fromJson(Map<String, dynamic> json) {
    return RequestSummary(
      method: json['method'] ?? "",
      path: json['path'] ?? "",
      queryString: json['query_string'] ?? "",
    );
  }
}

/// DetectionResult - A single analyzed request verdict
class DetectionResult {
  final String alertId;
  final String timestamp;
  final String verdict;          // "CLEAN", "ATTACK", or "ANOMALY"
  final String? detectionSource; // "RULE", "ML", or null
  final String? severity;        // "low", "medium", "high", "critical", or null
  final String? attackType;      // e.g. "SQL_INJECTION", "UNKNOWN_ANOMALY"
  final String? ruleTriggered;
  final double? confidence;      // Only for ML detections
  final String? affectedField;
  final RequestSummary requestSummary;

  DetectionResult({
    required this.alertId,
    required this.timestamp,
    required this.verdict,
    this.detectionSource,
    this.severity,
    this.attackType,
    this.ruleTriggered,
    this.confidence,
    this.affectedField,
    required this.requestSummary,
  });

  factory DetectionResult.fromJson(Map<String, dynamic> json) {
    return DetectionResult(
      alertId: json['alert_id'],
      timestamp: json['timestamp'],
      verdict: json['verdict'],
      detectionSource: json['detection_source'],
      severity: json['severity'],
      attackType: json['attack_type'],
      ruleTriggered: json['rule_triggered'],
      confidence: (json['confidence'] as num?)?.toDouble(),
      affectedField: json['affected_field'],
      requestSummary: RequestSummary.fromJson(json['request_summary']),
    );
  }
}

/// HealthStatus - Backend health check response
class HealthStatus {
  final String status;
  final Map<String, dynamic>? details;

  HealthStatus({
    required this.status,
    this.details,
  });

  factory HealthStatus.fromJson(Map<String, dynamic> json) {
    return HealthStatus(
      status: json['status'] ?? 'unknown',
      details: json,
    );
  }
}

/// AnalysisResponse - Response from /analyze endpoint
class AnalysisResponse {
  final Map<String, dynamic> summary;
  final List<DetectionResult> results;

  AnalysisResponse({
    required this.summary,
    required this.results,
  });

  factory AnalysisResponse.fromJson(Map<String, dynamic> json) {
    List<DetectionResult> results = (json['results'] as List?)
        ?.map((item) => DetectionResult.fromJson(item))
        .toList() ?? [];
    
    return AnalysisResponse(
      summary: json['summary'] ?? {},
      results: results,
    );
  }
}

/// MetricsData - Dashboard metrics response
class MetricsData {
  final int totalRequestsAnalyzed;
  final int totalAttactsDetected;
  final int totalAnomaliesDetected;
  final int totalClean;
  final Map<String, dynamic> attackTypeBreakdown;
  final Map<String, dynamic> detectionSourceBreakdown;
  final Map<String, dynamic> severityBreakdown;
  final Map<String, dynamic> mlConfidenceDistribution;

  MetricsData({
    required this.totalRequestsAnalyzed,
    required this.totalAttactsDetected,
    required this.totalAnomaliesDetected,
    required this.totalClean,
    required this.attackTypeBreakdown,
    required this.detectionSourceBreakdown,
    required this.severityBreakdown,
    required this.mlConfidenceDistribution,
  });

  factory MetricsData.fromJson(Map<String, dynamic> json) {
    return MetricsData(
      totalRequestsAnalyzed: json['total_requests_analyzed'] ?? 0,
      totalAttactsDetected: json['total_attacks_detected'] ?? 0,
      totalAnomaliesDetected: json['total_anomalies_detected'] ?? 0,
      totalClean: json['total_clean'] ?? 0,
      attackTypeBreakdown: json['attack_type_breakdown'] ?? {},
      detectionSourceBreakdown: json['detection_source_breakdown'] ?? {},
      severityBreakdown: json['severity_breakdown'] ?? {},
      mlConfidenceDistribution: json['ml_confidence_distribution'] ?? {},
    );
  }
}

/// AlertsResponse - Paginated alerts response
class AlertsResponse {
  final List<DetectionResult> alerts;
  final int total;
  final int page;

  AlertsResponse({
    required this.alerts,
    required this.total,
    required this.page,
  });

  factory AlertsResponse.fromJson(Map<String, dynamic> json) {
    List<DetectionResult> alerts = (json['alerts'] as List?)
        ?.map((item) => DetectionResult.fromJson(item))
        .toList() ?? [];
    
    return AlertsResponse(
      alerts: alerts,
      total: json['total'] ?? 0,
      page: json['page'] ?? 1,
    );
  }
}
