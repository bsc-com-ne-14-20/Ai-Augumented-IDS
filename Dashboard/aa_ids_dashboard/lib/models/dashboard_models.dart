
class Incident {
  final String id;
  final String time;
  final String endpoint;
  final String method;
  final String threat;        // "High", "Med", "Low"
  final String status;        // "Open", "Resolved"
  
  final String name;          // Incident title / name
  final double score;         // Anomaly score (0.0 - 1.0)
  final String sourceIp;
  final String detector;      // e.g., "ML Model", "Signature"
  final String alertMessage;
  final String httpRequest;
  
  final int flagStep;         // For future network trace (1-5)

  Incident({
    required this.id,
    required this.time,
    required this.endpoint,
    required this.method,
    required this.threat,
    required this.status,
    required this.name,
    required this.score,
    required this.sourceIp,
    required this.detector,
    required this.alertMessage,
    required this.httpRequest,
    this.flagStep = 3,
  });

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
      status: json['status']?.toString() ?? '',
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