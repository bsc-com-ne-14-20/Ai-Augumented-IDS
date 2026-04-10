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
