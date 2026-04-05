class Incident {
  final String id;
  final String time;
  final String endpoint;
  final String method;
  final String threat;
  final String status;

  Incident({
    required this.id,
    required this.time,
    required this.endpoint,
    required this.method,
    required this.threat,
    required this.status,
  });
}