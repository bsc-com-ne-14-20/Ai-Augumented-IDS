import 'package:flutter/material.dart';
import '../custom_widgets/dashboard_metric_card.dart';
import '../custom_widgets/incident_list.dart';
import '../custom_widgets/incident_detail_panel.dart';
import '../custom_widgets/app_bar.dart';
import '/models/dashboard_models.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  Incident? _selectedIncident;

  // Sample data
  final List<Incident> sampleIncidents = [
    Incident(
      id: "INC-0047",
      time: "14:31",
      endpoint: "/api/login",
      method: "POST",
      threat: "High",
      reviewedStatus: "Pending",
      name: "SQL Injection Attempt",
      score: 0.94,
      sourceIp: "192.168.4.77",
      detector: "ML Model",
      alertMessage: "Malicious SQLi payload in POST body at web server ingress",
      httpRequest: "POST /api/login HTTP/1.1\nHost: target.app.internal\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin' OR '1'='1&password=test",
    ),
    Incident(
      id: "INC-0046",
      time: "14:28",
      endpoint: "/admin/cfg",
      method: "GET",
      threat: "High",
      reviewedStatus: "Pending",
      name: "Path Traversal Attempt",
      score: 0.88,
      sourceIp: "10.10.5.22",
      detector: "Signature",
      alertMessage: "Directory traversal pattern detected in request URI",
      httpRequest: "GET /admin/cfg/../../../etc/passwd HTTP/1.1\nHost: target.app.internal",
    ),
    Incident(
      id: "INC-0045",
      time: "14:22",
      endpoint: "/api/users",
      method: "POST",
      threat: "Med",
      reviewedStatus: "Yes",
      name: "Brute Force Login",
      score: 0.71,
      sourceIp: "203.0.113.9",
      detector: "ML Model",
      alertMessage: "847 failed login attempts from single IP in 60 seconds",
      httpRequest: "POST /api/users HTTP/1.1\nHost: target.app.internal",
    ),
    Incident(
      id: "INC-0044",
      time: "14:17",
      endpoint: "/search",
      method: "GET",
      threat: "Med",
      reviewedStatus: "Pending",
      name: "XSS Payload Detected",
      score: 0.67,
      sourceIp: "172.16.0.88",
      detector: "Signature",
      alertMessage: "Reflected XSS vector in query string parameter",
      httpRequest: "GET /search?q=<script>alert(1)</script> HTTP/1.1",
    ),
    Incident(
      id: "INC-0043",
      time: "14:12",
      endpoint: "/api/export",
      method: "POST",
      threat: "High",
      reviewedStatus: "Yes",
      name: "CSRF Token Violation",
      score: 0.82,
      sourceIp: "198.51.100.45",
      detector: "Signature",
      alertMessage: "Missing or invalid CSRF token in state-changing request",
      httpRequest: "POST /api/export HTTP/1.1\nHost: target.app.internal\nReferer: target.app.internal\n\nformat=pdf",
    ),
    Incident(
      id: "INC-0042",
      time: "14:08",
      endpoint: "/upload",
      method: "POST",
      threat: "Low",
      reviewedStatus: "Yes",
      name: "Suspicious File Upload",
      score: 0.45,
      sourceIp: "192.0.2.12",
      detector: "ML Model",
      alertMessage: "File upload with potentially malicious extension detected",
      httpRequest: "POST /upload HTTP/1.1\nHost: target.app.internal\nContent-Type: multipart/form-data",
    ),
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0B0F14),
      appBar: const CustomAppBar(),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // ==================== METRIC CARDS ====================
              const Text(
                "OVERVIEW",
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w500,
                  color: Color(0xFF6E7681),
                  letterSpacing: 1,
                ),
              ),
              const SizedBox(height: 12),

              Row(
                children: [
                  Expanded(
                    child: DashboardMetricCard(
                      title: "TOTAL INCIDENTS LOGGED",
                      value: "47",
                      accentColor: const Color(0xFF4A9EFF),
                      icon: Icons.list_alt_rounded,
                      showBottomSection: false,
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: DashboardMetricCard(
                      title: "REQUESTS INSPECTED",
                      value: "84.2k",
                      accentColor: const Color(0xFF9B6BFF),
                      icon: Icons.article_outlined,
                      showBottomSection: false,
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: DashboardMetricCard(
                      title: "DETECTION RATE",
                      value: "0.056%",
                      accentColor: const Color(0xFFFFC107),
                      icon: Icons.insights_rounded,
                      showBottomSection: false,
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: DashboardMetricCard(
                      title: "UNREVIEWED ALERTS",
                      value: "19",
                      accentColor: const Color(0xFFFF5C5C),
                      icon: Icons.warning_amber_rounded,
                      showBottomSection: false,
                    ),
                  ),
                ],
              ),

              const SizedBox(height: 32),

              // ==================== MAIN CONTENT: LIST + DETAIL ====================
              Expanded(
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // Incident List (Left - takes more space)
                    Expanded(
                      flex: 7,
                      child: IncidentList(
                        incidents: sampleIncidents,
                        onIncidentSelected: (incident) {
                          setState(() {
                            _selectedIncident = incident;
                          });
                        },
                        onIncidentStatusUpdated: (updatedIncident) {
                          setState(() {
                            // Find and update the incident in the list
                            final index = sampleIncidents.indexWhere(
                              (inc) => inc.id == updatedIncident.id,
                            );
                            if (index != -1) {
                              sampleIncidents[index] = updatedIncident;
                              // Also update the selected incident if it's the same one
                              if (_selectedIncident?.id == updatedIncident.id) {
                                _selectedIncident = updatedIncident;
                              }
                            }
                          });
                        },
                      ),
                    ),

                    const SizedBox(width: 16),

                    // Detail Panel (Right)
                    Expanded(
                      flex: 5,
                      child: IncidentDetailPanel(
                        incident: _selectedIncident,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}