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
      status: "Open",
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
      status: "Open",
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
      status: "Open",
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
      status: "Open",
      name: "XSS Payload Detected",
      score: 0.67,
      sourceIp: "172.16.0.88",
      detector: "Signature",
      alertMessage: "Reflected XSS vector in query string parameter",
      httpRequest: "GET /search?q=<script>alert(1)</script> HTTP/1.1",
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
                      title: "TOTAL INCIDENTS",
                      value: "47",
                      badgeText: "+6 today",
                      subtitle: "since last shift",
                      accentColor: const Color(0xFF79C0FF),
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: DashboardMetricCard(
                      title: "ACTIVE THREATS",
                      value: "12",
                      badgeText: "3 critical",
                      subtitle: "require attention",
                      accentColor: const Color(0xFFFF7B72),
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: DashboardMetricCard(
                      title: "REQUESTS PROCESSED",
                      value: "84.2k",
                      badgeText: "+1.2k/min",
                      subtitle: "current rate",
                      accentColor: const Color(0xFFE3B341),
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: DashboardMetricCard(
                      title: "RESOLVED TODAY",
                      value: "35",
                      badgeText: "74.5%",
                      subtitle: "resolution rate",
                      accentColor: const Color(0xFF56D364),
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