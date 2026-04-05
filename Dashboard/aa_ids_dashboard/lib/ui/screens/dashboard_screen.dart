import 'package:flutter/material.dart';
import '../custom_widgets/dashboard_metric_card.dart';
import '../custom_widgets/incident_list.dart';
import '/models/dashboard_models.dart';

final List<Incident> sampleIncidents = [
                Incident(id: "INC-0047", time: "14:31", endpoint: "/api/login", method: "POST", threat: "High", status: "Open"),
                Incident(id: "INC-0046", time: "14:28", endpoint: "/admin/cfg", method: "GET", threat: "High", status: "Open"),
                Incident(id: "INC-0045", time: "14:22", endpoint: "/api/users", method: "POST", threat: "Medium", status: "Open"),
                // ... add more
              ];
class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Theme.of(context).scaffoldBackgroundColor,
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Top Row of Metric Cards
              Row(
                children: [
                  Expanded(
                    child: DashboardMetricCard(
                      title: "Total Traffic",
                      value: "2.4 GB",
                      badgeText: "Live",
                      subtitle: "Total network throughput",
                      accentColor: Colors.blueAccent,
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: DashboardMetricCard(
                      title: "Security Alerts",
                      value: "14",
                      badgeText: "High",
                      subtitle: "Requires immediate attention",
                      accentColor: Colors.redAccent,
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: DashboardMetricCard(
                      title: "AI Detections",
                      value: "158",
                      badgeText: "+12%",
                      subtitle: "Anomalies identified",
                      accentColor: Colors.orangeAccent,
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: DashboardMetricCard(
                      title: "System Uptime",
                      value: "99.9%",
                      badgeText: "Optimal",
                      subtitle: "Continuous monitoring active",
                      accentColor: Colors.greenAccent,
                    ),
                  ),
                ],
              ),

              const SizedBox(height: 32),

              // Placeholder for future dashboard sections
              Text(
                "Network Activity Overview",
                style: Theme.of(context).textTheme.headlineSmall?.copyWith(color: Colors.white),
              ),

              const SizedBox(height: 32),

              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(
                    child: SizedBox(
                      height: 500, // Providing a fixed height for the scrollable list
                      child: IncidentList(
                        incidents: sampleIncidents,
                        selectedFilter: "All",
                        onFilterChanged: (filter) {
                          print("Filter changed to: $filter");
                        },
                      ),
                    ),
                  ),
                  // You can add your next widget here as a sibling to the Expanded above
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}