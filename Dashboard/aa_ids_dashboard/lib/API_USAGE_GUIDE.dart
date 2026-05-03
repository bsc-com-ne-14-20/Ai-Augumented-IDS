/// API USAGE GUIDE - AA-IDS Dashboard
/// 
/// This file demonstrates how to use all the implemented API endpoints
/// and real-time socket integration in your Flutter app.

// ════════════════════════════════════════════════════════════════════════════
// 1. BASIC SETUP IN YOUR MAIN APP
// ════════════════════════════════════════════════════════════════════════════

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:aa_ids_dashboard/state/dashboard_provider.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => DashboardProvider()),
      ],
      child: MaterialApp(
        title: 'AA-IDS Dashboard',
        theme: ThemeData(primarySwatch: Colors.blue),
        home: const DashboardScreen(),
      ),
    );
  }
}

// ════════════════════════════════════════════════════════════════════════════
// 2. INITIALIZING REAL-TIME ALERTS
// ════════════════════════════════════════════════════════════════════════════

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({Key? key}) : super(key: key);

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  @override
  void initState() {
    super.initState();
    
    // Initialize real-time alerts from backend
    final provider = context.read<DashboardProvider>();
    provider.initializeRealtimeAlerts();
    
    // Load initial data
    provider.checkHealth();
    provider.fetchMetrics();
    provider.fetchAlerts();
  }

  @override
  void dispose() {
    // Clean up socket connection
    context.read<DashboardProvider>().dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('AA-IDS Dashboard')),
      body: Consumer<DashboardProvider>(
        builder: (context, provider, _) {
          return ListView(
            children: [
              // Health Status Section
              _buildHealthSection(provider),
              
              // Metrics Cards
              _buildMetricsSection(provider),
              
              // Live Incidents List
              _buildIncidentsSection(provider),
            ],
          );
        },
      ),
    );
  }

  Widget _buildHealthSection(DashboardProvider provider) {
    if (provider.healthCheckLoading) {
      return const Center(child: CircularProgressIndicator());
    }
    
    if (provider.healthError != null) {
      return Text('Health Error: ${provider.healthError}');
    }
    
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Backend Status', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
            const SizedBox(height: 8),
            Text('Status: ${provider.healthStatus?.status ?? "Unknown"}'),
            Text('Socket Connected: ${provider.socketConnected}'),
          ],
        ),
      ),
    );
  }

  Widget _buildMetricsSection(DashboardProvider provider) {
    if (provider.metricsLoading) {
      return const Center(child: CircularProgressIndicator());
    }
    
    if (provider.metrics == null) {
      return const Text('No metrics available');
    }
    
    final metrics = provider.metrics!;
    
    return GridView.count(
      crossAxisCount: 2,
      shrinkWrap: true,
      children: [
        _buildMetricCard('Total Requests', metrics.totalRequestsAnalyzed.toString()),
        _buildMetricCard('Attacks Detected', metrics.totalAttactsDetected.toString()),
        _buildMetricCard('Anomalies', metrics.totalAnomaliesDetected.toString()),
        _buildMetricCard('Clean Requests', metrics.totalClean.toString()),
      ],
    );
  }

  Widget _buildMetricCard(String label, String value) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(label, textAlign: TextAlign.center),
            const SizedBox(height: 8),
            Text(value, style: const TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
          ],
        ),
      ),
    );
  }

  Widget _buildIncidentsSection(DashboardProvider provider) {
    if (provider.incidentsLoading) {
      return const Center(child: CircularProgressIndicator());
    }
    
    if (provider.incidents.isEmpty) {
      return const Padding(
        padding: EdgeInsets.all(16),
        child: Text('No incidents detected'),
      );
    }
    
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const Text('Live Incidents', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
              Text('Total: ${provider.totalAlerts}'),
            ],
          ),
        ),
        ListView.builder(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          itemCount: provider.incidents.length,
          itemBuilder: (context, index) {
            final incident = provider.incidents[index];
            return ListTile(
              title: Text(incident.name),
              subtitle: Text('${incident.method} ${incident.endpoint}'),
              trailing: Chip(label: Text(incident.threat)),
            );
          },
        ),
      ],
    );
  }
}

// ════════════════════════════════════════════════════════════════════════════
// 3. USING ANALYSIS ENDPOINT
// ════════════════════════════════════════════════════════════════════════════

/// Example: Analyze HTTP logs
void analyzeLogsExample(DashboardProvider provider) {
  final logs = [
    LogEntry(
      method: 'POST',
      url: 'http://api.example.com/login',
      path: '/login',
      queryString: '',
      headers: {'Content-Type': 'application/json'},
      body: '{"username":"admin","password":"test"}',
      responseCode: 401,
      contentLength: 45,
      timestamp: DateTime.now().toIso8601String(),
    ),
    LogEntry(
      method: 'GET',
      url: 'http://api.example.com/users?id=1" OR "1"="1',
      path: '/users',
      queryString: 'id=1" OR "1"="1',
      headers: {'Authorization': 'Bearer token'},
      body: '',
      responseCode: 200,
      contentLength: 150,
      timestamp: DateTime.now().toIso8601String(),
    ),
  ];
  
  provider.analyzeLogs(logs);
}

// ════════════════════════════════════════════════════════════════════════════
// 4. FILTERING & PAGINATION
// ════════════════════════════════════════════════════════════════════════════

void filteringExample(DashboardProvider provider) {
  // Filter by verdict
  provider.setVerdictFilter('ATTACK');
  
  // Filter by severity
  provider.setSeverityFilter('high');
  
  // Navigate pages
  provider.nextPage();
  provider.previousPage();
  provider.goToPage(3);
  
  // Clear filters
  provider.clearFilters();
}

// ════════════════════════════════════════════════════════════════════════════
// 5. REAL-TIME SOCKET INTEGRATION
// ════════════════════════════════════════════════════════════════════════════

class RealtimeAlertsWidget extends StatefulWidget {
  const RealtimeAlertsWidget({Key? key}) : super(key: key);

  @override
  State<RealtimeAlertsWidget> createState() => _RealtimeAlertsWidgetState();
}

class _RealtimeAlertsWidgetState extends State<RealtimeAlertsWidget> {
  @override
  void initState() {
    super.initState();
    final provider = context.read<DashboardProvider>();
    
    // Initialize socket for live alerts
    provider.initializeRealtimeAlerts();
    
    // Optional: Subscribe to specific alert types
    provider.subscribeToSeverity('high');
    provider.subscribeToAlertType('SQL_INJECTION');
  }

  @override
  Widget build(BuildContext context) {
    return Consumer<DashboardProvider>(
      builder: (context, provider, _) {
        return Column(
          children: [
            // Socket status indicator
            Padding(
              padding: const EdgeInsets.all(8),
              child: Row(
                children: [
                  Container(
                    width: 12,
                    height: 12,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: provider.socketConnected ? Colors.green : Colors.red,
                    ),
                  ),
                  const SizedBox(width: 8),
                  Text(provider.socketConnected ? 'Live Connected' : 'Disconnected'),
                ],
              ),
            ),
            
            // Live incidents stream
            Expanded(
              child: provider.incidents.isEmpty
                  ? const Center(child: Text('Waiting for incidents...'))
                  : ListView.builder(
                      reverse: true,
                      itemCount: provider.incidents.length,
                      itemBuilder: (context, index) {
                        final incident = provider.incidents[index];
                        return Card(
                          color: _getSeverityColor(incident.threat),
                          child: ListTile(
                            title: Text(incident.name),
                            subtitle: Text('${incident.method} ${incident.endpoint}'),
                            trailing: Text(incident.score.toStringAsFixed(2)),
                          ),
                        );
                      },
                    ),
            ),
          ],
        );
      },
    );
  }

  Color _getSeverityColor(String threat) {
    switch (threat.toLowerCase()) {
      case 'high':
        return Colors.red.withOpacity(0.3);
      case 'med':
      case 'medium':
        return Colors.orange.withOpacity(0.3);
      case 'low':
        return Colors.yellow.withOpacity(0.3);
      default:
        return Colors.grey.withOpacity(0.3);
    }
  }
}

// ════════════════════════════════════════════════════════════════════════════
// 6. ERROR HANDLING
// ════════════════════════════════════════════════════════════════════════════

Widget buildErrorWidget(String? error) {
  if (error == null) return const SizedBox.shrink();
  
  return Container(
    padding: const EdgeInsets.all(16),
    color: Colors.red.withOpacity(0.2),
    child: Row(
      children: [
        const Icon(Icons.error, color: Colors.red),
        const SizedBox(width: 8),
        Expanded(child: Text(error)),
      ],
    ),
  );
}

// ════════════════════════════════════════════════════════════════════════════
// 7. EXAMPLE: CUSTOM WIDGET WITH ALL FEATURES
// ════════════════════════════════════════════════════════════════════════════

class FullDashboardExample extends StatefulWidget {
  const FullDashboardExample({Key? key}) : super(key: key);

  @override
  State<FullDashboardExample> createState() => _FullDashboardExampleState();
}

class _FullDashboardExampleState extends State<FullDashboardExample> {
  String? _selectedSeverity;

  @override
  void initState() {
    super.initState();
    final provider = context.read<DashboardProvider>();
    
    // Initialize everything
    provider.initializeRealtimeAlerts();
    provider.checkHealth();
    provider.fetchMetrics();
    provider.fetchAlerts();
  }

  @override
  void dispose() {
    context.read<DashboardProvider>().dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('AA-IDS Full Dashboard'),
        actions: [
          Consumer<DashboardProvider>(
            builder: (context, provider, _) => Padding(
              padding: const EdgeInsets.all(16),
              child: Center(
                child: Row(
                  children: [
                    CircleAvatar(
                      radius: 8,
                      backgroundColor: provider.socketConnected ? Colors.green : Colors.red,
                    ),
                    const SizedBox(width: 8),
                    Text(provider.socketConnected ? 'Live' : 'Offline'),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
      body: Consumer<DashboardProvider>(
        builder: (context, provider, _) {
          return SingleChildScrollView(
            child: Column(
              children: [
                // Error handling
                if (provider.analysisError != null)
                  buildErrorWidget(provider.analysisError),
                if (provider.metricsError != null)
                  buildErrorWidget(provider.metricsError),
                
                // Severity filter
                Padding(
                  padding: const EdgeInsets.all(16),
                  child: DropdownButton<String>(
                    value: _selectedSeverity,
                    hint: const Text('Filter by severity'),
                    items: ['low', 'medium', 'high', 'critical']
                        .map((s) => DropdownMenuItem(value: s, child: Text(s)))
                        .toList(),
                    onChanged: (value) {
                      setState(() => _selectedSeverity = value);
                      if (value != null) {
                        provider.setSeverityFilter(value);
                      }
                    },
                  ),
                ),
                
                // Incidents list
                provider.incidents.isEmpty
                    ? const Padding(
                        padding: EdgeInsets.all(16),
                        child: Text('No incidents'),
                      )
                    : ListView.builder(
                        shrinkWrap: true,
                        physics: const NeverScrollableScrollPhysics(),
                        itemCount: provider.incidents.length,
                        itemBuilder: (context, index) {
                          final incident = provider.incidents[index];
                          return ListTile(
                            title: Text(incident.name),
                            subtitle: Text(incident.endpoint),
                            trailing: Chip(label: Text(incident.threat)),
                          );
                        },
                      ),
              ],
            ),
          );
        },
      ),
    );
  }
}

// ════════════════════════════════════════════════════════════════════════════
// NOTES:
// ════════════════════════════════════════════════════════════════════════════
// 
// - Always call provider.dispose() when the provider is no longer needed
// - Initialize socket early in your app lifecycle for best experience
// - Use Consumer for reactive updates when provider state changes
// - Check loading states before displaying data
// - Handle errors gracefully with user-friendly messages
// - The socket automatically reconnects if connection is lost
// - Metrics update from /metrics endpoint for dashboard visualizations
// - Detection results can be filtered by verdict and severity
// - All API calls have proper timeout and error handling
//
// ════════════════════════════════════════════════════════════════════════════
