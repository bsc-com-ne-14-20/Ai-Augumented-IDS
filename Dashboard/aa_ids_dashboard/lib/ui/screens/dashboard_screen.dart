import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../custom_widgets/dashboard_metric_card.dart';
import '../custom_widgets/incident_list.dart';
import '../custom_widgets/incident_detail_panel.dart';
import '../custom_widgets/app_bar.dart';
import '../theming/app_colors.dart';
import '/models/dashboard_models.dart';
import '/state/theme_provider.dart';
import '/state/dashboard_provider.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  Incident? _selectedIncident;
  String? _notificationMessage;
  Color _notificationColor = AppColors.successReviewed;

  @override
  void initState() {
    super.initState();

    // Trigger data loading sequence
    WidgetsBinding.instance.addPostFrameCallback((_) {
      context.read<DashboardProvider>().loadInitialDashboardData();
    });
  }


  // ── Build ──────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final themeProvider = context.watch<ThemeProvider>();
    final dashboardProvider = context.watch<DashboardProvider>();
    final isDark = themeProvider.isDarkTheme;

    // Calculate total unreviewed from backend alerts
    final int unreviewedCount = dashboardProvider.incidents
        .where((i) => i.reviewedStatus.toLowerCase() == 'no')
        .length;

    return Scaffold(
      backgroundColor: isDark ? AppColors.darkVeryLight : AppColors.lightVeryLight,
      appBar: const CustomAppBar(),
      body: Stack(
        children: [
          SafeArea(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Header row
                  const Text(
                    'OVERVIEW',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.w500,
                      color: AppColors.textLabel,
                      letterSpacing: 1,
                    ),
                  ),
                  const SizedBox(height: 12),

                  // Metric cards - Using backend metrics from /metrics endpoint
                  Row(
                    children: [
                      Expanded(
                        child: DashboardMetricCard(
                          title: 'ATTACKS DETECTED',
                          // From metrics endpoint: total_attacks_detected
                          value: dashboardProvider
                                  .metrics?.totalAttactsDetected
                                  .toString() ??
                              '0',
                          accentColor: const Color(0xFF4A9EFF),
                          icon: Icons.list_alt_rounded,
                          showBottomSection: false,
                        ),
                      ),
                      const SizedBox(width: 16),
                      Expanded(
                        child: DashboardMetricCard(
                          title: 'REQUESTS INSPECTED',
                          // From metrics endpoint: total_requests_analyzed
                          value: dashboardProvider
                                  .metrics?.totalRequestsAnalyzed
                                  .toString() ??
                              '0',
                          accentColor: const Color(0xFF9B6BFF),
                          icon: Icons.article_outlined,
                          showBottomSection: false,
                        ),
                      ),
                      const SizedBox(width: 16),
                      Expanded(
                        child: DashboardMetricCard(
                          title: 'UNREVIEWED ALERTS',
                          // Live count — decrements as incidents are clicked.
                          value: '$unreviewedCount',
                          accentColor: const Color(0xFFFF5C5C),
                          icon: Icons.warning_amber_rounded,
                          showBottomSection: false,
                        ),
                      ),
                    ],
                  ),

                  const SizedBox(height: 32),

                  // Main content
                  Expanded(
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(
                          flex: 7,
                          child: IncidentList(
                            incidents: dashboardProvider.incidents,
                            onIncidentSelected: (incident) {
                              setState(
                                  () => _selectedIncident = incident);
                            },
                            onIncidentStatusUpdated: (updated) {
                              setState(() {
                                // Update the provider (backend incident)
                                dashboardProvider.markIncidentAsReviewed(updated.id);

                                // Sync the detail panel selection
                                if (_selectedIncident?.id == updated.id) {
                                  _selectedIncident = updated;
                                }
                              });
                            },
                          ),
                        ),
                        const SizedBox(width: 16),
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

          // Notification overlay
          if (_notificationMessage != null)
            Positioned(
              top: 2,
              left: 0,
              right: 0,
              child: Center(
                child: SizedBox(
                  width: 380,
                  child: Container(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 20, vertical: 14),
                    decoration: BoxDecoration(
                      color: _notificationColor.withOpacity(0.15),
                      border: Border.all(
                          color:
                              _notificationColor.withOpacity(0.5)),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Row(
                      children: [
                        Icon(
                          _notificationColor == AppColors.highThreat
                              ? Icons.error_outline
                              : Icons.check_circle_outline,
                          color: _notificationColor,
                          size: 20,
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Text(
                            _notificationMessage!,
                            style: TextStyle(
                              color: _notificationColor,
                              fontSize: 13,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),

          // Loading overlay - shows while initial data is loading
          if (dashboardProvider.isAppLoading)
            Container(
              color: isDark
                  ? AppColors.background.withOpacity(0.7)
                  : Colors.black.withOpacity(0.3),
              child: Center(
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    SizedBox(
                      width: 50,
                      height: 50,
                      child: CircularProgressIndicator(
                        strokeWidth: 3,
                        valueColor: AlwaysStoppedAnimation<Color>(
                          isDark
                              ? AppColors.accentBlueHighlight
                              : AppColors.lightAccentBlueHighlight,
                        ),
                      ),
                    ),
                    const SizedBox(height: 20),
                    Text(
                      'Loading Dashboard...',
                      style: TextStyle(
                        fontSize: 14,
                        fontWeight: FontWeight.w500,
                        color: isDark
                            ? AppColors.textLight
                            : AppColors.lightTextPrimary,
                      ),
                    ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }
}