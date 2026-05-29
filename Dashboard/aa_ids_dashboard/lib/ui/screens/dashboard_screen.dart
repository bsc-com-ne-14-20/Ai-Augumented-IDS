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

  // Responsive breakpoints
  static const double mobileBreakpoint = 600;
  static const double tabletBreakpoint = 1024;
  static const double desktopBreakpoint = 1440;

  @override
  void initState() {
    super.initState();

    // Trigger data loading sequence
    WidgetsBinding.instance.addPostFrameCallback((_) {
      context.read<DashboardProvider>().loadInitialDashboardData();
    });
  }

  // Responsive helper methods
  bool _isMobile(BuildContext context) => MediaQuery.of(context).size.width < mobileBreakpoint;
  bool _isTablet(BuildContext context) => MediaQuery.of(context).size.width >= mobileBreakpoint && 
                                           MediaQuery.of(context).size.width < tabletBreakpoint;
  bool _isDesktop(BuildContext context) => MediaQuery.of(context).size.width >= tabletBreakpoint;

  double _getHorizontalPadding(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < 600) return 12;
    if (width < 1024) return 16;
    return 24;
  }

  double _getVerticalSpacing(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < 600) return 16;
    if (width < 1024) return 20;
    return 32;
  }

  double _getHeaderFontSize(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < 600) return 16;
    if (width < 1024) return 17;
    return 18;
  }

  double _getMetricCardFontSize(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < 600) return 12;
    if (width < 1024) return 12.5;
    return 46;
  }

  // Build metric cards responsively
  Widget _buildMetricCards(BuildContext context, DashboardProvider dashboardProvider) {
    final width = MediaQuery.of(context).size.width;
    final isMobile = _isMobile(context);
    final isTablet = _isTablet(context);
    
    // Filter out "Unknown" attack types and root "/" endpoint (these are clean/legitimate requests)
    final List<Incident> actualAttacks = dashboardProvider.incidents
        .where((i) => i.attackType?.toLowerCase() != 'unknown' && 
                      i.attackType != null 
              )
        .toList();
    
    // Count unreviewed incidents (only real attacks, exclude Unknown and "/" endpoint)
    final int unreviewedCount = actualAttacks
        .where((i) => i.reviewedStatus.toLowerCase() != 'yes')
        .length;
    
    // Count attacks detected (only non-Unknown attacks and non-root endpoints)
    final int attacksDetected = actualAttacks.length;
    
    // Total requests inspected - count all incidents (includes clean/Unknown traffic)
    final int requestsInspected = dashboardProvider.incidents.length;

    final cards = [
      DashboardMetricCard(
        title: 'ATTACKS DETECTED',
        value: attacksDetected.toString(),
        accentColor: const Color(0xFF4A9EFF),
        icon: Icons.list_alt_rounded,
        showBottomSection: false,
      ),
      DashboardMetricCard(
        title: 'REQUESTS INSPECTED',
        value: requestsInspected.toString(),
        accentColor: const Color(0xFF9B6BFF),
        icon: Icons.article_outlined,
        showBottomSection: false,
      ),
      DashboardMetricCard(
        title: 'UNREVIEWED ALERTS',
        value: '$unreviewedCount',
        accentColor: const Color(0xFFFF5C5C),
        icon: Icons.warning_amber_rounded,
        showBottomSection: false,
      ),
    ];

    if (isMobile) {
      // Mobile: Single column, vertically stacked
      return Column(
        children: cards
            .asMap()
            .entries
            .map((entry) => Padding(
                  padding: EdgeInsets.only(bottom: entry.key < cards.length - 1 ? 12 : 0),
                  child: entry.value,
                ))
            .toList(),
      );
    } else if (isTablet) {
      // Tablet: Two cards per row
      return Column(
        children: [
          Row(
            children: [
              Expanded(child: cards[0]),
              const SizedBox(width: 12),
              Expanded(child: cards[1]),
            ],
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(child: cards[2]),
              const Spacer(),
            ],
          ),
        ],
      );
    } else {
      // Desktop: Three cards in one row
      return Row(
        children: [
          Expanded(child: cards[0]),
          const SizedBox(width: 16),
          Expanded(child: cards[1]),
          const SizedBox(width: 16),
          Expanded(child: cards[2]),
        ],
      );
    }
  }

  // Build main content area responsively
  Widget _buildMainContent(BuildContext context, DashboardProvider dashboardProvider) {
    final isMobile = _isMobile(context);
    final isTablet = _isTablet(context);

    // Filter out "Unknown" attack types and root "/" endpoint - they are clean traffic, not real incidents
    final List<Incident> filteredIncidents = dashboardProvider.incidents
        .where((i) => i.attackType?.toLowerCase() != 'unknown' && 
                      i.attackType != null )
        .toList();

    final incidentList = IncidentList(
      incidents: filteredIncidents,
      onIncidentSelected: (incident) {
        setState(() => _selectedIncident = incident);
      },
      onIncidentStatusUpdated: (updated) {
        setState(() {
          dashboardProvider.markIncidentAsReviewed(updated.id);
          if (_selectedIncident?.id == updated.id) {
            _selectedIncident = updated;
          }
        });
      },
    );

    final detailPanel = IncidentDetailPanel(
      incident: _selectedIncident,
    );

    if (isMobile) {
      // Mobile: Stacked vertically
      return Column(
        children: [
          Expanded(flex: 1, child: incidentList),
          const SizedBox(height: 16),
          Expanded(flex: 1, child: detailPanel),
        ],
      );
    } else if (isTablet) {
      // Tablet: Side by side with adjusted ratio
      return Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(flex: 6, child: incidentList),
          const SizedBox(width: 12),
          Expanded(flex: 4, child: detailPanel),
        ],
      );
    } else {
      // Desktop: Original layout with 7:5 ratio
      return Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(flex: 7, child: incidentList),
          const SizedBox(width: 16),
          Expanded(flex: 5, child: detailPanel),
        ],
      );
    }
  }

  // ── Build ──────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final themeProvider = context.watch<ThemeProvider>();
    final dashboardProvider = context.watch<DashboardProvider>();
    final isDark = themeProvider.isDarkTheme;
    
    final horizontalPadding = _getHorizontalPadding(context);
    final verticalSpacing = _getVerticalSpacing(context);
    final headerFontSize = _getHeaderFontSize(context);

    return Scaffold(
      backgroundColor: isDark ? AppColors.darkVeryLight : AppColors.lightVeryLight,
      appBar: const CustomAppBar(),
      body: Stack(
        children: [
          SafeArea(
            child: Padding(
              padding: EdgeInsets.all(horizontalPadding),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Header row
                  Text(
                    'OVERVIEW',
                    style: TextStyle(
                      fontSize: headerFontSize,
                      fontWeight: FontWeight.w500,
                      color: AppColors.textLabel,
                      letterSpacing: 1,
                    ),
                  ),
                  SizedBox(height: verticalSpacing * 0.4),

                  // Metric cards - Responsive
                  _buildMetricCards(context, dashboardProvider),

                  SizedBox(height: verticalSpacing),

                  // Main content - Responsive layout
                  Expanded(
                    child: _buildMainContent(context, dashboardProvider),
                  ),
                ],
              ),
            ),
          ),

          // Responsive Notification overlay
          if (_notificationMessage != null)
            _buildNotificationOverlay(context),

          // Loading overlay - shows while initial data is loading
          if (dashboardProvider.isAppLoading)
            _buildLoadingOverlay(context, isDark),
        ],
      ),
    );
  }

  Widget _buildNotificationOverlay(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    final notificationWidth = width < 600 ? width - 24 : 380.0;
    final padding = width < 600 ? 12.0 : 24.0;

    return Positioned(
      top: padding,
      left: padding,
      right: padding,
      child: Center(
        child: SizedBox(
          width: notificationWidth,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
            decoration: BoxDecoration(
              color: _notificationColor.withOpacity(0.15),
              border: Border.all(color: _notificationColor.withOpacity(0.5)),
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
    );
  }

  Widget _buildLoadingOverlay(BuildContext context, bool isDark) {
    return Container(
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
    );
  }
}
