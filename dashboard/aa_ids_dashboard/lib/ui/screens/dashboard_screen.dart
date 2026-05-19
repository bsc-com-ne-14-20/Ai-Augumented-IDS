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
  late List<Incident> sampleIncidents;
  String? _notificationMessage;
  Color _notificationColor = AppColors.successReviewed;

  @override
  void initState() {
    super.initState();
    sampleIncidents = [];
    
    // Initialize dashboard provider for real-time alerts and API calls
    final dashboardProvider = context.read<DashboardProvider>();
    dashboardProvider.initializeRealtimeAlerts();
    
    // Load backend metrics and initial alerts
    // This will populate the provider with real data from the backend
    dashboardProvider.checkHealth();
    dashboardProvider.fetchMetrics();
    dashboardProvider.fetchAlerts();
  }

  // ── Notification helpers ───────────────────────────────────────

  void _showNotification(String message, {Color? color}) {
    setState(() {
      _notificationMessage = message;
      _notificationColor = color ?? AppColors.successReviewed;
    });
    Future.delayed(const Duration(seconds: 4), () {
      if (mounted) setState(() => _notificationMessage = null);
    });
  }

  // ── CSV dialog ─────────────────────────────────────────────────

  void _showCsvInputDialog() {
    final controller = TextEditingController();
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: AppColors.darkCardBg,
        title: const Text(
          'ADD INCIDENTS FROM CSV',
          style: TextStyle(
            color: AppColors.textLabelLight,
            fontSize: 14,
            fontWeight: FontWeight.w600,
          ),
        ),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Exactly 10 comma-separated columns per line:\n'
                '  id, time, endpoint, method, threat,\n'
                '  reviewedStatus (ignored — always Pending),\n'
                '  name, score, sourceIp, detector\n\n'
                'Example:\n'
                'INC-0040,13:45,/api/auth,POST,High,'
                'ignored,Auth Bypass Attempt,0.92,203.0.113.5,ML Model\n\n'
                'Note: if your incident name contains a comma,\n'
                'wrap the whole name in double quotes.',
                style: TextStyle(
                  color: AppColors.textLabel,
                  fontSize: 11,
                  height: 1.6,
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: controller,
                maxLines: 8,
                minLines: 4,
                style: const TextStyle(
                    color: AppColors.textLight, fontSize: 12),
                decoration: InputDecoration(
                  hintText:
                      'Paste CSV rows here (one incident per line)',
                  hintStyle:
                      const TextStyle(color: AppColors.textMutedDark),
                  filled: true,
                  fillColor: AppColors.darkVeryLight,
                  border: OutlineInputBorder(
                    borderSide:
                        const BorderSide(color: AppColors.borderDark),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  enabledBorder: OutlineInputBorder(
                    borderSide:
                        const BorderSide(color: AppColors.borderDark),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  focusedBorder: OutlineInputBorder(
                    borderSide:
                        const BorderSide(color: AppColors.accentBlueHighlight),
                    borderRadius: BorderRadius.circular(6),
                  ),
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('CANCEL',
                style: TextStyle(color: AppColors.textLabel)),
          ),
          TextButton(
            onPressed: () {
              _parseAndAddIncidents(controller.text);
              Navigator.pop(context);
            },
            child: const Text(
              'ADD INCIDENTS',
              style: TextStyle(
                  color: AppColors.accentBlueHighlight,
                  fontWeight: FontWeight.w600),
            ),
          ),
        ],
      ),
    );
  }

  // ── CSV parser ─────────────────────────────────────────────────
  //
  // Expected columns (index → field):
  //   0  id
  //   1  time
  //   2  endpoint
  //   3  method
  //   4  threat
  //   5  reviewedStatus  ← always overridden to "Pending"
  //   6  name            ← may be quoted if it contains commas
  //   7  score
  //   8  sourceIp
  //   9  detector
  //
  // Uses a proper quoted-field splitter so names like
  // "Auth Bypass, Type 2" don't corrupt the indices that follow.

  List<String> _splitCsvLine(String line) {
    final result = <String>[];
    final buf = StringBuffer();
    var inQuotes = false;

    for (var i = 0; i < line.length; i++) {
      final ch = line[i];
      if (ch == '"') {
        // Toggle quoted mode; handle "" as escaped quote inside quotes.
        if (inQuotes && i + 1 < line.length && line[i + 1] == '"') {
          buf.write('"');
          i++; // skip the second quote
        } else {
          inQuotes = !inQuotes;
        }
      } else if (ch == ',' && !inQuotes) {
        result.add(buf.toString().trim());
        buf.clear();
      } else {
        buf.write(ch);
      }
    }
    result.add(buf.toString().trim()); // last field
    return result;
  }

  void _parseAndAddIncidents(String csvText) {
    final lines = csvText.trim().split('\n');
    final added = <Incident>[];
    final skipped = <String>[];
    var duplicateCount = 0;

    for (final rawLine in lines) {
      final line = rawLine.trim();
      if (line.isEmpty) continue;

      // Use the quoted-aware splitter so a name like
      // "Auth Bypass, Type 2" does not shift indices 7-9.
      final parts = _splitCsvLine(line);

      // Guard: must have at least 10 fields.
      if (parts.length < 10) {
        skipped.add('${parts.isNotEmpty ? parts[0] : "?"} '
            '(only ${parts.length} columns)');
        debugPrint('Skipping short line: $line');
        continue;
      }

      // Guard: safe indexed access with fallbacks for every field.
      final id = parts[0].isNotEmpty ? parts[0] : 'INC-????';
      final time = parts[1].isNotEmpty ? parts[1] : '--:--';
      final endpoint = parts[2].isNotEmpty ? parts[2] : '/unknown';
      final method = parts[3].isNotEmpty ? parts[3] : 'GET';
      final threat = parts[4].isNotEmpty ? parts[4] : 'Low';
      // parts[5] is reviewedStatus — intentionally ignored.
      final name = parts[6].isNotEmpty ? parts[6] : 'Unknown Incident';
      // score: parse safely; never null because tryParse fallback is 0.0
      final score = double.tryParse(parts[7]) ?? 0.0;
      final sourceIp = parts[8].isNotEmpty ? parts[8] : '0.0.0.0';
      final detector = parts[9].isNotEmpty ? parts[9] : 'Unknown';

      // Skip duplicates.
      if (sampleIncidents.any((i) => i.id == id)) {
        duplicateCount++;
        debugPrint('Skipping duplicate: $id');
        continue;
      }

      // Synthesise a realistic HTTP request so the detail panel
      // always has something to show.
      final httpRequest = _buildHttpRequest(
          method: method, endpoint: endpoint, sourceIp: sourceIp);

      // Synthesise a human-readable alert message.
      final alertMessage = '$name detected on $endpoint '
          'from $sourceIp — logged, security team notified.';

      added.add(Incident(
        id: id,
        time: time,
        endpoint: endpoint,
        method: method,
        threat: threat,
        reviewedStatus: 'Pending', // always Pending on import
        name: name,
        score: score,
        sourceIp: sourceIp,
        detector: detector,
        alertMessage: alertMessage,
        httpRequest: httpRequest,
        // flagStep defaults to 3 via the model constructor
      ));
    }

    if (added.isNotEmpty) {
      setState(() {
        // Spread into a new list — triggers a full rebuild of every
        // widget that depends on sampleIncidents.
        sampleIncidents = [...sampleIncidents, ...added];
      });
      _showNotification('Added ${added.length} incident(s)',
          color: AppColors.successReviewed);
    } else {
      final parts = <String>[];
      if (duplicateCount > 0) {
        parts.add('Found $duplicateCount duplicate(s)');
      }
      if (skipped.isNotEmpty) {
        parts.add('${skipped.length} invalid format');
      }
      final detail = parts.isNotEmpty ? '\n${parts.join(', ')}' : '';
      _showNotification('No valid incidents found.$detail',
          color: AppColors.highThreat);
    }
  }

  /// Builds a plausible HTTP request block from basic parsed fields.
  /// Never returns null — always a non-empty string.
  String _buildHttpRequest({
    required String method,
    required String endpoint,
    required String sourceIp,
  }) {
    final buf = StringBuffer();
    buf.writeln('$method $endpoint HTTP/1.1');
    buf.writeln('Host: target.app.internal');
    buf.writeln('X-Forwarded-For: $sourceIp');

    if (method == 'POST' ||
        method == 'PUT' ||
        method == 'PATCH') {
      buf.writeln('Content-Type: application/json');
      buf.writeln();
      buf.write('{"payload": "<suspicious content detected>"}');
    }

    return buf.toString().trim();
  }

  // ── Build ──────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final themeProvider = context.watch<ThemeProvider>();
    final dashboardProvider = context.watch<DashboardProvider>();
    final isDark = themeProvider.isDarkTheme;

    // Calculate total unreviewed (Local CSV + Backend Alerts)
    final int unreviewedCount = sampleIncidents
            .where((i) => i.reviewedStatus.toLowerCase() == 'pending')
            .length +
        dashboardProvider.incidents
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
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      const Text(
                        'OVERVIEW',
                        style: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.w500,
                          color: AppColors.textLabel,
                          letterSpacing: 1,
                        ),
                      ),
                      ElevatedButton.icon(
                        onPressed: _showCsvInputDialog,
                        icon: const Icon(Icons.add_circle_outline,
                            size: 18),
                        label: const Text('ADD INCIDENTS (CSV)'),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppColors.darkActiveBg,
                          foregroundColor: AppColors.accentBlueHighlight,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(6),
                            side: const BorderSide(
                                color: AppColors.accentBlueHighlight),
                          ),
                          padding: const EdgeInsets.symmetric(
                              horizontal: 16, vertical: 10),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),

                  // Metric cards
                  Row(
                    children: [
                      Expanded(
                        child: DashboardMetricCard(
                          title: 'TOTAL INCIDENTS LOGGED',
                          // Combine fetched alerts and imported ones
                          value: (dashboardProvider.totalAlerts +
                                  sampleIncidents.length)
                              .toString(),
                          accentColor: const Color(0xFF4A9EFF),
                          icon: Icons.list_alt_rounded,
                          showBottomSection: false,
                        ),
                      ),
                      const SizedBox(width: 16),
                      Expanded(
                        child: DashboardMetricCard(
                          title: 'REQUESTS INSPECTED',
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
                          title: 'DETECTION RATE',
                          value: dashboardProvider.metrics != null
                              ? '${((dashboardProvider.metrics!.totalAttactsDetected / (dashboardProvider.metrics!.totalRequestsAnalyzed > 0 ? dashboardProvider.metrics!.totalRequestsAnalyzed : 1)) * 100).toStringAsFixed(3)}%'
                              : '0.000%',
                          accentColor: const Color(0xFFFFC107),
                          icon: Icons.insights_rounded,
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
                            incidents: [
                              ...dashboardProvider.incidents,
                              ...sampleIncidents
                            ],
                            onIncidentSelected: (incident) {
                              setState(
                                  () => _selectedIncident = incident);
                            },
                            onIncidentStatusUpdated: (updated) {
                              // 1. Check if it's a local CSV incident
                              final idx = sampleIncidents
                                  .indexWhere((i) => i.id == updated.id);
                              
                              setState(() {
                                if (idx >= 0) {
                                  sampleIncidents[idx] = updated;
                                } else {
                                  // 2. Otherwise update the provider (backend incident)
                                  dashboardProvider.markIncidentAsReviewed(updated.id);
                                }

                                // 3. Sync the detail panel selection
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
        ],
      ),
    );
  }
}