import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '/models/dashboard_models.dart';
import '../theming/app_colors.dart';
import '/state/theme_provider.dart';

class IncidentDetailPanel extends StatelessWidget {
  final Incident? incident;

  const IncidentDetailPanel({
    super.key,
    this.incident,
  });

  Color _getThreatColor(String threat) {
    switch (threat.toLowerCase()) {
      case 'high':
        return AppColors.highThreat;
      case 'med':
      case 'medium':
        return AppColors.mediumThreat;
      case 'low':
        return AppColors.lowThreat;
      default:
        return Colors.grey;
    }
  }

  @override
  Widget build(BuildContext context) {
    if (incident == null) {
      return _buildEmptyState(context);
    }

    final accentColor = _getThreatColor(incident!.threat);

    return _buildDetailCard(context, incident!, accentColor);
  }

  Widget _buildEmptyState(BuildContext context) {
    final themeProvider = context.watch<ThemeProvider>();
    final isDark = themeProvider.isDarkTheme;
    return Container(
      height: 420,
      decoration: BoxDecoration(
        color: isDark ? AppColors.darkCardBg : AppColors.lightCardBg,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: isDark ? AppColors.borderDark : AppColors.lightBorderDark),
      ),
      child: Builder(builder: (context) {
        final themeProvider = context.watch<ThemeProvider>();
        final isDark = themeProvider.isDarkTheme;
        return Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.select_all_rounded, size: 52, color: isDark ? AppColors.textMutedIcon : AppColors.lightTextMutedIcon),
              const SizedBox(height: 16),
              Text(
                "Select an incident to view details",
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: isDark ? AppColors.textMutedSubtle : AppColors.lightTextMutedSubtle,
                  fontSize: 14,
                ),
              ),
            ],
          ),
        );
      }),
    );
  }

  Widget _buildDetailCard(BuildContext context, Incident inc, Color accent) {
    final themeProvider = context.watch<ThemeProvider>();
    final isDark = themeProvider.isDarkTheme;
    return Container(
      decoration: BoxDecoration(
        color: isDark ? AppColors.darkCardBg : AppColors.lightCardBg,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: isDark ? AppColors.borderDark : AppColors.lightBorderDark),
      ),
      child: SingleChildScrollView(
        physics: const BouncingScrollPhysics(),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Incident Name
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 18, 16, 0),
              child: Text(
                inc.name,
                style: TextStyle(
                  fontSize: 17,
                  fontWeight: FontWeight.w600,
                  color: accent,
                ),
              ),
            ),

            // Meta Information Row
            Padding(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  // Method Badge
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 5),
                    decoration: BoxDecoration(
                      color: isDark ? AppColors.darkActiveBg : AppColors.lightActiveBg,
                      border: Border.all(color: isDark ? AppColors.borderBlueLight : AppColors.lightBorderSecondary),
                      borderRadius: BorderRadius.circular(5),
                    ),
                    child: Text(
                      inc.method,
                      style: const TextStyle(
                        color: AppColors.accentBlueSoft,
                        fontSize: 12.5,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),

                  // Threat Badge
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 5),
                    decoration: BoxDecoration(
                      color: accent.withOpacity(isDark ? 0.12 : 0.15),
                      border: Border.all(color: accent.withOpacity(isDark ? 0.35 : 0.4)),
                      borderRadius: BorderRadius.circular(5),
                    ),
                    child: Text(
                      inc.threat == 'Med' ? 'Medium' : inc.threat,
                      style: TextStyle(
                        color: accent,
                        fontSize: 12.5,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),

                  const Spacer(),

                  // Anomaly Score
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.end,
                    children: [
                      Text(
                        inc.score.toStringAsFixed(2),
                        style: TextStyle(
                          fontSize: 27,
                          fontWeight: FontWeight.bold,
                          color: accent,
                        ),
                      ),
                      Text(
                        "ANOMALY SCORE",
                        style: TextStyle(
                          fontSize: 9.2,
                          color: isDark ? AppColors.textMutedDark : AppColors.lightTextMutedDark,
                          letterSpacing: 0.6,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),

            // Detail Fields Grid
            Container(
              decoration: BoxDecoration(
                border: Border(
                  top: BorderSide(color: isDark ? AppColors.borderDark : AppColors.lightBorderDark),
                ),
              ),
              child: GridView.count(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                crossAxisCount: 2,
                childAspectRatio: 3.1,
                children: [
                  _detailField("Source IP", inc.sourceIp),
                  _detailField("Destination", inc.endpoint),
                  _detailField("Timestamp", "2025-04-08 ${inc.time}"),
                  _detailField("Detector", inc.detector),
                ],
              ),
            ),

            // HTTP Request Section
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 6),
              child: Text(
                "HTTP REQUEST",
                style: TextStyle(
                  fontSize: 9.5,
                  fontWeight: FontWeight.w500,
                  color: isDark ? AppColors.textMutedDark : AppColors.lightTextMutedDark,
                  letterSpacing: 0.7,
                ),
              ),
            ),
            Container(
              margin: const EdgeInsets.fromLTRB(16, 0, 16, 20),
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: isDark ? AppColors.darkVeryLight : AppColors.lightSecondaryBg,
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: isDark ? AppColors.darkSecondaryBg : AppColors.lightBorderSecondary),
              ),
              child: SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: Text(
                  inc.httpRequest,
                  style: TextStyle(
                    fontFamily: 'Courier New',
                    fontSize: 12.8,
                    height: 1.65,
                    color: isDark ? AppColors.textLight : AppColors.lightTextLabel,
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _detailField(String label, String value) {
    return Builder(builder: (context) {
      final themeProvider = context.watch<ThemeProvider>();
      final isDark = themeProvider.isDarkTheme;
      return Padding(
        padding: const EdgeInsets.symmetric(horizontal: 15, vertical: 10),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label.toUpperCase(),
              style: TextStyle(
                fontSize: 9,
                color: isDark ? AppColors.textMutedDark : AppColors.lightTextMutedDark,
                letterSpacing: 0.6,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              value,
              style: TextStyle(
                fontSize: 13.2,
                color: isDark ? AppColors.textLight : AppColors.lightTextLabel,
                fontFamily: 'Courier New',
              ),
            ),
          ],
        ),
      );
    });
  }
}