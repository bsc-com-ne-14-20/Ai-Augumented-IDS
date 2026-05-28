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

  // Responsive breakpoints
  static const double mobileBreakpoint = 600;
  static const double tabletBreakpoint = 1024;

  bool _isMobile(BuildContext context) => MediaQuery.of(context).size.width < mobileBreakpoint;
  bool _isTablet(BuildContext context) => MediaQuery.of(context).size.width >= mobileBreakpoint && 
                                           MediaQuery.of(context).size.width < tabletBreakpoint;

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

  double _getEmptyStateHeight(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < mobileBreakpoint) return 300;
    if (width < tabletBreakpoint) return 350;
    return 420;
  }

  double _getNameFontSize(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < mobileBreakpoint) return 15;
    if (width < tabletBreakpoint) return 16;
    return 17;
  }

  double _getAnomalyScoreFontSize(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < mobileBreakpoint) return 22;
    if (width < tabletBreakpoint) return 25;
    return 27;
  }

  double _getDetailFieldFontSize(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < mobileBreakpoint) return 11;
    if (width < tabletBreakpoint) return 12;
    return 13.2;
  }

  double _getMetaPadding(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < mobileBreakpoint) return 12;
    if (width < tabletBreakpoint) return 14;
    return 16;
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
    final emptyHeight = _getEmptyStateHeight(context);

    return Container(
      height: emptyHeight,
      decoration: BoxDecoration(
        color: isDark ? AppColors.darkCardBg : AppColors.lightCardBg,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: isDark ? AppColors.borderDark : AppColors.lightBorderDark),
      ),
      child: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.select_all_rounded,
              size: _isMobile(context) ? 40 : 52,
              color: isDark ? AppColors.textMutedIcon : AppColors.lightTextMutedIcon,
            ),
            const SizedBox(height: 16),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Text(
                "Select an incident to view details",
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: isDark ? AppColors.textMutedSubtle : AppColors.lightTextMutedSubtle,
                  fontSize: _isMobile(context) ? 12 : 14,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDetailCard(BuildContext context, Incident inc, Color accent) {
    final themeProvider = context.watch<ThemeProvider>();
    final isDark = themeProvider.isDarkTheme;
    final isMobile = _isMobile(context);
    final isTablet = _isTablet(context);
    final metaPadding = _getMetaPadding(context);
    final nameFontSize = _getNameFontSize(context);
    final anomalyFontSize = _getAnomalyScoreFontSize(context);

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
              padding: EdgeInsets.fromLTRB(metaPadding, metaPadding + 2, metaPadding, 0),
              child: Text(
                inc.name,
                style: TextStyle(
                  fontSize: nameFontSize,
                  fontWeight: FontWeight.w600,
                  color: accent,
                ),
              ),
            ),

            // Meta Information Row - Responsive
            Padding(
              padding: EdgeInsets.all(metaPadding),
              child: isMobile
                  ? Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        // Badges
                        Wrap(
                          spacing: 8,
                          runSpacing: 8,
                          children: [
                            // Method Badge
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                              decoration: BoxDecoration(
                                color: isDark ? AppColors.darkActiveBg : AppColors.lightActiveBg,
                                border: Border.all(color: isDark ? AppColors.borderBlueLight : AppColors.lightBorderSecondary),
                                borderRadius: BorderRadius.circular(5),
                              ),
                              child: Text(
                                inc.method,
                                style: const TextStyle(
                                  color: AppColors.accentBlueSoft,
                                  fontSize: 11,
                                  fontWeight: FontWeight.w500,
                                ),
                              ),
                            ),
                            // Threat Badge
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                              decoration: BoxDecoration(
                                color: accent.withOpacity(isDark ? 0.12 : 0.15),
                                border: Border.all(color: accent.withOpacity(isDark ? 0.35 : 0.4)),
                                borderRadius: BorderRadius.circular(5),
                              ),
                              child: Text(
                                inc.threat == 'Med' ? 'Medium' : inc.threat,
                                style: TextStyle(
                                  color: accent,
                                  fontSize: 11,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),
                        // Anomaly Score
                        Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              "ANOMALY SCORE",
                              style: TextStyle(
                                fontSize: 8.5,
                                color: isDark ? AppColors.textMutedDark : AppColors.lightTextMutedDark,
                                letterSpacing: 0.6,
                              ),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              inc.score.toStringAsFixed(2),
                              style: TextStyle(
                                fontSize: anomalyFontSize - 3,
                                fontWeight: FontWeight.bold,
                                color: accent,
                              ),
                            ),
                          ],
                        ),
                      ],
                    )
                  : Row(
                      children: [
                        // Badges
                        Wrap(
                          spacing: 8,
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
                          ],
                        ),
                        const Spacer(),
                        // Anomaly Score
                        Column(
                          crossAxisAlignment: CrossAxisAlignment.end,
                          children: [
                            Text(
                              inc.score.toStringAsFixed(2),
                              style: TextStyle(
                                fontSize: anomalyFontSize,
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

            // Detail Fields Grid - Responsive columns
            Container(
              decoration: BoxDecoration(
                border: Border(
                  top: BorderSide(color: isDark ? AppColors.borderDark : AppColors.lightBorderDark),
                ),
              ),
              child: GridView.count(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                crossAxisCount: isMobile ? 1 : (isTablet ? 2 : 2),
                childAspectRatio: isMobile ? 2.8 : 3.1,
                children: [
                  _detailField("Source IP", inc.sourceIp, context),
                  _detailField("Destination", inc.endpoint, context),
                  _detailField("Timestamp", "2025-04-08 ${inc.time}", context),
                  _detailField("Detector", inc.detector, context),
                ],
              ),
            ),

            // HTTP Request Section
            Padding(
              padding: EdgeInsets.fromLTRB(metaPadding, metaPadding, metaPadding, 6),
              child: Text(
                "HTTP REQUEST",
                style: TextStyle(
                  fontSize: isMobile ? 8.5 : 9.5,
                  fontWeight: FontWeight.w500,
                  color: isDark ? AppColors.textMutedDark : AppColors.lightTextMutedDark,
                  letterSpacing: 0.7,
                ),
              ),
            ),
            Container(
              margin: EdgeInsets.fromLTRB(metaPadding, 0, metaPadding, 20),
              padding: EdgeInsets.all(isMobile ? 10 : 14),
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
                    fontSize: isMobile ? 10 : 12.8,
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

  Widget _detailField(String label, String value, BuildContext context) {
    final isMobile = _isMobile(context);
    return Builder(builder: (context) {
      final themeProvider = context.watch<ThemeProvider>();
      final isDark = themeProvider.isDarkTheme;
      final detailFontSize = _getDetailFieldFontSize(context);

      return Padding(
        padding: EdgeInsets.symmetric(horizontal: isMobile ? 12 : 15, vertical: isMobile ? 8 : 10),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label.toUpperCase(),
              style: TextStyle(
                fontSize: isMobile ? 8 : 9,
                color: isDark ? AppColors.textMutedDark : AppColors.lightTextMutedDark,
                letterSpacing: 0.6,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              value,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                fontSize: detailFontSize,
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