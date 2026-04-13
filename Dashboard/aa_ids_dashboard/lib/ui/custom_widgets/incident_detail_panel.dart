import 'package:flutter/material.dart';
import '/models/dashboard_models.dart';
import '../theming/app_colors.dart';

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
      return _buildEmptyState();
    }

    final accentColor = _getThreatColor(incident!.threat);

    return _buildDetailCard(incident!, accentColor);
  }

  Widget _buildEmptyState() {
    return Container(
      height: 420,
      decoration: BoxDecoration(
        color: AppColors.darkCardBg,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: AppColors.borderDark),
      ),
      child: const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.select_all_rounded, size: 52, color: AppColors.textMutedIcon),
            SizedBox(height: 16),
            Text(
              "Select an incident to view details",
              textAlign: TextAlign.center,
              style: TextStyle(
                color: AppColors.textMutedSubtle,
                fontSize: 14,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDetailCard(Incident inc, Color accent) {
    return Container(
      decoration: BoxDecoration(
        color: AppColors.darkCardBg,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: AppColors.borderDark),
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
                      color: AppColors.darkActiveBg,
                      border: Border.all(color: AppColors.borderBlueLight),
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
                      color: accent.withOpacity(0.12),
                      border: Border.all(color: accent.withOpacity(0.35)),
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
                      const Text(
                        "ANOMALY SCORE",
                        style: TextStyle(
                          fontSize: 9.2,
                          color: AppColors.textMutedDark,
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
              decoration: const BoxDecoration(
                border: Border(
                  top: BorderSide(color: AppColors.borderDark),
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
            const Padding(
              padding: EdgeInsets.fromLTRB(16, 16, 16, 6),
              child: Text(
                "HTTP REQUEST",
                style: TextStyle(
                  fontSize: 9.5,
                  fontWeight: FontWeight.w500,
                  color: AppColors.textMutedDark,
                  letterSpacing: 0.7,
                ),
              ),
            ),
            Container(
              margin: const EdgeInsets.fromLTRB(16, 0, 16, 20),
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: AppColors.darkVeryLight,
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: AppColors.darkSecondaryBg),
              ),
              child: SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: Text(
                  inc.httpRequest,
                  style: const TextStyle(
                    fontFamily: 'Courier New',
                    fontSize: 12.8,
                    height: 1.65,
                    color: AppColors.textLight,
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
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 15, vertical: 10),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label.toUpperCase(),
            style: const TextStyle(
              fontSize: 9,
              color: AppColors.textMutedDark,
              letterSpacing: 0.6,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            value,
            style: const TextStyle(
              fontSize: 13.2,
              color: AppColors.textLight,
              fontFamily: 'Courier New',
            ),
          ),
        ],
      ),
    );
  }
}