// lib/custom_widgets/dashboard_metric_card.dart

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../theming/app_colors.dart';
import '/state/theme_provider.dart';

class DashboardMetricCard extends StatelessWidget {
  final String title;
  final String value;
  final String? badgeText;
  final String? subtitle;
  final Color accentColor;
  final IconData? icon;

  final double borderRadius;
  final bool showBottomSection;   // whether to show badge + subtitle

  const DashboardMetricCard({
    super.key,
    required this.title,
    required this.value,
    this.badgeText,
    this.subtitle,
    required this.accentColor,
    this.icon,
    this.borderRadius = 12.0,
    this.showBottomSection = true,   // Default is true for backward compatibility
  });

  @override
  Widget build(BuildContext context) {
    final themeProvider = context.watch<ThemeProvider>();
    final isDark = themeProvider.isDarkTheme;

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: isDark ? AppColors.darkCardBg : AppColors.lightCardBg,
        borderRadius: BorderRadius.circular(borderRadius),
        border: Border.all(
          color: accentColor.withOpacity(0.25),
          width: 1.2,
        ),
        boxShadow: [
          BoxShadow(
            color: accentColor.withOpacity(0.08),
            blurRadius: 12,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Icon + Title
          Row(
            children: [
              if (icon != null) ...[
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: accentColor.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Icon(icon, color: accentColor, size: 20),
                ),
                const SizedBox(width: 12),
              ],
              Expanded(
                child: Text(
                  title.toUpperCase(),
                  style: TextStyle(
                    fontSize: 12.5,
                    fontWeight: FontWeight.w500,
                    color: isDark
                        ? AppColors.textLabelLight
                        : AppColors.lightTextLabelLight,
                    letterSpacing: 0.6,
                  ),
                ),
              ),
            ],
          ),

          const SizedBox(height: 18),

          // Main Value
          Text(
            value,
            style: TextStyle(
              fontSize: 46,
              fontWeight: FontWeight.w600,
              color: accentColor,
              height: 1.0,
              letterSpacing: -1.2,
            ),
          ),

          // Bottom Section (Badge + Subtitle) - Now Optional
          if (showBottomSection && (badgeText != null || subtitle != null)) ...[
            const SizedBox(height: 14),
            Row(
              children: [
                if (badgeText != null)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                    decoration: BoxDecoration(
                      color: accentColor.withOpacity(0.15),
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: Text(
                      badgeText!,
                      style: TextStyle(
                        color: accentColor,
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                if (badgeText != null && subtitle != null)
                  const SizedBox(width: 12),
                if (subtitle != null)
                  Expanded(
                    child: Text(
                      subtitle!,
                      style: TextStyle(
                        fontSize: 12.5,
                        color: isDark
                            ? AppColors.textLabelSecondary
                            : AppColors.lightTextLabelSecondary,
                      ),
                    ),
                  ),
              ],
            ),
          ],
        ],
      ),
    );
  }
}