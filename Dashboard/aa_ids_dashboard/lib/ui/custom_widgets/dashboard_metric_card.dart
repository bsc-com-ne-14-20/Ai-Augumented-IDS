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

  // Responsive breakpoints
  static const double mobileBreakpoint = 600;
  static const double tabletBreakpoint = 1024;

  bool _isMobile(BuildContext context) => MediaQuery.of(context).size.width < mobileBreakpoint;
  bool _isTablet(BuildContext context) => MediaQuery.of(context).size.width >= mobileBreakpoint && 
                                           MediaQuery.of(context).size.width < tabletBreakpoint;
  bool _isDesktop(BuildContext context) => MediaQuery.of(context).size.width >= tabletBreakpoint;

  double _getValueFontSize(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < mobileBreakpoint) return 32;
    if (width < tabletBreakpoint) return 38;
    return 46;
  }

  double _getTitleFontSize(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < mobileBreakpoint) return 11;
    if (width < tabletBreakpoint) return 12;
    return 12.5;
  }

  double _getPadding(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < mobileBreakpoint) return 14;
    if (width < tabletBreakpoint) return 16;
    return 20;
  }

  double _getIconSize(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < mobileBreakpoint) return 16;
    if (width < tabletBreakpoint) return 18;
    return 20;
  }

  @override
  Widget build(BuildContext context) {
    final themeProvider = context.watch<ThemeProvider>();
    final isDark = themeProvider.isDarkTheme;
    final padding = _getPadding(context);
    final valueFontSize = _getValueFontSize(context);
    final titleFontSize = _getTitleFontSize(context);
    final iconSize = _getIconSize(context);
    final isMobile = _isMobile(context);

    return Container(
      padding: EdgeInsets.all(padding),
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
              if (icon != null && !isMobile) ...[
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: accentColor.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Icon(icon, color: accentColor, size: iconSize),
                ),
                const SizedBox(width: 12),
              ],
              Expanded(
                child: Text(
                  title.toUpperCase(),
                  style: TextStyle(
                    fontSize: titleFontSize,
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

          SizedBox(height: isMobile ? 12 : 18),

          // Main Value
          Text(
            value,
            style: TextStyle(
              fontSize: valueFontSize,
              fontWeight: FontWeight.w600,
              color: accentColor,
              height: 1.0,
              letterSpacing: -1.2,
            ),
          ),

          // Bottom Section (Badge + Subtitle) - Now Optional
          if (showBottomSection && (badgeText != null || subtitle != null)) ...[
            SizedBox(height: isMobile ? 10 : 14),
            Row(
              children: [
                if (badgeText != null)
                  Container(
                    padding: EdgeInsets.symmetric(
                      horizontal: isMobile ? 8 : 10,
                      vertical: isMobile ? 3 : 4,
                    ),
                    decoration: BoxDecoration(
                      color: accentColor.withOpacity(0.15),
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: Text(
                      badgeText!,
                      style: TextStyle(
                        color: accentColor,
                        fontSize: isMobile ? 10 : 12,
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
                        fontSize: isMobile ? 11 : 12.5,
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