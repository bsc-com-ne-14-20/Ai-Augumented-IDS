// lib/custom_widgets/dashboard_metric_card.dart

import 'package:flutter/material.dart';

class DashboardMetricCard extends StatelessWidget {
  final String title;
  final String value;
  final String? badgeText;
  final String? subtitle;

  final Color accentColor;

  final double borderRadius;
  final EdgeInsets padding;

  const DashboardMetricCard({
    super.key,
    required this.title,
    required this.value,
    this.badgeText,
    this.subtitle,
    required this.accentColor,
    this.borderRadius = 10.0,
    this.padding = const EdgeInsets.fromLTRB(22, 20, 22, 20),
  });

  Color _darken(Color color, [double amount = 0.68]) {
    final hsl = HSLColor.fromColor(color);
    return hsl.withLightness((hsl.lightness * (1 - amount)).clamp(0.0, 1.0)).toColor();
  }

  Color _lighten(Color color, [double amount = 0.12]) {
    final hsl = HSLColor.fromColor(color);
    return hsl.withLightness((hsl.lightness + amount).clamp(0.0, 1.0)).toColor();
  }

  @override
  Widget build(BuildContext context) {
    final backgroundColor = _darken(accentColor, 0.68);
    final badgeBackground = _lighten(accentColor, 0.08);

    return Container(
      padding: padding,
      decoration: BoxDecoration(
        color: backgroundColor,
        borderRadius: BorderRadius.circular(borderRadius),
        border: Border.all(
          color: Colors.white.withOpacity(0.08),
          width: 1,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          // Title
          Text(
            title.toUpperCase(),
            style: const TextStyle(
              fontSize: 11.5,
              fontWeight: FontWeight.w500,
              color: Color(0xFF8B9EB0),
              letterSpacing: 0.8,
            ),
          ),

          const SizedBox(height: 10),

          // Value
          Text(
            value,
            style: TextStyle(
              fontSize: 42,
              fontWeight: FontWeight.w600,
              color: accentColor,
              height: 1.05,
              letterSpacing: -0.5,
            ),
          ),

          const SizedBox(height: 12),

          // Badge + Subtitle Row
          if (badgeText != null || subtitle != null)
            Row(
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                if (badgeText != null)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3.5),
                    decoration: BoxDecoration(
                      color: badgeBackground,
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: Text(
                      badgeText!,
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                        letterSpacing: 0.2,
                      ),
                    ),
                  ),

                if (badgeText != null && subtitle != null)
                  const SizedBox(width: 10),

                if (subtitle != null)
                  Expanded(
                    child: Text(
                      subtitle!,
                      style: const TextStyle(
                        fontSize: 12.5,
                        color: Color(0xFF6E8AA8),
                        height: 1.2,
                      ),
                    ),
                  ),
              ],
            ),
        ],
      ),
    );
  }
}