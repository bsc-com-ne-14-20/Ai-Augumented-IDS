// lib/widgets/dashboard_metric_card.dart

import 'package:flutter/material.dart';

class DashboardMetricCard extends StatelessWidget {
  // Main content
  final String title;
  final String value;
  final String? badgeText;
  final String? subtitle;

  // Only one color to control the whole theme
  final Color accentColor;

  // Layout customization
  final double borderRadius;
  final EdgeInsets padding;

  const DashboardMetricCard({
    super.key,
    required this.title,
    required this.value,
    this.badgeText,
    this.subtitle,
    required this.accentColor,
    this.borderRadius = 12.0,
    this.padding = const EdgeInsets.all(20),
  });

  // Helper to create darker/lighter shades
  Color _darken(Color color, [double amount = 0.25]) {
    assert(amount >= 0 && amount <= 1);
    final hsl = HSLColor.fromColor(color);
    return hsl.withLightness((hsl.lightness * (1 - amount)).clamp(0.0, 1.0)).toColor();
  }

  Color _lighten(Color color, [double amount = 0.15]) {
    assert(amount >= 0 && amount <= 1);
    final hsl = HSLColor.fromColor(color);
    return hsl.withLightness((hsl.lightness + amount).clamp(0.0, 1.0)).toColor();
  }

  @override
  Widget build(BuildContext context) {
    final background = _darken(accentColor, 0.65);     // Dark background
    final badgeBg = _lighten(accentColor, 0.05);       // Slightly brighter accent for badge

    return Container(
      padding: padding,
      decoration: BoxDecoration(
        color: background,
        borderRadius: BorderRadius.circular(borderRadius),
        border: Border.all(
          color: Colors.white.withOpacity(0.07),
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
            style: TextStyle(
              color: Colors.white70,
              fontSize: 13,
              fontWeight: FontWeight.w500,
              letterSpacing: 1.1,
            ),
          ),

          const SizedBox(height: 12),

          // Big Value
          Text(
            value,
            style: TextStyle(
              color: accentColor,
              fontSize: 52,
              fontWeight: FontWeight.bold,
              height: 1.0,
            ),
          ),

          const SizedBox(height: 16),

          // Badge + Subtitle
          if (badgeText != null || subtitle != null)
            Row(
              children: [
                if (badgeText != null)
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 11,
                      vertical: 5,
                    ),
                    decoration: BoxDecoration(
                      color: badgeBg,
                      borderRadius: BorderRadius.circular(20),
                    ),
                    child: Text(
                      badgeText!,
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 12.5,
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
                      style: const TextStyle(
                        color: Colors.white60,
                        fontSize: 13.5,
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