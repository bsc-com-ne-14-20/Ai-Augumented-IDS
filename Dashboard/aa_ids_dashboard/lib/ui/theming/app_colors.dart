import 'package:flutter/material.dart';

class AppColors {
  // 🔹 Core Brand Colors
  static const Color primaryBlue = Color(0xFF2196F3);
  static const Color primaryDark = Color(0xFF1E1E1E);

  // 🔹 Background Layers
  static const Color background = Color(0xFF121212);
  static const Color surface = Color(0xFF1E1E1E);
  static const Color card = Color(0xFF2A2A2A);

  // 🔹 Text Colors
  static const Color textPrimary = Colors.white;
  static const Color textSecondary = Color(0xFFB0B0B0);
  static const Color textMuted = Color(0xFF757575);

  // 🔹 Borders / Dividers
  static const Color border = Color(0xFF333333);
  static const Color divider = Color(0xFF2C2C2C);

  // 🔹 Status Colors (IDS-specific)
  static const Color success = Color(0xFF4CAF50);
  static const Color warning = Color(0xFFFFA726);
  static const Color danger = Color(0xFFE53935);

  // 🔹 Threat Levels (Important for IDS)
  static const Color lowThreat = Color(0xFF4CAF50);
  static const Color mediumThreat = Color(0xFFFFA726);
  static const Color highThreat = Color(0xFFE53935);

  // 🔹 Highlight / Accent Variants
  static const Color accentBlueLight = Color(0xFF64B5F6);
  static const Color accentBlueDark = Color(0xFF1976D2);

  // 🔹 Hover / Focus States
  static const Color hover = Color(0xFF2C2C2C);
  static const Color focus = Color(0xFF1565C0);
}