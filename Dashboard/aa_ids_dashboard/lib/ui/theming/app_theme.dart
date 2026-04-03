

import 'package:flutter/material.dart';
import 'app_colors.dart';

class AppTheme {
  static ThemeData get darkTheme {
    return ThemeData(
      brightness: Brightness.dark,

      // 🔹 Core Colors
      scaffoldBackgroundColor: AppColors.background,
      primaryColor: AppColors.primaryBlue,

      colorScheme: const ColorScheme.dark().copyWith(
        primary: AppColors.primaryBlue,
        secondary: AppColors.accentBlueLight,
        surface: AppColors.surface,
        error: AppColors.danger,
      ),

      // 🔹 AppBar Theme
      appBarTheme: const AppBarTheme(
        backgroundColor: AppColors.primaryDark,
        elevation: 0,
        centerTitle: false,
        titleTextStyle: TextStyle(
          color: AppColors.textPrimary,
          fontSize: 18,
          fontWeight: FontWeight.w600,
        ),
      ),

      // 🔹 Card Theme (important for dashboard panels)
      cardTheme: CardTheme(
        color: AppColors.card,
        elevation: 2,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: const BorderSide(color: AppColors.border),
        ),
      ),

      // 🔹 Text Theme
      textTheme: const TextTheme(
        headlineLarge: TextStyle(
          color: AppColors.textPrimary,
          fontWeight: FontWeight.bold,
        ),
        bodyLarge: TextStyle(
          color: AppColors.textPrimary,
        ),
        bodyMedium: TextStyle(
          color: AppColors.textSecondary,
        ),
        bodySmall: TextStyle(
          color: AppColors.textMuted,
        ),
      ),

      // 🔹 Input Fields (Forms)
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: AppColors.surface,
        hintStyle: const TextStyle(color: AppColors.textMuted),
        labelStyle: const TextStyle(color: AppColors.textSecondary),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: AppColors.border),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: AppColors.border),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide: const BorderSide(color: AppColors.primaryBlue),
        ),
      ),

      // 🔹 Buttons
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: AppColors.primaryBlue,
          foregroundColor: Colors.white,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(10),
          ),
        ),
      ),

      // 🔹 Divider
      dividerTheme: const DividerThemeData(
        color: AppColors.divider,
        thickness: 1,
      ),

      // 🔹 DataTable (important for incident lists)
      dataTableTheme: DataTableThemeData(
        headingRowColor:
            WidgetStateProperty.all(AppColors.primaryDark),
        dataRowColor:
            WidgetStateProperty.resolveWith<Color?>((states) {
          if (states.contains(MaterialState.hovered)) {
            return AppColors.hover;
          }
          return AppColors.surface;
        }),
        headingTextStyle: const TextStyle(
          color: AppColors.textPrimary,
          fontWeight: FontWeight.bold,
        ),
        dataTextStyle: const TextStyle(
          color: AppColors.textSecondary,
        ),
      ),

      // 🔹 Icon Theme
      iconTheme: const IconThemeData(
        color: AppColors.textSecondary,
      ),
    );
  }
}