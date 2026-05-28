

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
      cardTheme: CardThemeData(
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
        fillColor: AppColors.background,
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

  static ThemeData get lightTheme {
    return ThemeData(
      brightness: Brightness.light,

      // 🔹 Core Colors
      scaffoldBackgroundColor: AppColors.lightBackground,
      primaryColor: AppColors.primaryBlue,

      colorScheme: const ColorScheme.light().copyWith(
        primary: AppColors.primaryBlue,
        secondary: AppColors.accentBlueDark,
        surface: AppColors.lightSurface,
        error: AppColors.danger,
      ),

      // 🔹 AppBar Theme
      appBarTheme: const AppBarTheme(
        backgroundColor: AppColors.lightCard,
        elevation: 1,
        centerTitle: false,
        titleTextStyle: TextStyle(
          color: AppColors.lightTextPrimary,
          fontSize: 18,
          fontWeight: FontWeight.w600,
        ),
        iconTheme: IconThemeData(color: AppColors.lightTextPrimary),
      ),

      // 🔹 Card Theme (important for dashboard panels)
      cardTheme: CardThemeData(
        color: AppColors.lightCard,
        elevation: 1,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: BorderSide(
            color: AppColors.lightCardBorder,
            width: 0.5,
          ),
        ),
      ),

      // 🔹 Text Theme
      textTheme: const TextTheme(
        headlineLarge: TextStyle(
          color: AppColors.lightTextPrimary,
          fontWeight: FontWeight.bold,
        ),
        bodyLarge: TextStyle(
          color: AppColors.lightTextPrimary,
        ),
        bodyMedium: TextStyle(
          color: AppColors.lightTextSecondary,
        ),
        bodySmall: TextStyle(
          color: AppColors.lightTextMuted,
        ),
      ),

      // 🔹 Input Fields (Forms)
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: AppColors.lightBackground,
        hintStyle: const TextStyle(color: AppColors.lightTextMuted),
        labelStyle: const TextStyle(color: AppColors.lightTextSecondary),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide:
              const BorderSide(color: AppColors.lightBorder),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide:
              const BorderSide(color: AppColors.lightBorder),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide:
              const BorderSide(color: AppColors.primaryBlue),
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
        color: AppColors.lightDivider,
        thickness: 1,
      ),

      // 🔹 DataTable (important for incident lists)
      dataTableTheme: DataTableThemeData(
        headingRowColor: WidgetStateProperty.all(
            AppColors.lightHeaderBg),
        dataRowColor:
            WidgetStateProperty.resolveWith<Color?>((states) {
          if (states.contains(MaterialState.hovered)) {
            return AppColors.lightHover;
          }
          return AppColors.lightSurface;
        }),
        headingTextStyle: const TextStyle(
          color: AppColors.lightTextPrimary,
          fontWeight: FontWeight.bold,
        ),
        dataTextStyle: const TextStyle(
          color: AppColors.lightTextSecondary,
        ),
      ),

      // 🔹 Icon Theme
      iconTheme: const IconThemeData(
        color: AppColors.lightTextSecondary,
      ),
    );
  }
}