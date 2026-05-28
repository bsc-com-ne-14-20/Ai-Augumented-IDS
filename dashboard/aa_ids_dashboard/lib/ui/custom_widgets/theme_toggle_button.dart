import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '/state/theme_provider.dart';

/// A theme toggle button widget that can be placed in the AppBar or anywhere else
class ThemeToggleButton extends StatelessWidget {
  final Color? color;
  final double size;

  const ThemeToggleButton({
    super.key,
    this.color,
    this.size = 24,
  });

  @override
  Widget build(BuildContext context) {
    final themeProvider = context.watch<ThemeProvider>();

    return IconButton(
      icon: Icon(
        themeProvider.isDarkTheme ? Icons.light_mode : Icons.dark_mode,
        size: size,
        color: color,
      ),
      onPressed: () => themeProvider.toggleTheme(),
      tooltip: themeProvider.isDarkTheme
          ? 'Switch to Light Theme'
          : 'Switch to Dark Theme',
    );
  }
}
