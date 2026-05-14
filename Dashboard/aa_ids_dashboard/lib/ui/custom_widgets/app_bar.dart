import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../theming/app_colors.dart';
import 'theme_toggle_button.dart';
import '/state/theme_provider.dart';

class CustomAppBar extends StatelessWidget implements PreferredSizeWidget {
  final String title;
  final String subtitle;
  final String systemStatusText;
  final bool isSystemActive;
  final VoidCallback? onMenuPressed; // For future drawer/menu

  const CustomAppBar({
    super.key,
    this.title = "AA-IDS Prototype",
    this.subtitle = "Hybrid HTTP Anomaly Detection",
    this.systemStatusText = "System active",
    this.isSystemActive = true,
    this.onMenuPressed,
  });

  @override
  Size get preferredSize => const Size.fromHeight(48);

  @override
  Widget build(BuildContext context) {
    final themeProvider = context.watch<ThemeProvider>();
    final isDark = themeProvider.isDarkTheme;

    return Container(
      height: 48,
      padding: const EdgeInsets.symmetric(horizontal: 24),
      decoration: BoxDecoration(
        color: isDark ? AppColors.darkCardBg : AppColors.lightCardBg,
        border: Border(
          bottom: BorderSide(
            color: isDark ? AppColors.borderDark : AppColors.lightBorderDark,
            width: 1,
          ),
        ),
      ),
      child: Row(
        children: [
          // Left Side - Brand
          Row(
            children: [
              // Animated Pulse Dot
              Container(
                width: 7,
                height: 7,
                decoration: BoxDecoration(
                  color: AppColors.successOnline,
                  shape: BoxShape.circle,
                  boxShadow: [
                    BoxShadow(
                      color: AppColors.successOnline.withOpacity(0.6),
                      blurRadius: 6,
                      spreadRadius: 1,
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 10),

              // Title
              Text(
                title,
                style: TextStyle(
                  fontSize: 13.5,
                  fontWeight: FontWeight.w500,
                  color: isDark
                      ? AppColors.accentBlueHighlight
                      : AppColors.lightAccentBlueHighlight,
                  letterSpacing: 0.3,
                ),
              ),

              const SizedBox(width: 8),
              Text(
                "|",
                style: TextStyle(
                  color:
                      isDark ? AppColors.borderDark : AppColors.lightBorderDark,
                  fontWeight: FontWeight.w300,
                ),
              ),
              const SizedBox(width: 8),

              // Subtitle
              Text(
                subtitle,
                style: TextStyle(
                  fontSize: 11.5,
                  color: isDark
                      ? AppColors.textMutedDark
                      : AppColors.lightTextMutedDark,
                  fontWeight: FontWeight.w400,
                ),
              ),
            ],
          ),

          const Spacer(),

          // Right Side
          Row(
            children: [
              // System Status
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: isDark
                      ? AppColors.threatHighBg
                      : AppColors.lightThreatHighBg,
                  border: Border.all(
                    color: isDark
                        ? AppColors.threatHighBorder
                        : AppColors.lightThreatHighBorder,
                  ),
                  borderRadius: BorderRadius.circular(5),
                ),
                child: Row(
                  children: [
                    Container(
                      width: 6,
                      height: 6,
                      decoration: const BoxDecoration(
                        color: AppColors.successOnline,
                        shape: BoxShape.circle,
                      ),
                    ),
                    const SizedBox(width: 6),
                    Text(
                      systemStatusText,
                      style: const TextStyle(
                        fontSize: 11.5,
                        color: AppColors.successOnline,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ],
                ),
              ),

              const SizedBox(width: 24),

              // Live Clock
              const _LiveClock(),

              const SizedBox(width: 16),

              // Theme Toggle Button
              ThemeToggleButton(
                color: isDark ? AppColors.textLabel : AppColors.lightTextLabel,
                size: 20,
              ),
            ],
          ),
        ],
      ),
    );
  }
}

// Separate widget for live updating clock
class _LiveClock extends StatefulWidget {
  const _LiveClock();

  @override
  State<_LiveClock> createState() => _LiveClockState();
}

class _LiveClockState extends State<_LiveClock> {
  late DateTime _currentTime;

  @override
  void initState() {
    super.initState();
    _currentTime = DateTime.now();
    _startClock();
  }

  void _startClock() {
    Future.delayed(const Duration(seconds: 1), () {
      if (mounted) {
        setState(() {
          _currentTime = DateTime.now();
        });
        _startClock();
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final themeProvider = context.watch<ThemeProvider>();
    final isDark = themeProvider.isDarkTheme;
    
    final String timeString = 
        "${_currentTime.year}-${_currentTime.month.toString().padLeft(2, '0')}-"
        "${_currentTime.day.toString().padLeft(2, '0')} "
        "${_currentTime.hour.toString().padLeft(2, '0')}:"
        "${_currentTime.minute.toString().padLeft(2, '0')}:"
        "${_currentTime.second.toString().padLeft(2, '0')} UTC";

    return Text(
      timeString,
      style: TextStyle(
        fontSize: 12,
        color: isDark ? AppColors.textLabel : AppColors.lightTextLabel,
        fontFamily: 'Courier New',
      ),
    );
  }
}