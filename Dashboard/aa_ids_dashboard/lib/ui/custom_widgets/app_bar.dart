import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../theming/app_colors.dart';
import 'theme_toggle_button.dart';
import '/state/theme_provider.dart';
import '/state/dashboard_provider.dart';

class CustomAppBar extends StatelessWidget implements PreferredSizeWidget {
  final String title;
  final String subtitle;
  final VoidCallback? onMenuPressed; // For future drawer/menu

  const CustomAppBar({
    super.key,
    this.title = "AA-IDS Prototype",
    this.subtitle = "Hybrid HTTP Anomaly Detection",
    this.onMenuPressed,
  });

  @override
  Size get preferredSize => const Size.fromHeight(48);

  bool _isMobile(BuildContext context) => MediaQuery.of(context).size.width < 600;

  double _getTitleFontSize(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < 600) return 12;
    if (width < 1024) return 12.5;
    return 13.5;
  }

  double _getSubtitleFontSize(BuildContext context) {
    final width = MediaQuery.of(context).size.width;
    if (width < 600) return 10;
    if (width < 1024) return 10.5;
    return 11.5;
  }

  @override
  Widget build(BuildContext context) {
    final themeProvider = context.watch<ThemeProvider>();
    final dashboardProvider = context.watch<DashboardProvider>();
    final isDark = themeProvider.isDarkTheme;
    final isMobile = _isMobile(context);
    final titleFontSize = _getTitleFontSize(context);
    final subtitleFontSize = _getSubtitleFontSize(context);
    
    // Get socket connection status
    final isSystemActive = dashboardProvider.socketConnected;
    final systemStatusColor = isSystemActive ? AppColors.successOnline : AppColors.highThreat;
    final systemStatusText = isSystemActive ? "System active" : "System inactive";

    return Container(
      height: 48,
      padding: EdgeInsets.symmetric(horizontal: isMobile ? 12 : 24),
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
          // Left Side - Brand (responsive)
          Expanded(
            child: Row(
              children: [
                // Animated Pulse Dot (socket status indicator)
                Container(
                  width: 7,
                  height: 7,
                  decoration: BoxDecoration(
                    color: systemStatusColor,
                    shape: BoxShape.circle,
                    boxShadow: [
                      BoxShadow(
                        color: systemStatusColor.withOpacity(0.6),
                        blurRadius: 6,
                        spreadRadius: 1,
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 10),

                // Title and Subtitle (hide subtitle on mobile if needed)
                if (!isMobile) ...[
                  Text(
                    title,
                    style: TextStyle(
                      fontSize: titleFontSize,
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
                      color: isDark ? AppColors.borderDark : AppColors.lightBorderDark,
                      fontWeight: FontWeight.w300,
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      subtitle,
                      style: TextStyle(
                        fontSize: subtitleFontSize,
                        color: isDark
                            ? AppColors.textMutedDark
                            : AppColors.lightTextMutedDark,
                        fontWeight: FontWeight.w400,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ),
                ] else ...[
                  Expanded(
                    child: Text(
                      title,
                      style: TextStyle(
                        fontSize: titleFontSize,
                        fontWeight: FontWeight.w500,
                        color: isDark
                            ? AppColors.accentBlueHighlight
                            : AppColors.lightAccentBlueHighlight,
                        letterSpacing: 0.3,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),

          // Right Side (responsive)
          if (!isMobile)
            Row(
              children: [
                // System Status (Socket Connection Indicator)
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                  decoration: BoxDecoration(
                    color: isSystemActive
                        ? (isDark
                            ? AppColors.threatHighBg
                            : AppColors.lightThreatHighBg)
                        : (isDark
                            ? AppColors.threatHighBg
                            : AppColors.lightThreatHighBg),
                    border: Border.all(
                      color: systemStatusColor.withOpacity(0.4),
                    ),
                    borderRadius: BorderRadius.circular(5),
                  ),
                  child: Row(
                    children: [
                      Container(
                        width: 6,
                        height: 6,
                        decoration: BoxDecoration(
                          color: systemStatusColor,
                          shape: BoxShape.circle,
                        ),
                      ),
                      const SizedBox(width: 6),
                      Text(
                        systemStatusText,
                        style: TextStyle(
                          fontSize: 11.5,
                          color: systemStatusColor,
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
            )
          else ...[
            // Mobile: Show only theme toggle
            ThemeToggleButton(
              color: isDark ? AppColors.textLabel : AppColors.lightTextLabel,
              size: 18,
            ),
          ],
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