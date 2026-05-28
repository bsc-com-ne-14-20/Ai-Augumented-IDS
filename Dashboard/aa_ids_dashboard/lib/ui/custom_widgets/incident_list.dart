import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '/models/dashboard_models.dart';
import '../theming/app_colors.dart';
import '/state/theme_provider.dart';

class IncidentList extends StatefulWidget {
  final List<Incident> incidents;
  final Function(Incident)? onIncidentSelected;
  final Function(Incident)? onIncidentStatusUpdated;

  const IncidentList({
    super.key,
    required this.incidents,
    this.onIncidentSelected,
    this.onIncidentStatusUpdated,
  });

  @override
  State<IncidentList> createState() => _IncidentListState();
}

class _IncidentListState extends State<IncidentList> {
  String _selectedFilter = 'All';
  String? _selectedId;

  // Responsive breakpoints
  static const double mobileBreakpoint = 600;
  static const double tabletBreakpoint = 1024;

  bool _isMobile(BuildContext context) => MediaQuery.of(context).size.width < mobileBreakpoint;
  bool _isTablet(BuildContext context) => MediaQuery.of(context).size.width >= mobileBreakpoint && 
                                           MediaQuery.of(context).size.width < tabletBreakpoint;
  bool _isDesktop(BuildContext context) => MediaQuery.of(context).size.width >= tabletBreakpoint;

  // Local override map: incidentId → reviewedStatus.
  // Status changes are written here immediately so the UI updates
  // in the same frame, independent of the parent rebuild cycle.
  final Map<String, String> _statusOverrides = {};

  // Returns the locally-overridden status, or falls back to the
  // value stored in the Incident model itself.
  String _reviewedStatus(Incident inc) =>
      _statusOverrides[inc.id] ?? inc.reviewedStatus;

  Color _threatColor(String threat) {
    switch (threat.toLowerCase()) {
      case 'high':
        return AppColors.highThreat;
      case 'med':
      case 'medium':
        return AppColors.mediumThreat;
      case 'low':
        return AppColors.lowThreat;
      default:
        return AppColors.textLabel;
    }
  }

  List<Incident> get _filtered {
    return widget.incidents.where((inc) {
      final threatLower = inc.threat.toLowerCase();
      final statusLower = _reviewedStatus(inc).toLowerCase();
      
      switch (_selectedFilter) {
        case 'High':
          return threatLower == 'high';
        case 'Medium':
          return threatLower == 'med' || threatLower == 'medium';
        case 'Unreviewed':
          // Show incidents that are NOT marked as reviewed ('Yes')
          return statusLower != 'yes';
        default:
          return true;
      }
    }).toList();
  }

  void _onTap(Incident inc) {
    final status = _reviewedStatus(inc);
    Incident resolved = inc;

    // If incident is unreviewed (any status other than 'Yes'), mark it as reviewed
    if (status.toLowerCase() != 'yes') {
      // Apply locally first — this frame, not the next.
      setState(() {
        _statusOverrides[inc.id] = 'Yes';
        _selectedId = inc.id;
      });
      resolved = inc.copyWith(reviewedStatus: 'Yes');
      // Notify parent to keep master list in sync and update backend
      widget.onIncidentStatusUpdated?.call(resolved);
    } else {
      // Already reviewed, just select it
      setState(() => _selectedId = inc.id);
    }

    widget.onIncidentSelected?.call(resolved);
  }

  Map<String, Color> _getChipColors(String chipType, bool isDark, Color? accentColor) {
    switch (chipType) {
      case 'method':
        return {
          'fg': AppColors.accentBlueSoft,
          'bg': isDark ? AppColors.darkSecondaryBg : AppColors.lightSecondaryBg,
          'border': isDark ? AppColors.borderSecondary : AppColors.lightBorderSecondary,
        };
      case 'threat':
        return {
          'fg': accentColor ?? Colors.grey,
          'bg': (accentColor ?? Colors.grey).withOpacity(0.15),
          'border': (accentColor ?? Colors.grey).withOpacity(0.4),
        };
      case 'reviewed':
        return {
          'fg': accentColor ?? Colors.grey,
          'bg': (accentColor ?? Colors.grey).withOpacity(0.15),
          'border': (accentColor ?? Colors.grey).withOpacity(0.4),
        };
      default:
        return {'fg': Colors.grey, 'bg': Colors.grey, 'border': Colors.grey};
    }
  }

  // Responsive filter buttons - wraps on mobile, row on desktop
  Widget _buildFilterButtons(bool isDark) {
    final buttons = ['All', 'High', 'Medium', 'Unreviewed'];
    final width = MediaQuery.of(context).size.width;
    
    if (width < mobileBreakpoint) {
      return Wrap(
        spacing: 6,
        runSpacing: 6,
        children: buttons.map((f) {
          final active = _selectedFilter == f;
          return GestureDetector(
            onTap: () => setState(() => _selectedFilter = f),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
              decoration: BoxDecoration(
                color: active
                    ? (isDark ? AppColors.darkActiveBg : AppColors.lightActiveBg)
                    : (isDark ? AppColors.darkSecondaryBg : AppColors.lightSecondaryBg),
                border: Border.all(
                  color: active
                      ? (isDark ? AppColors.accentBlueHighlight : AppColors.lightAccentBlueHighlight)
                      : (isDark ? AppColors.borderSecondary : AppColors.lightBorderSecondary),
                ),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text(
                f,
                style: TextStyle(
                  fontSize: 10,
                  color: active
                      ? (isDark ? AppColors.accentBlueHighlight : AppColors.lightAccentBlueHighlight)
                      : (isDark ? AppColors.textLabel : AppColors.lightTextLabel),
                  fontWeight: active ? FontWeight.w500 : FontWeight.normal,
                ),
              ),
            ),
          );
        }).toList(),
      );
    }
    
    return Row(
      children: buttons.map((f) {
        final active = _selectedFilter == f;
        return GestureDetector(
          onTap: () => setState(() => _selectedFilter = f),
          child: Container(
            margin: const EdgeInsets.only(left: 6),
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
            decoration: BoxDecoration(
              color: active
                  ? (isDark ? AppColors.darkActiveBg : AppColors.lightActiveBg)
                  : (isDark ? AppColors.darkSecondaryBg : AppColors.lightSecondaryBg),
              border: Border.all(
                color: active
                    ? (isDark ? AppColors.accentBlueHighlight : AppColors.lightAccentBlueHighlight)
                    : (isDark ? AppColors.borderSecondary : AppColors.lightBorderSecondary),
              ),
              borderRadius: BorderRadius.circular(4),
            ),
            child: Text(
              f,
              style: TextStyle(
                fontSize: 11,
                color: active
                    ? (isDark ? AppColors.accentBlueHighlight : AppColors.lightAccentBlueHighlight)
                    : (isDark ? AppColors.textLabel : AppColors.lightTextLabel),
                fontWeight: active ? FontWeight.w500 : FontWeight.normal,
              ),
            ),
          ),
        );
      }).toList(),
    );
  }

  // Build card-based layout for mobile/tablet
  Widget _buildCardView(bool isDark, List<Incident> rows) {
    if (rows.isEmpty) {
      return Center(
        child: Text(
          'No incidents match this filter',
          style: TextStyle(
            color: isDark ? AppColors.textMutedDark : AppColors.lightTextMutedDark,
            fontSize: 12,
          ),
        ),
      );
    }

    return ListView.builder(
      itemCount: rows.length,
      itemBuilder: (context, index) {
        final inc = rows[index];
        final accent = _threatColor(inc.threat);
        final status = _reviewedStatus(inc);
        final reviewed = status.toLowerCase() == 'yes';
        final statusColor = reviewed ? AppColors.successReviewed : AppColors.warningPending;
        final isSelected = _selectedId == inc.id;

        return Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          child: InkWell(
            onTap: () => _onTap(inc),
            child: Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: isSelected
                    ? (isDark ? AppColors.darkActiveBg : AppColors.lightActiveBg)
                    : Colors.transparent,
                border: Border.all(
                  color: isSelected
                      ? (isDark ? AppColors.accentBlueHighlight : AppColors.lightAccentBlueHighlight)
                      : (isDark ? AppColors.borderDark : AppColors.lightBorderDark),
                ),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Expanded(
                        child: Text(
                          'ID: ${inc.id}',
                          style: TextStyle(
                            fontFamily: 'Courier New',
                            fontSize: 10,
                            fontWeight: FontWeight.w600,
                            color: isDark ? Color(0xFF6E7681) : AppColors.lightTextLabel,
                          ),
                        ),
                      ),
                      _Chip(
                        label: status,
                        fg: statusColor,
                        bg: statusColor.withOpacity(0.15),
                        border: statusColor.withOpacity(0.4),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Time: ${inc.time}',
                    style: TextStyle(
                      fontSize: 10,
                      color: isDark ? Color(0xFF4E5966) : AppColors.lightTextLabel,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Endpoint: ${inc.endpoint}',
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      fontSize: 10,
                      color: isDark ? Color(0xFFC9D1D9) : AppColors.lightTextLabel,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      Expanded(
                        child: Row(
                          children: [
                            Text(
                              'Method: ',
                              style: TextStyle(
                                fontSize: 9,
                                color: isDark ? AppColors.textMutedDark : AppColors.lightTextMutedDark,
                              ),
                            ),
                            Expanded(
                              child: _Chip(
                                label: inc.method,
                                fg: AppColors.accentBlueSoft,
                                bg: isDark ? AppColors.darkSecondaryBg : AppColors.lightSecondaryBg,
                                border: isDark ? AppColors.borderSecondary : AppColors.lightBorderSecondary,
                                mono: true,
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Row(
                          children: [
                            Text(
                              'Threat: ',
                              style: TextStyle(
                                fontSize: 9,
                                color: isDark ? AppColors.textMutedDark : AppColors.lightTextMutedDark,
                              ),
                            ),
                            Expanded(
                              child: _Chip(
                                label: inc.threat == 'Med' ? 'Medium' : inc.threat,
                                fg: accent,
                                bg: accent.withOpacity(0.15),
                                border: accent.withOpacity(0.4),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }

  // Build table layout for desktop
  Widget _buildTableView(bool isDark, List<Incident> rows) {
    if (rows.isEmpty) {
      return Center(
        child: Text(
          'No incidents match this filter',
          style: TextStyle(
            color: isDark ? AppColors.textMutedDark : AppColors.lightTextMutedDark,
            fontSize: 12,
          ),
        ),
      );
    }

    return ListView.builder(
      itemCount: rows.length,
      itemBuilder: (context, index) {
        final inc = rows[index];
        final accent = _threatColor(inc.threat);
        final status = _reviewedStatus(inc);
        final reviewed = status.toLowerCase() == 'yes';
        final statusColor = reviewed ? AppColors.successReviewed : AppColors.warningPending;
        final isSelected = _selectedId == inc.id;

        return InkWell(
          onTap: () => _onTap(inc),
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 11),
            decoration: BoxDecoration(
              color: isSelected
                  ? (isDark ? AppColors.darkActiveBg : AppColors.lightActiveBg)
                  : Colors.transparent,
              border: Border(
                left: isSelected
                    ? BorderSide(
                        color: isDark ? AppColors.accentBlueHighlight : AppColors.lightAccentBlueHighlight,
                        width: 2)
                    : BorderSide.none,
                bottom: BorderSide(color: isDark ? AppColors.darkSecondaryBg : AppColors.lightSecondaryBg),
              ),
            ),
            child: Row(
              children: [
                Expanded(
                  flex: 2,
                  child: Text(
                    inc.id,
                    style: TextStyle(
                      fontFamily: 'Courier New',
                      fontSize: 12,
                      color: isDark ? Color(0xFF6E7681) : AppColors.lightTextLabel,
                    ),
                  ),
                ),
                Expanded(
                  flex: 2,
                  child: Text(
                    inc.time,
                    style: TextStyle(
                      fontSize: 12,
                      color: isDark ? Color(0xFF4E5966) : AppColors.lightTextLabel,
                    ),
                  ),
                ),
                Expanded(
                  flex: 4,
                  child: Text(
                    inc.endpoint,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      fontSize: 12,
                      color: isDark ? Color(0xFFC9D1D9) : AppColors.lightTextLabel,
                    ),
                  ),
                ),
                Expanded(
                  flex: 2,
                  child: Align(
                    alignment: Alignment.centerLeft,
                    child: Builder(builder: (context) {
                      final methodColors = _getChipColors('method', isDark, null);
                      return _Chip(
                        label: inc.method,
                        fg: methodColors['fg']!,
                        bg: methodColors['bg']!,
                        border: methodColors['border']!,
                        mono: true,
                      );
                    }),
                  ),
                ),
                Expanded(
                  flex: 3,
                  child: Align(
                    alignment: Alignment.centerLeft,
                    child: _Chip(
                      label: inc.threat == 'Med' ? 'Medium' : inc.threat,
                      fg: accent,
                      bg: accent.withOpacity(0.15),
                      border: accent.withOpacity(0.4),
                    ),
                  ),
                ),
                Expanded(
                  flex: 3,
                  child: Align(
                    alignment: Alignment.centerLeft,
                    child: _Chip(
                      label: status,
                      fg: statusColor,
                      bg: statusColor.withOpacity(0.15),
                      border: statusColor.withOpacity(0.4),
                    ),
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    final themeProvider = context.watch<ThemeProvider>();
    final isDark = themeProvider.isDarkTheme;
    final rows = _filtered;
    final isDesktop = _isDesktop(context);

    return Container(
      decoration: BoxDecoration(
        color: isDark ? AppColors.darkCardBg : AppColors.lightCardBg,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
          color: isDark ? AppColors.borderDark : AppColors.lightBorderDark,
        ),
      ),
      child: Column(
        children: [
          // Header
          Padding(
            padding: EdgeInsets.fromLTRB(12, 10, 12, 10),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'INCIDENT LOG',
                  style: TextStyle(
                    fontSize: 11.5,
                    fontWeight: FontWeight.w500,
                    color: isDark ? AppColors.textLabel : AppColors.lightTextLabel,
                    letterSpacing: 0.8,
                  ),
                ),
                const SizedBox(height: 10),
                _buildFilterButtons(isDark),
              ],
            ),
          ),

          Divider(
            height: 1,
            color: isDark ? AppColors.borderDark : AppColors.lightBorderDark,
          ),

          // Show table header only on desktop
          if (isDesktop)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              color: isDark ? AppColors.darkHeaderBg : AppColors.lightHeaderBg,
              child: const Row(
                children: [
                  Expanded(flex: 2, child: _ColHeader('ID')),
                  Expanded(flex: 2, child: _ColHeader('TIME')),
                  Expanded(flex: 4, child: _ColHeader('ENDPOINT')),
                  Expanded(flex: 2, child: _ColHeader('METHOD')),
                  Expanded(flex: 3, child: _ColHeader('THREAT')),
                  Expanded(flex: 3, child: _ColHeader('REVIEWED')),
                ],
              ),
            ),

          // Content area - responsive
          Expanded(
            child: isDesktop
                ? _buildTableView(isDark, rows)
                : _buildCardView(isDark, rows),
          ),
        ],
      ),
    );
  }
}


class _ColHeader extends StatelessWidget {
  final String label;
  const _ColHeader(this.label);

  @override
  Widget build(BuildContext context) => Text(
        label,
        style: const TextStyle(
          fontSize: 10,
          color: AppColors.textMutedDark,
          fontWeight: FontWeight.w500,
          letterSpacing: 0.5,
        ),
      );
}

class _Chip extends StatelessWidget {
  final String label;
  final Color fg, bg, border;
  final bool mono;

  const _Chip({
    required this.label,
    required this.fg,
    required this.bg,
    required this.border,
    this.mono = false,
  });

  @override
  Widget build(BuildContext context) => Container(
        padding:
            const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
        decoration: BoxDecoration(
          color: bg,
          border: Border.all(color: border),
          borderRadius: BorderRadius.circular(4),
        ),
        child: Text(
          label,
          style: TextStyle(
            fontSize: 11,
            fontWeight: FontWeight.w600,
            color: fg,
            fontFamily: mono ? 'Courier New' : null,
          ),
        ),
      );
}