import 'package:flutter/material.dart';
import '/models/dashboard_models.dart';

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
        return const Color(0xFFFF7B72);
      case 'med':
      case 'medium':
        return const Color(0xFFE3B341);
      case 'low':
        return const Color(0xFF56D364);
      default:
        return const Color(0xFF8B949E);
    }
  }

  List<Incident> get _filtered {
    return widget.incidents.where((inc) {
      switch (_selectedFilter) {
        case 'High':
          return inc.threat.toLowerCase() == 'high';
        case 'Medium':
          return inc.threat.toLowerCase() == 'med' ||
              inc.threat.toLowerCase() == 'medium';
        case 'Unreviewed':
          // Use the local override so a just-reviewed row disappears
          // immediately without waiting for the parent rebuild.
          return _reviewedStatus(inc).toLowerCase() == 'pending';
        default:
          return true;
      }
    }).toList();
  }

  void _onTap(Incident inc) {
    final status = _reviewedStatus(inc);
    Incident resolved = inc;

    if (status.toLowerCase() == 'pending') {
      // Apply locally first — this frame, not the next.
      setState(() {
        _statusOverrides[inc.id] = 'Yes';
        _selectedId = inc.id;
      });
      resolved = inc.copyWith(reviewedStatus: 'Yes');
      // Notify parent to keep master list in sync.
      widget.onIncidentStatusUpdated?.call(resolved);
    } else {
      setState(() => _selectedId = inc.id);
    }

    widget.onIncidentSelected?.call(resolved);
  }

  @override
  Widget build(BuildContext context) {
    final rows = _filtered;

    return Container(
      decoration: BoxDecoration(
        color: const Color(0xFF0F1419),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: const Color(0xFF1E2530)),
      ),
      child: Column(
        children: [
          // Header
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                const Text(
                  'INCIDENT LOG',
                  style: TextStyle(
                    fontSize: 11.5,
                    fontWeight: FontWeight.w500,
                    color: Color(0xFF6E7681),
                    letterSpacing: 0.8,
                  ),
                ),
                Row(
                  children: ['All', 'High', 'Medium', 'Unreviewed']
                      .map((f) {
                    final active = _selectedFilter == f;
                    return GestureDetector(
                      onTap: () => setState(() => _selectedFilter = f),
                      child: Container(
                        margin: const EdgeInsets.only(left: 6),
                        padding: const EdgeInsets.symmetric(
                            horizontal: 10, vertical: 4),
                        decoration: BoxDecoration(
                          color: active
                              ? const Color(0xFF0C1A30)
                              : const Color(0xFF1A2230),
                          border: Border.all(
                            color: active
                                ? const Color(0xFF58A6FF)
                                : const Color(0xFF263040),
                          ),
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Text(
                          f,
                          style: TextStyle(
                            fontSize: 11,
                            color: active
                                ? const Color(0xFF58A6FF)
                                : const Color(0xFF6E7681),
                            fontWeight: active
                                ? FontWeight.w500
                                : FontWeight.normal,
                          ),
                        ),
                      ),
                    );
                  }).toList(),
                ),
              ],
            ),
          ),

          const Divider(height: 1, color: Color(0xFF1E2530)),

          // Column headers
          Container(
            padding: const EdgeInsets.symmetric(
                horizontal: 16, vertical: 10),
            color: const Color(0xFF111820),
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

          // Rows
          Expanded(
            child: rows.isEmpty
                ? const Center(
                    child: Text(
                      'No incidents match this filter',
                      style: TextStyle(
                          color: Color(0xFF4E5966), fontSize: 12),
                    ),
                  )
                : ListView.builder(
                    itemCount: rows.length,
                    itemBuilder: (context, index) {
                      if (index < 0 || index >= rows.length) {
                        return const SizedBox.shrink();
                      }
                      final inc = rows[index];
                      final accent = _threatColor(inc.threat);
                      final status = _reviewedStatus(inc);
                      final reviewed = status.toLowerCase() == 'yes';
                      final statusColor = reviewed
                          ? const Color(0xFF4ADE80)
                          : const Color(0xFFFFC107);
                      final isSelected = _selectedId == inc.id;

                      return InkWell(
                        onTap: () => _onTap(inc),
                        child: Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 16, vertical: 11),
                          decoration: BoxDecoration(
                            color: isSelected
                                ? const Color(0xFF0C1A30)
                                : Colors.transparent,
                            border: Border(
                              left: isSelected
                                  ? const BorderSide(
                                      color: Color(0xFF58A6FF),
                                      width: 2)
                                  : BorderSide.none,
                              bottom: const BorderSide(
                                  color: Color(0xFF1A2230)),
                            ),
                          ),
                          child: Row(
                            children: [
                              Expanded(
                                flex: 2,
                                child: Text(
                                  inc.id,
                                  style: const TextStyle(
                                    fontFamily: 'Courier New',
                                    fontSize: 12,
                                    color: Color(0xFF6E7681),
                                  ),
                                ),
                              ),
                              Expanded(
                                flex: 2,
                                child: Text(
                                  inc.time,
                                  style: const TextStyle(
                                      fontSize: 12,
                                      color: Color(0xFF4E5966)),
                                ),
                              ),
                              Expanded(
                                flex: 4,
                                child: Text(
                                  inc.endpoint,
                                  overflow: TextOverflow.ellipsis,
                                  style: const TextStyle(
                                      fontSize: 12,
                                      color: Color(0xFFC9D1D9)),
                                ),
                              ),
                              Expanded(
                                flex: 2,
                                child: Align(
                                  alignment: Alignment.centerLeft,
                                  child: _Chip(
                                    label: inc.method,
                                    fg: const Color(0xFF79C0FF),
                                    bg: const Color(0xFF1A2230),
                                    border: const Color(0xFF263040),
                                    mono: true,
                                  ),
                                ),
                              ),
                              Expanded(
                                flex: 3,
                                child: Align(
                                  alignment: Alignment.centerLeft,
                                  child: _Chip(
                                    label: inc.threat == 'Med'
                                        ? 'Medium'
                                        : inc.threat,
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
                                    border:
                                        statusColor.withOpacity(0.4),
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ),
                      );
                    },
                  ),
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
          color: Color(0xFF4E5966),
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