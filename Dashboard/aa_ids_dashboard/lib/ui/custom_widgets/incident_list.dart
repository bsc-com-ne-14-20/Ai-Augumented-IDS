import 'package:flutter/material.dart';
import '/models/dashboard_models.dart';

class IncidentList extends StatefulWidget {
  final List<Incident> incidents;
  final Function(Incident)? onIncidentSelected;

  const IncidentList({
    super.key,
    required this.incidents,
    this.onIncidentSelected,
  });

  @override
  State<IncidentList> createState() => _IncidentListState();
}

class _IncidentListState extends State<IncidentList> {
  String _selectedFilter = "All";

  Color _getThreatColor(String threat) {
    switch (threat.toLowerCase()) {
      case 'high':
        return const Color(0xFFFF7B72);
      case 'med':
      case 'medium':
        return const Color(0xFFE3B341);
      case 'low':
        return const Color(0xFF56D364);
      default:
        return Colors.grey;
    }
  }

  @override
  Widget build(BuildContext context) {
    final filteredIncidents = widget.incidents.where((inc) {
      if (_selectedFilter == "All") return true;
      if (_selectedFilter == "High") return inc.threat.toLowerCase() == "high";
      if (_selectedFilter == "Medium") return inc.threat.toLowerCase() == "med";
      if (_selectedFilter == "Open") return inc.status.toLowerCase() == "open";
      return true;
    }).toList();

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
                  "INCIDENT LIST",
                  style: TextStyle(
                    fontSize: 11.5,
                    fontWeight: FontWeight.w500,
                    color: Color(0xFF6E7681),
                    letterSpacing: 0.8,
                  ),
                ),
                // Filters
                Row(
                  children: ["All", "High", "Medium", "Open"].map((filter) {
                    final isActive = _selectedFilter == filter;
                    return GestureDetector(
                      onTap: () => setState(() => _selectedFilter = filter),
                      child: Container(
                        margin: const EdgeInsets.only(left: 6),
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                        decoration: BoxDecoration(
                          color: isActive ? const Color(0xFF0C1A30) : const Color(0xFF1A2230),
                          border: Border.all(
                            color: isActive ? const Color(0xFF58A6FF) : const Color(0xFF263040),
                          ),
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: Text(
                          filter,
                          style: TextStyle(
                            fontSize: 11,
                            color: isActive ? const Color(0xFF58A6FF) : const Color(0xFF6E7681),
                            fontWeight: isActive ? FontWeight.w500 : FontWeight.normal,
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

          // Table Header
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            color: const Color(0xFF111820),
            child: const Row(
              children: [
                Expanded(flex: 2, child: Text("ID", style: TextStyle(fontSize: 10, color: Color(0xFF4E5966), fontWeight: FontWeight.w500))),
                Expanded(flex: 2, child: Text("TIME", style: TextStyle(fontSize: 10, color: Color(0xFF4E5966), fontWeight: FontWeight.w500))),
                Expanded(flex: 4, child: Text("ENDPOINT", style: TextStyle(fontSize: 10, color: Color(0xFF4E5966), fontWeight: FontWeight.w500))),
                Expanded(flex: 2, child: Text("METHOD", style: TextStyle(fontSize: 10, color: Color(0xFF4E5966), fontWeight: FontWeight.w500))),
                Expanded(flex: 3, child: Text("THREAT", style: TextStyle(fontSize: 10, color: Color(0xFF4E5966), fontWeight: FontWeight.w500))),
                Expanded(flex: 3, child: Text("STATUS", style: TextStyle(fontSize: 10, color: Color(0xFF4E5966), fontWeight: FontWeight.w500))),
              ],
            ),
          ),

          // Table Body
          Expanded(
            child: ListView.builder(
              itemCount: filteredIncidents.length,
              itemBuilder: (context, index) {
                final inc = filteredIncidents[index];
                final accent = _getThreatColor(inc.threat);

                return InkWell(
                  onTap: () => widget.onIncidentSelected?.call(inc),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 11),
                    decoration: const BoxDecoration(
                      border: Border(bottom: BorderSide(color: Color(0xFF1A2230))),
                    ),
                    child: Row(
                      children: [
                        // ID
                        Expanded(
                          flex: 2,
                          child: Text(
                            inc.id,
                            style: const TextStyle(
                              fontFamily: 'Courier New',
                              fontSize: 12.5,
                              color: Color(0xFF6E7681),
                            ),
                          ),
                        ),
                        // Time
                        Expanded(
                          flex: 2,
                          child: Text(
                            inc.time,
                            style: const TextStyle(fontSize: 12.5, color: Color(0xFF4E5966)),
                          ),
                        ),
                        // Endpoint
                        Expanded(
                          flex: 4,
                          child: Text(
                            inc.endpoint,
                            overflow: TextOverflow.ellipsis,
                            style: const TextStyle(fontSize: 12.5, color: Color(0xFFC9D1D9)),
                          ),
                        ),
                        // Method
                        Expanded(
                          flex: 2,
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                            decoration: BoxDecoration(
                              color: const Color(0xFF1A2230),
                              border: Border.all(color: const Color(0xFF263040)),
                              borderRadius: BorderRadius.circular(3),
                            ),
                            child: Text(
                              inc.method,
                              textAlign: TextAlign.center,
                              style: const TextStyle(
                                fontFamily: 'Courier New',
                                fontSize: 11,
                                color: Color(0xFF79C0FF),
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                          ),
                        ),
                        // Threat
                        Expanded(
                          flex: 3,
                          child: Center(
                            child: Container(
                              padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 3),
                              decoration: BoxDecoration(
                                color: accent.withOpacity(0.15),
                                border: Border.all(color: accent.withOpacity(0.4)),
                                borderRadius: BorderRadius.circular(4),
                              ),
                              child: Text(
                                inc.threat == 'Med' ? 'Medium' : inc.threat,
                                style: TextStyle(
                                  color: accent,
                                  fontSize: 11.5,
                                  fontWeight: FontWeight.w600,
                                ),
                              ),
                            ),
                          ),
                        ),
                        // Status
                        Expanded(
                          flex: 3,
                          child: Row(
                            children: [
                              Icon(
                                inc.status.toLowerCase() == "open"
                                    ? Icons.circle
                                    : Icons.check_circle,
                                size: 13,
                                color: inc.status.toLowerCase() == "open"
                                    ? const Color(0xFFE3B341)
                                    : const Color(0xFF56D364),
                              ),
                              const SizedBox(width: 6),
                              Text(
                                inc.status.toLowerCase() == "open" ? "Open" : "Done",
                                style: TextStyle(
                                  fontSize: 12.5,
                                  color: inc.status.toLowerCase() == "open"
                                      ? const Color(0xFFE3B341)
                                      : const Color(0xFF56D364),
                                  fontWeight: FontWeight.w500,
                                ),
                              ),
                            ],
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