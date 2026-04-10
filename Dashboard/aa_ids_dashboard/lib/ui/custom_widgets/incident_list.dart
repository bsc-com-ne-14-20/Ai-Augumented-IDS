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
      if (_selectedFilter == "Unreviewed") return inc.reviewedStatus.toLowerCase() == "pending";
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
                  "INCIDENT LOG",
                  style: TextStyle(
                    fontSize: 11.5,
                    fontWeight: FontWeight.w500,
                    color: Color(0xFF6E7681),
                    letterSpacing: 0.8,
                  ),
                ),
                // Filters
                Row(
                  children: ["All", "High", "Medium", "Unreviewed"].map((filter) {
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
                Expanded(flex: 3, child: Text("REVIEWED", style: TextStyle(fontSize: 10, color: Color(0xFF4E5966), fontWeight: FontWeight.w500))),
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
                final isReviewed = inc.reviewedStatus.toLowerCase() == "yes";
                final statusColor = isReviewed
                    ? const Color(0xFF4ADE80)
                    : const Color(0xFFFFC107);

                return InkWell(
                  onTap: () {
                    // Update the reviewed status to "Yes" if it was "Pending"
                    if (inc.reviewedStatus.toLowerCase() == "pending") {
                      final updatedIncident = inc.copyWith(reviewedStatus: "Yes");
                      widget.onIncidentStatusUpdated?.call(updatedIncident);
                    }
                    // Select the incident
                    widget.onIncidentSelected?.call(inc);
                  },
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
                          child: Align(
                            alignment: Alignment.centerLeft,
                            child: Container(
                              padding: const EdgeInsets.symmetric(horizontal: 3, vertical: 0),
                              decoration: BoxDecoration(
                                color: const Color(0xFF1A2230),
                                border: Border.all(color: const Color(0xFF263040)),
                                borderRadius: BorderRadius.circular(3),
                              ),
                              child: Text(
                                inc.method,
                                style: const TextStyle(
                                  fontFamily: 'Courier New',
                                  fontSize: 11,
                                  color: Color(0xFF79C0FF),
                                  fontWeight: FontWeight.w500,
                                ),
                              ),
                            ),
                          ),
                        ),
                        // Threat
                        Expanded(
                          flex: 3,
                          child: Align(
                            alignment: Alignment.centerLeft,
                            child: Container(
                              padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 0),
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
                        // Reviewed (New Column)
                        Expanded(
                          flex: 3,
                          child: Align(
                            alignment: Alignment.centerLeft,
                            child: Container(
                              padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 0),
                              decoration: BoxDecoration(
                                color: statusColor.withOpacity(0.15),
                                border: Border.all(color: statusColor.withOpacity(0.4)),
                                borderRadius: BorderRadius.circular(4),
                              ),
                              child: Text(
                                inc.reviewedStatus,
                                style: TextStyle(
                                  fontSize: 12.5,
                                  fontWeight: FontWeight.w600,
                                  color: statusColor,
                                ),
                              ),
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