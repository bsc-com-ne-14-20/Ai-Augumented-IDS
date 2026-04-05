// lib/widgets/incident_list.dart

import 'package:flutter/material.dart';
import '/models/dashboard_models.dart';

class IncidentList extends StatelessWidget {
  final List<Incident> incidents;
  final String? selectedFilter; // "All", "High", "Medium", "Open", etc.
  final ValueChanged<String>? onFilterChanged;

  const IncidentList({
    super.key,
    required this.incidents,
    this.selectedFilter = "All",
    this.onFilterChanged,
  });

  // Helper to get color based on threat level
  Color _getThreatColor(String threat) {
    switch (threat.toLowerCase()) {
      case 'high':
        return const Color(0xFFE11D48); // Red
      case 'medium':
        return const Color(0xFFF59E0B); // Orange
      case 'low':
        return const Color(0xFF10B981); // Green
      default:
        return Colors.grey;
    }
  }

  // Helper to get status icon and color
  Widget _buildStatus(String status) {
    final isDone = status.toLowerCase() == "done";

    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(
          isDone ? Icons.check_circle : Icons.circle,
          size: 14,
          color: isDone ? const Color(0xFF34D399) : const Color(0xFFFBBF24),
        ),
        const SizedBox(width: 6),
        Text(
          status,
          style: TextStyle(
            color: isDone ? const Color(0xFF34D399) : const Color(0xFFFBBF24),
            fontSize: 13,
            fontWeight: FontWeight.w500,
          ),
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: const Color(0xFF1A1F2E),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header with Title and Filters
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 16, 20, 12),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                const Text(
                  "INCIDENT LIST",
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                // Filter Chips
                Row(
                  children: ["All", "High", "Medium", "Open"].map((filter) {
                    final isSelected = selectedFilter == filter;
                    return Padding(
                      padding: const EdgeInsets.only(left: 6),
                      child: FilterChip(
                        label: Text(filter),
                        selected: isSelected,
                        onSelected: (selected) {
                          if (onFilterChanged != null) {
                            onFilterChanged!(filter);
                          }
                        },
                        backgroundColor: const Color(0xFF2A3348),
                        selectedColor: const Color(0xFF3B82F6),
                        labelStyle: TextStyle(
                          color: isSelected ? Colors.white : Colors.white70,
                          fontSize: 12,
                        ),
                        padding: const EdgeInsets.symmetric(horizontal: 10),
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(20),
                        ),
                      ),
                    );
                  }).toList(),
                ),
              ],
            ),
          ),

          const Divider(height: 1, color: Colors.white12),

          // Table Header
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
            decoration: const BoxDecoration(
              color: Color(0xFF252B3D),
            ),
            child: const Row(
              children: [
                Expanded(flex: 2, child: Text("ID", style: TextStyle(color: Colors.white54, fontSize: 12))),
                Expanded(flex: 2, child: Text("TIME", style: TextStyle(color: Colors.white54, fontSize: 12))),
                Expanded(flex: 4, child: Text("ENDPOINT", style: TextStyle(color: Colors.white54, fontSize: 12))),
                Expanded(flex: 2, child: Text("MTH", style: TextStyle(color: Colors.white54, fontSize: 12))),
                Expanded(flex: 3, child: Text("THREAT", style: TextStyle(color: Colors.white54, fontSize: 12))),
                Expanded(flex: 3, child: Text("STATUS", style: TextStyle(color: Colors.white54, fontSize: 12))),
              ],
            ),
          ),

          // Incident Rows
          Expanded(
            child: ListView.builder(
              itemCount: incidents.length,
              itemBuilder: (context, index) {
                final incident = incidents[index];
                return Container(
                  padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
                  decoration: BoxDecoration(
                    border: Border(
                      bottom: BorderSide(color: Colors.white.withOpacity(0.06)),
                    ),
                  ),
                  child: Row(
                    children: [
                      // ID
                      Expanded(
                        flex: 2,
                        child: Text(
                          incident.id,
                          style: const TextStyle(color: Colors.white, fontSize: 14),
                        ),
                      ),
                      // Time
                      Expanded(
                        flex: 2,
                        child: Text(
                          incident.time,
                          style: const TextStyle(color: Colors.white70, fontSize: 14),
                        ),
                      ),
                      // Endpoint
                      Expanded(
                        flex: 4,
                        child: Text(
                          incident.endpoint,
                          style: const TextStyle(color: Colors.white70, fontSize: 14),
                        ),
                      ),
                      // Method
                      Expanded(
                        flex: 2,
                        child: Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                          decoration: BoxDecoration(
                            color: const Color(0xFF334155),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(
                            incident.method,
                            textAlign: TextAlign.center,
                            style: const TextStyle(
                              color: Color(0xFF94A3B8),
                              fontSize: 12,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                      ),
                      // Threat
                      Expanded(
                        flex: 3,
                        child: Container(
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                          decoration: BoxDecoration(
                            color: _getThreatColor(incident.threat).withOpacity(0.15),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(
                            incident.threat,
                            textAlign: TextAlign.center,
                            style: TextStyle(
                              color: _getThreatColor(incident.threat),
                              fontSize: 13,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                      ),
                      // Status
                      Expanded(
                        flex: 3,
                        child: _buildStatus(incident.status),
                      ),
                    ],
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