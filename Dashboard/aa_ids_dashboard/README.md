# AA-IDS Dashboard (Flutter Application)

The dashboard for the **Hybrid HTTP Anomaly Detection System (AA-IDS Prototype)** is implemented as a Flutter application, serving as the primary interface for monitoring and investigating security incidents.

This application is responsible for presenting processed data from the backend in a clear, responsive, and user-friendly format. It does not perform anomaly detection itself; instead, it consumes data from backend APIs powered by Django/Flask and the machine learning model.

## Core Responsibilities

* Display a real-time list of detected HTTP anomalies (incidents)
* Allow users to select and inspect individual incidents in detail
* Visualize request information and simplified network traces
* Reflect system status and threat levels in an intuitive UI

## Architecture Role

The Flutter dashboard operates as the presentation layer in the system architecture:

```
Flutter UI (Dashboard)
        ↓
Backend API (Django / Flask)
        ↓
ML Model (Anomaly Detection Engine)
        ↓
Database (Incidents & Logs)
```

## Key Characteristics

* Clean, modern, and responsive interface
* API-driven (REST/WebSocket integration)
* Decoupled from backend logic and ML processing
* Designed for scalability and real-time monitoring

This approach ensures a clear separation of concerns, allowing the backend to handle computation and data processing while Flutter delivers a polished and interactive user experience.


For help getting started with Flutter development, view the
[online documentation](https://docs.flutter.dev/), which offers tutorials,
samples, guidance on mobile development, and a full API reference.
