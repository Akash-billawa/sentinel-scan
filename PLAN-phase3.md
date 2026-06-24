# Phase 3 Implementation Plan

## 1. Scheduled Reports

### Backend
- **`backend/database.py`**: Add `ReportSchedule` model (frequency, last_run, next_run, is_active, recipients)
- **`backend/scheduler.py`**: Lightweight thread-based scheduler (apscheduler-free)
- **`backend/reports.py`**: Add `run_scheduled_reports()` that generates PDF and emails it
- **`backend/app.py`**: Add CRUD endpoints for schedule management

### Frontend
- Settings panel for report scheduling (frequency, email recipients)

## 2. Per-Source Attack Timeline

### Backend
- **`backend/app.py`**: `GET /api/sources/<ip>/timeline` endpoint
- Returns: attacks, packets, alerts per time bucket for a single source IP

### Frontend
- Timeline chart (Chart.js or native canvas) showing attack events over time
- Clickable dots for drill-down

## 3. Network Topology Visualization

### Backend
- **`backend/app.py`**: `GET /api/topology` endpoint
- Derives topology from `Attack` and `PacketEvent` tables (source → target edges)

### Frontend
- Force-directed graph using native canvas or lightweight D3.js (no heavy deps)
- Nodes: source IPs (size = packet count), target IPs
- Edges: directed attacks
- Color coding by scan type / risk level
