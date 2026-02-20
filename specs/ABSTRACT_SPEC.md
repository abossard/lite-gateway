# Lite Gateway Abstract Spec

## 1) Purpose
Lite Gateway (LGW) is a high-throughput edge reverse proxy between local instruments and Cloud Gateway (CGW), replacing the legacy IIS-based approach.

## 2) Core Architecture
- Transparent reverse proxy for device-to-cloud traffic.
- Pass-through payload handling (no business payload mutation).
- Bidirectional streaming and large transfer compatibility.
- Deployment target: Windows Service first; architecture should stay portable to K8S-style hosting.

## 3) Security Model
- Mandatory mTLS for inbound (device -> LGW) and outbound (LGW -> CGW) traffic.
- Trust model: "Never trust, always verify".
- Certificates managed through enterprise-safe stores/processes.
- Outbound requests must include customer identity header enrichment.

## 4) Scale + Traffic Envelope
- Baseline scale target: 3,000 connected instruments per Lite Gateway.
- Per-device steady-state volume: ~440 requests/day.
- LGW baseline throughput target: ~15.3 RPS (~918 RPM).
- Critical peak period: midnight synchronization burst.

## 5) PoC Performance Validation
- Test pattern: 4 iterations x 3,000 requests, 5-second spacing.
- Realism constraints:
  - mTLS active end-to-end.
  - 5-second artificial processing delay in cloud flow simulation.
  - No Keep-Alive in instrument-like scenarios.
- Success indicator: low rejection/error with response times in expected operational range.

## 6) Operations + Manageability
- Local authenticated admin UI for health, resources, network status, and service control.
- Control-plane agent supports polling, telemetry/log upload, remote command execution, and cached artifact delivery.

## 7) Installation + Migration
- Installer requires admin privileges.
- Must support migration from legacy IIS with rollback safety:
  - stop legacy service,
  - install/migrate LGW,
  - validate cloud connectivity,
  - rollback to IIS on validation failure.
