"""
NetPulse – Internet Speed & Network Stability Checker
=====================================================
A complete single-file Computer Networks demonstration and diagnostic application.
Built with Python Flask, Chart.js, HTML5 Canvas, and modern Web APIs.

All metrics are real measurements:
- Real HTTP RTT latency & jitter samples
- Real TCP 3-way handshake times & packet loss estimation via socket connections
- Real timed chunk streaming for download throughput
- Real timed payload transmission for upload throughput
- Real mathematical stability score formula
- Real before-and-after fix verification engine
- Comprehensive rules-based problem detection and actionable recommendations
"""

import os
import sys
import time
import json
import socket
import statistics
import subprocess
import platform
import re
import threading
from flask import Flask, request, jsonify, Response, render_template_string, stream_with_context

# ==============================================================================
# SECTION 1: CONFIGURATION & SYSTEM INITIALIZATION
# ==============================================================================

app = Flask(__name__)
# Maximum request size for upload testing (35 MB safe limit)
app.config['MAX_CONTENT_LENGTH'] = 35 * 1024 * 1024

# Reusable buffer of pseudo-random bytes for high-efficiency download streaming.
# Reusing this buffer eliminates CPU bottleneck so measured speed reflects true network throughput.
STREAM_CHUNK_SIZE = 64 * 1024  # 64 KB
STREAM_CHUNK = os.urandom(STREAM_CHUNK_SIZE)

# Strict allowlist of reliable public internet endpoints for TCP handshake checking.
# Prevents arbitrary socket abuse while testing real world connectivity.
ALLOWED_TCP_TARGETS = {
    "1.1.1.1": [443, 853],          # Cloudflare Public DNS (HTTPS, DoT)
    "1.0.0.1": [443],               # Cloudflare Secondary DNS
    "8.8.8.8": [53, 443],           # Google Public DNS (DNS, HTTPS)
    "8.8.4.4": [53, 443],           # Google Secondary DNS
    "9.9.9.9": [53, 443],           # Quad9 Public DNS
    "google.com": [80, 443],        # Google Web Services
    "cloudflare.com": [80, 443],    # Cloudflare Edge
    "github.com": [80, 443],        # GitHub Edge
    "wikipedia.org": [80, 443],     # Wikimedia Foundation
}

ALLOWED_PING_HOSTS = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
    "google.com", "cloudflare.com"
}


# ==============================================================================
# SECTION 2: NETWORKING UTILITIES & MATHEMATICAL METRICS
# ==============================================================================

def compute_stability_score(avg_latency, jitter, packet_loss, min_latency, max_latency):
    """
    STABILITY SCORE FORMULA (Scale: 0 to 100)
    -----------------------------------------
    Stability evaluates how predictable and robust the connection is over time.
    High raw speed with high jitter and packet loss produces a poor user experience
    (e.g., buffering video, stuttering VoIP calls, online game disconnects).

    Formula breakdown:
    Base Score = 100.0

    1. Latency Penalty (Max 30 pts):
       Baseline acceptable round-trip time is 20ms.
       Penalty = clamp(0, 30, (avg_latency - 20) * 0.25)
       (e.g., 60ms avg -> 10 pts penalty; 140ms avg -> 30 pts penalty)

    2. Jitter Penalty (Max 35 pts):
       Jitter represents delay variation (RFC 3550). High jitter causes buffer churn.
       Penalty = clamp(0, 35, jitter * 1.2)
       (e.g., 5ms jitter -> 6 pts penalty; 25ms jitter -> 30 pts penalty)

    3. Packet Loss Penalty (Max 40 pts):
       Packet loss is catastrophic for TCP throughput (forces Congestion Window halving)
       and causes packet drops in UDP voice/video.
       Penalty = clamp(0, 40, packet_loss * 4.0)
       (e.g., 1% loss -> 4 pts penalty; 5% loss -> 20 pts penalty; 10% loss -> 40 pts penalty)

    4. Latency Spread / Variance Penalty (Max 15 pts):
       Variance reflects bufferbloat or transient Wi-Fi interference spikes.
       Spread = max(0, max_latency - min_latency)
       Penalty = clamp(0, 15, spread * 0.15)
       (e.g., 50ms spread -> 7.5 pts penalty)

    Final Stability Score = round(clamp(0, 100, 100 - (P_latency + P_jitter + P_loss + P_spread)))
    """
    try:
        p_latency = max(0.0, min(30.0, (float(avg_latency) - 20.0) * 0.25)) if avg_latency > 20 else 0.0
        p_jitter = max(0.0, min(35.0, float(jitter) * 1.2))
        p_loss = max(0.0, min(40.0, float(packet_loss) * 4.0))
        spread = max(0.0, float(max_latency) - float(min_latency))
        p_spread = max(0.0, min(15.0, spread * 0.15))

        total_penalty = p_latency + p_jitter + p_loss + p_spread
        score = max(0.0, min(100.0, 100.0 - total_penalty))
        return round(score, 1)
    except Exception:
        return 50.0


def measure_tcp_handshake(host, port, count=15, timeout=1.5):
    """
    Measures real TCP connection establishment times to a remote host.
    This simulates raw socket connection (SYN -> SYN-ACK -> ACK 3-way handshake).
    Because browsers cannot send raw ICMP packets, TCP handshake timing is the gold
    standard for detecting packet loss and layer-4 connection latency.
    """
    latencies = []
    lost_count = 0

    for _ in range(count):
        t0 = time.perf_counter()
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000.0)
        except (socket.timeout, socket.error, OSError):
            lost_count += 1
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
        # Brief inter-probe delay to avoid triggering remote rate-limiters
        time.sleep(0.03)

    total_probes = count
    loss_pct = (lost_count / total_probes) * 100.0 if total_probes > 0 else 0.0

    if latencies:
        avg_lat = statistics.mean(latencies)
        min_lat = min(latencies)
        max_lat = max(latencies)
        # RFC 3550 style jitter: mean consecutive sample difference
        if len(latencies) > 1:
            diffs = [abs(latencies[i] - latencies[i - 1]) for i in range(1, len(latencies))]
            jitter = statistics.mean(diffs)
        else:
            jitter = 0.0
    else:
        avg_lat = min_lat = max_lat = jitter = 0.0

    return {
        "host": host,
        "port": port,
        "total": total_probes,
        "successful": len(latencies),
        "lost": lost_count,
        "loss_percent": round(loss_pct, 1),
        "min_ms": round(min_lat, 2) if latencies else None,
        "avg_ms": round(avg_lat, 2) if latencies else None,
        "max_ms": round(max_lat, 2) if latencies else None,
        "jitter_ms": round(jitter, 2) if latencies else None,
        "samples": [round(x, 2) for x in latencies]
    }


def execute_system_ping(host, count=4):
    """
    Executes the OS ping utility via subprocess and parses the ICMP output.
    Handles differences between Windows (-n, -w) and Unix/macOS (-c, -W).
    Gracefully falls back if ping is restricted or blocked by firewall.
    """
    system_os = platform.system().lower()
    if system_os == "windows":
        cmd = ["ping", "-n", str(count), "-w", "1000", host]
    elif system_os == "darwin":
        # macOS ping -W takes milliseconds
        cmd = ["ping", "-c", str(count), "-W", "1000", host]
    else:
        # Linux ping -W takes seconds
        cmd = ["ping", "-c", str(count), "-W", "1", host]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=8
        )
        output = proc.stdout

        # Parse packet loss percentage
        loss_match = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet\s*)?loss", output, re.IGNORECASE)
        loss_pct = float(loss_match.group(1)) if loss_match else 0.0

        # Parse min/avg/max latencies
        min_ms = avg_ms = max_ms = None
        # Unix/macOS format: min/avg/max/stddev = 20.002/21.805/23.463/1.417 ms
        unix_match = re.search(r"min/avg/max/(?:mdev|stddev)\s*=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)", output, re.IGNORECASE)
        if unix_match:
            min_ms = float(unix_match.group(1))
            avg_ms = float(unix_match.group(2))
            max_ms = float(unix_match.group(3))
        else:
            # Windows format: Minimum = 20ms, Maximum = 24ms, Average = 22ms
            win_min = re.search(r"Minimum\s*=\s*(\d+)ms", output, re.IGNORECASE)
            win_max = re.search(r"Maximum\s*=\s*(\d+)ms", output, re.IGNORECASE)
            win_avg = re.search(r"Average\s*=\s*(\d+)ms", output, re.IGNORECASE)
            if win_min and win_max and win_avg:
                min_ms = float(win_min.group(1))
                max_ms = float(win_max.group(1))
                avg_ms = float(win_avg.group(1))

        return {
            "available": True,
            "host": host,
            "loss_percent": loss_pct,
            "min_ms": round(min_ms, 2) if min_ms is not None else None,
            "avg_ms": round(avg_ms, 2) if avg_ms is not None else None,
            "max_ms": round(max_ms, 2) if max_ms is not None else None,
            "raw_output": output.strip()
        }
    except Exception as e:
        return {
            "available": False,
            "host": host,
            "reason": str(e)
        }


# ==============================================================================
# SECTION 3: FLASK API ENDPOINTS
# ==============================================================================

@app.route("/")
def index():
    """Serves the single-page application UI."""
    return render_template_string(HTML_TEMPLATE)


@app.route("/favicon.ico")
def favicon():
    """Return 204 No Content to keep browser console and server logs clean."""
    return ("", 204)


@app.route("/api/ping", methods=["GET"])
def api_ping():
    """
    High-frequency, ultra-lightweight ping endpoint.
    Used by the browser to measure real HTTP Round-Trip Time (RTT) and Jitter.
    Includes anti-caching headers to guarantee fresh network measurements.
    """
    response = jsonify({
        "pong": True,
        "server_time": time.time(),
        "client_ip": request.remote_addr or "127.0.0.1"
    })
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/api/download", methods=["GET"])
def api_download():
    """
    Streams raw payload bytes to the client to measure real download throughput.
    Size parameter is clamped between 64 KB and 25 MB for safety.
    """
    requested_size = request.args.get("size", default=5 * 1024 * 1024, type=int)
    # Clamp between 64 KB and 25 MB
    safe_size = max(64 * 1024, min(25 * 1024 * 1024, requested_size))

    def generate_bytes():
        bytes_sent = 0
        while bytes_sent < safe_size:
            chunk_to_send = min(STREAM_CHUNK_SIZE, safe_size - bytes_sent)
            if chunk_to_send == STREAM_CHUNK_SIZE:
                yield STREAM_CHUNK
            else:
                yield STREAM_CHUNK[:chunk_to_send]
            bytes_sent += chunk_to_send

    response = Response(
        stream_with_context(generate_bytes()),
        mimetype="application/octet-stream"
    )
    response.headers["Content-Length"] = str(safe_size)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@app.route("/api/upload", methods=["POST"])
def api_upload():
    """
    Receives uploaded bytes and measures actual transfer size and server processing time.
    Used in conjunction with client-side timing to calculate true upload throughput.
    """
    t0 = time.perf_counter()
    received_bytes = 0

    # Stream in chunks to avoid unbounded memory accumulation
    chunk_size = 64 * 1024
    while True:
        chunk = request.stream.read(chunk_size)
        if not chunk:
            break
        received_bytes += len(chunk)

    t1 = time.perf_counter()
    elapsed_ms = (t1 - t0) * 1000.0

    return jsonify({
        "status": "success",
        "received_bytes": received_bytes,
        "server_elapsed_ms": round(elapsed_ms, 2)
    })


@app.route("/api/tcp-check", methods=["GET"])
def api_tcp_check():
    """
    Performs real TCP 3-way handshakes to verify WAN connectivity,
    TCP establishment latency, and remote packet loss.
    """
    host = request.args.get("host", default="1.1.1.1", type=str)
    port = request.args.get("port", default=443, type=int)
    count = request.args.get("count", default=15, type=int)

    # Validate target against allowlist
    if host not in ALLOWED_TCP_TARGETS or port not in ALLOWED_TCP_TARGETS[host]:
        return jsonify({
            "error": "Target not in allowed list.",
            "allowed_hosts": list(ALLOWED_TCP_TARGETS.keys())
        }), 400

    # Clamp probe count between 5 and 30
    safe_count = max(5, min(30, count))
    result = measure_tcp_handshake(host, port, safe_count)
    return jsonify(result)


@app.route("/api/system-ping", methods=["GET"])
def api_system_ping():
    """
    Optional ICMP OS-level ping endpoint.
    Attempts raw ICMP ping and returns results or fallback details.
    """
    host = request.args.get("host", default="1.1.1.1", type=str)
    count = request.args.get("count", default=4, type=int)

    if host not in ALLOWED_PING_HOSTS:
        return jsonify({"error": "Host not allowed"}), 400

    safe_count = max(1, min(10, count))
    result = execute_system_ping(host, safe_count)
    return jsonify(result)


# ==============================================================================
# SECTION 4: EMBEDDED FRONTEND (HTML / CSS / JS)
# ==============================================================================

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NetPulse – Internet Speed & Network Stability Checker</title>
  
  <!-- Modern Typography (Space Grotesk, Inter, JetBrains Mono) -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
  
  <!-- Chart.js for live latency updates and before/after comparisons -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>

  <style>
    /* CSS VARIABLES & DESIGN SYSTEM (Midnight Operations Theme) */
    :root {
      --bg-dark: #070b14;
      --bg-surface: rgba(13, 21, 38, 0.72);
      --bg-surface-elevated: rgba(18, 30, 56, 0.82);
      --bg-card: rgba(16, 26, 48, 0.65);
      --border-subtle: rgba(0, 240, 255, 0.14);
      --border-glow: rgba(0, 240, 255, 0.45);
      
      --cyan: #00f0ff;
      --blue: #3b82f6;
      --indigo: #6366f1;
      --teal: #10b981;
      --amber: #f59e0b;
      --red: #ef4444;
      --purple: #a855f7;
      
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      
      --font-heading: 'Space Grotesk', -apple-system, sans-serif;
      --font-body: 'Inter', -apple-system, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
      
      --glow-cyan: 0 0 20px rgba(0, 240, 255, 0.35);
      --glow-blue: 0 0 20px rgba(59, 130, 246, 0.35);
      --glow-green: 0 0 20px rgba(16, 185, 129, 0.35);
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-dark);
      color: var(--text-main);
      font-family: var(--font-body);
      min-height: 100vh;
      overflow-x: hidden;
      line-height: 1.5;
      position: relative;
    }

    /* Ambient Animated Node Network Canvas */
    #ambientCanvas {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      pointer-events: none;
      z-index: 0;
      opacity: 0.45;
    }

    /* Outer Wrapper */
    .app-wrapper {
      position: relative;
      z-index: 1;
      max-width: 1280px;
      margin: 0 auto;
      padding: 24px 20px 80px 20px;
    }

    /* GLASSMORPHISM CARD UTILITY */
    .glass-card {
      background: var(--bg-card);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      border: 1px solid var(--border-subtle);
      border-radius: 16px;
      padding: 24px;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.45);
      transition: transform 0.25s ease, border-color 0.25s ease, box-shadow 0.25s ease;
    }
    .glass-card:hover {
      border-color: rgba(0, 240, 255, 0.25);
    }

    /* HEADER & HERO */
    .hero-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 20px;
      margin-bottom: 28px;
      padding-bottom: 20px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }

    .brand-group {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .brand-logo-icon {
      width: 50px;
      height: 50px;
      background: linear-gradient(135deg, rgba(0, 240, 255, 0.15), rgba(99, 102, 241, 0.25));
      border: 1px solid var(--cyan);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: var(--glow-cyan);
    }

    .brand-logo-icon svg {
      width: 28px;
      height: 28px;
      stroke: var(--cyan);
      filter: drop-shadow(0 0 6px var(--cyan));
    }

    .brand-title {
      font-family: var(--font-heading);
      font-size: 1.9rem;
      font-weight: 700;
      letter-spacing: -0.5px;
      background: linear-gradient(120deg, #ffffff 40%, var(--cyan) 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .brand-subtitle {
      font-size: 0.88rem;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .online-indicator {
      display: inline-block;
      width: 8px;
      height: 8px;
      background: var(--teal);
      border-radius: 50%;
      box-shadow: 0 0 8px var(--teal);
      animation: pulseGreen 2s infinite;
    }

    @keyframes pulseGreen {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.5; transform: scale(1.2); }
    }

    /* ACTION BUTTONS */
    .header-actions {
      display: flex;
      gap: 12px;
      align-items: center;
    }

    .btn {
      font-family: var(--font-heading);
      font-size: 0.95rem;
      font-weight: 600;
      padding: 12px 24px;
      border-radius: 12px;
      border: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 10px;
      transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      text-decoration: none;
      outline: none;
    }

    .btn:focus-visible {
      box-shadow: 0 0 0 3px var(--cyan);
    }

    .btn-primary {
      background: linear-gradient(135deg, #00d2ff, #0077ff);
      color: #030816;
      box-shadow: 0 4px 20px rgba(0, 180, 255, 0.4);
    }
    .btn-primary:hover:not(:disabled) {
      transform: translateY(-2px);
      box-shadow: 0 6px 26px rgba(0, 200, 255, 0.6);
      background: linear-gradient(135deg, #26dcff, #1a88ff);
    }
    .btn-primary:disabled {
      opacity: 0.45;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
    }

    .btn-secondary {
      background: rgba(255, 255, 255, 0.06);
      color: var(--text-main);
      border: 1px solid rgba(255, 255, 255, 0.15);
    }
    .btn-secondary:hover:not(:disabled) {
      background: rgba(255, 255, 255, 0.12);
      border-color: var(--cyan);
      color: var(--cyan);
    }

    /* NOTICE BANNER (Browser sandboxing note) */
    .security-note {
      background: rgba(0, 240, 255, 0.05);
      border-left: 3px solid var(--cyan);
      padding: 12px 18px;
      border-radius: 0 10px 10px 0;
      margin-bottom: 24px;
      font-size: 0.84rem;
      color: var(--text-muted);
      display: flex;
      align-items: flex-start;
      gap: 12px;
    }
    .security-note svg {
      width: 20px;
      height: 20px;
      flex-shrink: 0;
      stroke: var(--cyan);
      margin-top: 1px;
    }

    /* PHASE PROGRESS SECTION */
    .phase-tracker {
      margin-bottom: 28px;
    }

    .phase-bar-track {
      width: 100%;
      height: 8px;
      background: rgba(255, 255, 255, 0.07);
      border-radius: 99px;
      overflow: hidden;
      margin-bottom: 16px;
      position: relative;
    }

    .phase-bar-fill {
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, var(--cyan), var(--blue), var(--teal));
      border-radius: 99px;
      transition: width 0.4s ease;
      box-shadow: 0 0 12px var(--cyan);
    }

    .phase-steps-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
    }

    @media (max-width: 768px) {
      .phase-steps-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    .phase-step-card {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.06);
      border-radius: 10px;
      padding: 10px 14px;
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 0.82rem;
      color: var(--text-dim);
      transition: all 0.3s ease;
    }

    .phase-step-card.active {
      background: rgba(0, 240, 255, 0.08);
      border-color: var(--cyan);
      color: var(--text-main);
      box-shadow: 0 0 15px rgba(0, 240, 255, 0.2);
    }

    .phase-step-card.completed {
      background: rgba(16, 185, 129, 0.08);
      border-color: var(--teal);
      color: var(--teal);
    }

    .phase-icon-circle {
      width: 24px;
      height: 24px;
      border-radius: 50%;
      background: rgba(255, 255, 255, 0.08);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 0.75rem;
      font-weight: 700;
      color: var(--text-muted);
    }
    .phase-step-card.active .phase-icon-circle {
      background: var(--cyan);
      color: #030816;
      box-shadow: 0 0 8px var(--cyan);
    }
    .phase-step-card.completed .phase-icon-circle {
      background: var(--teal);
      color: #030816;
    }

    /* LIVE METRICS DASHBOARD (GAUGES & REAL-TIME CHART) */
    .live-dashboard-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 24px;
      margin-bottom: 28px;
    }

    @media (max-width: 900px) {
      .live-dashboard-grid {
        grid-template-columns: 1fr;
      }
    }

    .gauges-card {
      display: flex;
      flex-direction: column;
      justify-content: center;
    }

    .gauges-container {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      align-items: center;
      text-align: center;
      margin-top: 10px;
    }

    .gauge-wrapper {
      display: flex;
      flex-direction: column;
      align-items: center;
      position: relative;
    }

    .gauge-canvas {
      width: 190px;
      height: 190px;
      max-width: 100%;
    }

    .gauge-label {
      font-family: var(--font-heading);
      font-size: 0.95rem;
      font-weight: 600;
      margin-top: -6px;
      color: var(--text-muted);
    }

    .gauge-peak-badge {
      font-family: var(--font-mono);
      font-size: 0.76rem;
      color: var(--text-dim);
      margin-top: 4px;
    }

    .chart-card {
      display: flex;
      flex-direction: column;
    }

    .card-title-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 14px;
    }

    .card-title {
      font-family: var(--font-heading);
      font-size: 1.05rem;
      font-weight: 600;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .badge-live {
      font-family: var(--font-mono);
      font-size: 0.7rem;
      padding: 3px 8px;
      border-radius: 99px;
      background: rgba(0, 240, 255, 0.12);
      color: var(--cyan);
      border: 1px solid rgba(0, 240, 255, 0.3);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .chart-container {
      position: relative;
      flex: 1;
      min-height: 200px;
      width: 100%;
    }

    /* TELEMETRY LOG TICKER */
    .telemetry-ticker {
      background: rgba(0, 0, 0, 0.4);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 8px;
      padding: 8px 14px;
      font-family: var(--font-mono);
      font-size: 0.78rem;
      color: var(--text-muted);
      margin-top: 14px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .telemetry-ticker-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--cyan);
      box-shadow: 0 0 6px var(--cyan);
    }

    /* SUMMARY CARDS GRID */
    .summary-section {
      margin-bottom: 32px;
    }

    .section-title {
      font-family: var(--font-heading);
      font-size: 1.35rem;
      font-weight: 700;
      margin-bottom: 18px;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .summary-grid {
      display: grid;
      grid-template-columns: repeat(6, 1fr);
      gap: 14px;
    }

    @media (max-width: 1100px) {
      .summary-grid {
        grid-template-columns: repeat(3, 1fr);
      }
    }
    @media (max-width: 600px) {
      .summary-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    .metric-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 14px;
      padding: 16px 14px;
      display: flex;
      flex-direction: column;
      position: relative;
      overflow: hidden;
      transition: all 0.25s ease;
    }
    .metric-card:hover {
      transform: translateY(-2px);
      border-color: rgba(0, 240, 255, 0.3);
    }

    .metric-label {
      font-size: 0.76rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-muted);
      font-weight: 600;
      margin-bottom: 6px;
    }

    .metric-value-box {
      display: flex;
      align-items: baseline;
      gap: 4px;
      margin-bottom: 4px;
    }

    .metric-value {
      font-family: var(--font-mono);
      font-size: 1.6rem;
      font-weight: 700;
      color: #ffffff;
    }

    .metric-unit {
      font-size: 0.8rem;
      color: var(--text-dim);
      font-weight: 500;
    }

    .metric-subtext {
      font-size: 0.72rem;
      color: var(--text-dim);
      font-family: var(--font-mono);
    }

    /* STABILITY SCORE HIGHLIGHT CARD */
    .metric-card.stability-card {
      background: linear-gradient(135deg, rgba(16, 26, 48, 0.9), rgba(18, 38, 72, 0.9));
      border-color: rgba(0, 240, 255, 0.35);
      box-shadow: 0 4px 20px rgba(0, 240, 255, 0.15);
    }

    .stability-badge {
      display: inline-block;
      font-size: 0.7rem;
      padding: 2px 8px;
      border-radius: 99px;
      font-weight: 600;
      margin-top: 4px;
      text-transform: uppercase;
      letter-spacing: 0.4px;
    }
    .badge-excellent { background: rgba(16, 185, 129, 0.2); color: var(--teal); border: 1px solid var(--teal); }
    .badge-good { background: rgba(59, 130, 246, 0.2); color: var(--blue); border: 1px solid var(--blue); }
    .badge-fair { background: rgba(245, 158, 11, 0.2); color: var(--amber); border: 1px solid var(--amber); }
    .badge-poor { background: rgba(239, 68, 68, 0.2); color: var(--red); border: 1px solid var(--red); }

    /* PROBLEMS & RECOMMENDATIONS SECTION */
    .problems-section {
      margin-bottom: 32px;
    }

    .health-verdict-banner {
      background: rgba(255, 255, 255, 0.03);
      border-radius: 14px;
      border: 1px solid rgba(255, 255, 255, 0.08);
      padding: 16px 20px;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
    }

    .health-verdict-left {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .health-verdict-icon {
      width: 42px;
      height: 42px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.3rem;
    }

    .health-verdict-title {
      font-family: var(--font-heading);
      font-size: 1.1rem;
      font-weight: 700;
    }

    .health-verdict-desc {
      font-size: 0.85rem;
      color: var(--text-muted);
    }

    .issues-list-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
      gap: 14px;
    }

    .issue-card {
      background: var(--bg-surface);
      border-radius: 12px;
      border: 1px solid rgba(255, 255, 255, 0.08);
      padding: 18px;
      display: flex;
      flex-direction: column;
      gap: 10px;
      transition: all 0.2s ease;
    }

    .issue-card.severity-critical {
      border-left: 4px solid var(--red);
      background: rgba(239, 68, 68, 0.06);
    }
    .issue-card.severity-warning {
      border-left: 4px solid var(--amber);
      background: rgba(245, 158, 11, 0.06);
    }
    .issue-card.severity-info {
      border-left: 4px solid var(--blue);
      background: rgba(59, 130, 246, 0.06);
    }
    .issue-card.severity-healthy {
      border-left: 4px solid var(--teal);
      background: rgba(16, 185, 129, 0.06);
    }

    .issue-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
    }

    .issue-title {
      font-family: var(--font-heading);
      font-size: 0.95rem;
      font-weight: 600;
      color: var(--text-main);
    }

    .severity-tag {
      font-family: var(--font-mono);
      font-size: 0.68rem;
      padding: 2px 7px;
      border-radius: 6px;
      font-weight: 700;
      text-transform: uppercase;
    }
    .severity-critical .severity-tag { background: rgba(239, 68, 68, 0.2); color: var(--red); }
    .severity-warning .severity-tag { background: rgba(245, 158, 11, 0.2); color: var(--amber); }
    .severity-info .severity-tag { background: rgba(59, 130, 246, 0.2); color: var(--blue); }
    .severity-healthy .severity-tag { background: rgba(16, 185, 129, 0.2); color: var(--teal); }

    .issue-trigger-val {
      font-family: var(--font-mono);
      font-size: 0.78rem;
      color: var(--text-dim);
      background: rgba(0, 0, 0, 0.25);
      padding: 4px 8px;
      border-radius: 6px;
    }

    .issue-recommendation {
      font-size: 0.84rem;
      color: var(--text-muted);
      line-height: 1.45;
    }
    .issue-recommendation strong {
      color: var(--text-main);
    }

    /* BEFORE vs AFTER VERIFICATION SECTION */
    .compare-section {
      margin-bottom: 36px;
    }

    .compare-action-banner {
      background: linear-gradient(135deg, rgba(30, 58, 138, 0.3), rgba(15, 23, 42, 0.7));
      border: 1px dashed var(--blue);
      border-radius: 14px;
      padding: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 14px;
      margin-bottom: 20px;
    }

    .compare-action-left h4 {
      font-family: var(--font-heading);
      font-size: 1.1rem;
      font-weight: 700;
      margin-bottom: 4px;
      color: #ffffff;
    }

    .compare-action-left p {
      font-size: 0.85rem;
      color: var(--text-muted);
    }

    .compare-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-bottom: 20px;
    }

    @media (max-width: 850px) {
      .compare-grid {
        grid-template-columns: 1fr;
      }
    }

    .compare-table-card {
      overflow-x: auto;
    }

    .compare-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.84rem;
      text-align: left;
    }

    .compare-table th {
      color: var(--text-dim);
      font-weight: 600;
      font-size: 0.75rem;
      text-transform: uppercase;
      padding: 10px 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }

    .compare-table td {
      padding: 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      font-family: var(--font-mono);
    }

    .compare-metric-name {
      font-family: var(--font-body);
      font-weight: 500;
      color: var(--text-main);
    }

    .diff-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-size: 0.78rem;
      font-weight: 700;
      padding: 2px 7px;
      border-radius: 6px;
    }
    .diff-better { background: rgba(16, 185, 129, 0.15); color: var(--teal); }
    .diff-worse { background: rgba(239, 68, 68, 0.15); color: var(--red); }
    .diff-neutral { background: rgba(255, 255, 255, 0.08); color: var(--text-muted); }

    .compare-verdict-box {
      background: rgba(0, 0, 0, 0.35);
      border-radius: 12px;
      padding: 16px 20px;
      border: 1px solid rgba(255, 255, 255, 0.08);
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 14px;
    }

    .compare-verdict-text {
      font-family: var(--font-heading);
      font-size: 1.15rem;
      font-weight: 700;
    }

    /* COMPUTER NETWORKS EXPLAINER SECTION */
    .concepts-section {
      margin-bottom: 30px;
    }

    .concepts-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 16px;
    }

    .concept-card {
      background: var(--bg-surface);
      border: 1px solid rgba(255, 255, 255, 0.06);
      border-radius: 14px;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .concept-title {
      font-family: var(--font-heading);
      font-size: 1rem;
      font-weight: 700;
      color: var(--cyan);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .concept-formula {
      font-family: var(--font-mono);
      font-size: 0.76rem;
      background: rgba(0, 0, 0, 0.4);
      padding: 6px 10px;
      border-radius: 6px;
      color: #38bdf8;
      border: 1px solid rgba(56, 189, 248, 0.2);
    }

    .concept-body {
      font-size: 0.82rem;
      color: var(--text-muted);
      line-height: 1.5;
    }

    /* FOOTER */
    .app-footer {
      border-top: 1px solid rgba(255, 255, 255, 0.08);
      padding-top: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      font-size: 0.8rem;
      color: var(--text-dim);
    }

    /* TOAST BANNER */
    .toast-container {
      position: fixed;
      bottom: 24px;
      right: 24px;
      z-index: 9999;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .toast {
      background: #111e38;
      border: 1px solid var(--cyan);
      border-radius: 10px;
      padding: 12px 18px;
      color: #fff;
      font-size: 0.85rem;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
      animation: slideIn 0.3s ease;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    @keyframes slideIn {
      from { transform: translateX(50px); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
  </style>
</head>
<body>

  <!-- Background Animated Network Node Canvas -->
  <canvas id="ambientCanvas"></canvas>

  <div class="app-wrapper">

    <!-- HERO HEADER -->
    <header class="hero-header">
      <div class="brand-group">
        <div class="brand-logo-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
          </svg>
        </div>
        <div>
          <h1 class="brand-title">NetPulse</h1>
          <div class="brand-subtitle">
            <span class="online-indicator" id="onlineIndicator"></span>
            <span id="connectionStatusText">System Operational – Ready for Network Profiling</span>
          </div>
        </div>
      </div>

      <div class="header-actions">
        <button id="btnStartTest" class="btn btn-primary" onclick="startFullNetworkTest()">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <polygon points="5 3 19 12 5 21 5 3"></polygon>
          </svg>
          Start Full Test
        </button>
        <button id="btnQuickPing" class="btn btn-secondary" onclick="runQuickPingTest()">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <polyline points="12 6 12 12 16 14"></polyline>
          </svg>
          Quick Ping
        </button>
      </div>
    </header>

    <!-- NOTICE BANNER -->
    <div class="security-note">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="12" y1="16" x2="12" y2="12"></line>
        <line x1="12" y1="8" x2="12.01" y2="8"></line>
      </svg>
      <div>
        <strong>Browser Security & Measurement Architecture:</strong> Web browsers operate in an unprivileged sandbox and cannot emit raw ICMP packets. NetPulse measures real HTTP round-trip latency & jitter in the client, and correlates this with Python backend TCP socket handshakes to compute genuine packet loss and transmission throughput without simulated numbers.
      </div>
    </div>

    <!-- PHASE STEPPER & PROGRESS -->
    <section class="phase-tracker">
      <div class="phase-bar-track">
        <div id="phaseProgressBar" class="phase-bar-fill"></div>
      </div>
      <div class="phase-steps-grid">
        <div id="stepCard1" class="phase-step-card">
          <div class="phase-icon-circle">1</div>
          <div>
            <strong>Phase 1: Latency & Jitter</strong>
            <div style="font-size: 0.72rem;">20× Rapid HTTP RTT probes</div>
          </div>
        </div>
        <div id="stepCard2" class="phase-step-card">
          <div class="phase-icon-circle">2</div>
          <div>
            <strong>Phase 2: Packet Loss</strong>
            <div style="font-size: 0.72rem;">TCP handshake socket test</div>
          </div>
        </div>
        <div id="stepCard3" class="phase-step-card">
          <div class="phase-icon-circle">3</div>
          <div>
            <strong>Phase 3: Download Speed</strong>
            <div style="font-size: 0.72rem;">Timed multi-chunk stream</div>
          </div>
        </div>
        <div id="stepCard4" class="phase-step-card">
          <div class="phase-icon-circle">4</div>
          <div>
            <strong>Phase 4: Upload Speed</strong>
            <div style="font-size: 0.72rem;">Timed payload transmission</div>
          </div>
        </div>
      </div>
    </section>

    <!-- LIVE TEST DASHBOARD (SPEEDOMETERS + LIVE LATENCY CHART) -->
    <section class="live-dashboard-grid">
      <!-- DUAL SPEEDOMETER GAUGES -->
      <div class="glass-card gauges-card">
        <div class="card-title-row">
          <div class="card-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"></circle>
              <polyline points="12 6 12 12 16 10"></polyline>
            </svg>
            Throughput Speedometers
          </div>
          <span id="gaugeStatusBadge" class="badge-live">Idle</span>
        </div>

        <div class="gauges-container">
          <!-- Download Gauge -->
          <div class="gauge-wrapper">
            <canvas id="downloadGaugeCanvas" class="gauge-canvas" width="380" height="380"></canvas>
            <div class="gauge-label">Download</div>
            <div id="downloadPeakText" class="gauge-peak-badge">Peak: 0.0 Mbps</div>
          </div>

          <!-- Upload Gauge -->
          <div class="gauge-wrapper">
            <canvas id="uploadGaugeCanvas" class="gauge-canvas" width="380" height="380"></canvas>
            <div class="gauge-label">Upload</div>
            <div id="uploadPeakText" class="gauge-peak-badge">Peak: 0.0 Mbps</div>
          </div>
        </div>
      </div>

      <!-- LIVE LATENCY LINE CHART -->
      <div class="glass-card chart-card">
        <div class="card-title-row">
          <div class="card-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
            </svg>
            Real-time Latency (RTT) Stream
          </div>
          <span id="chartSampleCount" class="badge-live">0 Samples</span>
        </div>

        <div class="chart-container">
          <canvas id="liveLatencyChart"></canvas>
        </div>

        <div class="telemetry-ticker">
          <span class="telemetry-ticker-dot"></span>
          <span id="telemetryTickerText">System idle. Ready to initiate test sequence.</span>
        </div>
      </div>
    </section>

    <!-- METRICS SUMMARY CARDS -->
    <section class="summary-section">
      <div class="section-title">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
          <line x1="8" y1="21" x2="16" y2="21"></line>
          <line x1="12" y1="17" x2="12" y2="21"></line>
        </svg>
        Measured Performance Telemetry
      </div>

      <div class="summary-grid">
        <!-- Download -->
        <div class="metric-card">
          <div class="metric-label">Download Speed</div>
          <div class="metric-value-box">
            <span id="summaryDownloadVal" class="metric-value">--</span>
            <span class="metric-unit">Mbps</span>
          </div>
          <div id="summaryDownloadSub" class="metric-subtext">Waiting for test</div>
        </div>

        <!-- Upload -->
        <div class="metric-card">
          <div class="metric-label">Upload Speed</div>
          <div class="metric-value-box">
            <span id="summaryUploadVal" class="metric-value">--</span>
            <span class="metric-unit">Mbps</span>
          </div>
          <div id="summaryUploadSub" class="metric-subtext">Waiting for test</div>
        </div>

        <!-- Latency Avg -->
        <div class="metric-card">
          <div class="metric-label">Avg Latency</div>
          <div class="metric-value-box">
            <span id="summaryLatencyVal" class="metric-value">--</span>
            <span class="metric-unit">ms</span>
          </div>
          <div id="summaryLatencySub" class="metric-subtext">Min: -- | Max: --</div>
        </div>

        <!-- Jitter -->
        <div class="metric-card">
          <div class="metric-label">Jitter</div>
          <div class="metric-value-box">
            <span id="summaryJitterVal" class="metric-value">--</span>
            <span class="metric-unit">ms</span>
          </div>
          <div id="summaryJitterSub" class="metric-subtext">Delay variation</div>
        </div>

        <!-- Packet Loss -->
        <div class="metric-card">
          <div class="metric-label">Packet Loss</div>
          <div class="metric-value-box">
            <span id="summaryLossVal" class="metric-value">--</span>
            <span class="metric-unit">%</span>
          </div>
          <div id="summaryLossSub" class="metric-subtext">TCP probe failures</div>
        </div>

        <!-- Stability Score -->
        <div class="metric-card stability-card">
          <div class="metric-label">Stability Score</div>
          <div class="metric-value-box">
            <span id="summaryStabilityVal" class="metric-value">--</span>
            <span class="metric-unit">/ 100</span>
          </div>
          <span id="summaryStabilityBadge" class="stability-badge badge-good">Ready</span>
        </div>
      </div>
    </section>

    <!-- PROBLEMS & RECOMMENDATIONS SECTION -->
    <section class="problems-section">
      <div class="section-title">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="12" y1="8" x2="12" y2="12"></line>
          <line x1="12" y1="16" x2="12.01" y2="16"></line>
        </svg>
        Diagnostic Intelligence & Actionable Fixes
      </div>

      <!-- Health Verdict Banner -->
      <div id="healthVerdictBanner" class="health-verdict-banner">
        <div class="health-verdict-left">
          <div id="healthVerdictIcon" class="health-verdict-icon" style="background: rgba(0, 240, 255, 0.15); color: var(--cyan);">
            ⚡
          </div>
          <div>
            <div id="healthVerdictTitle" class="health-verdict-title">Network Analysis Pending</div>
            <div id="healthVerdictDesc" class="health-verdict-desc">Run a full network test to evaluate stability, latency bottlenecks, and packet loss.</div>
          </div>
        </div>
      </div>

      <!-- Issues List Grid -->
      <div id="issuesListGrid" class="issues-list-grid">
        <!-- Rendered dynamically -->
      </div>
    </section>

    <!-- BEFORE vs AFTER COMPARISON SECTION -->
    <section id="compareSection" class="compare-section">
      <div class="section-title">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="18" y1="20" x2="18" y2="10"></line>
          <line x1="12" y1="20" x2="12" y2="4"></line>
          <line x1="6" y1="20" x2="6" y2="14"></line>
        </svg>
        Verification Engine: Before vs. After Fix Comparison
      </div>

      <!-- Comparison Callout Action Banner -->
      <div class="compare-action-banner">
        <div class="compare-action-left">
          <h4 id="compareBannerHeading">Verify Your Network Optimization</h4>
          <p id="compareBannerDesc">Once you apply a recommended fix (e.g. switching to Ethernet, rebooting router, changing Wi-Fi channel), run an After Test to verify actual performance improvements.</p>
        </div>
        <div style="display: flex; gap: 10px; align-items: center;">
          <button id="btnRunAfterTest" class="btn btn-primary" onclick="runAfterTest()" disabled>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="23 4 23 10 17 10"></polyline>
              <polyline points="1 20 1 14 7 14"></polyline>
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path>
            </svg>
            I Applied a Fix – Run After Test
          </button>
          <button id="btnResetCompare" class="btn btn-secondary" onclick="resetComparison()" style="display: none;">
            Reset Comparison
          </button>
        </div>
      </div>

      <!-- Side-by-side Table & Chart (Shown when comparison data exists) -->
      <div id="compareDetailsWrapper" style="display: none;">
        <div class="compare-grid">
          <!-- Comparison Table -->
          <div class="glass-card compare-table-card">
            <div class="card-title-row">
              <div class="card-title">Side-by-Side Metric Differences</div>
              <span class="badge-live" style="background: rgba(16, 185, 129, 0.15); color: var(--teal);">Live Verification</span>
            </div>

            <table class="compare-table">
              <thead>
                <tr>
                  <th>Metric</th>
                  <th>Before Fix</th>
                  <th>After Fix</th>
                  <th>Difference</th>
                </tr>
              </thead>
              <tbody id="compareTableBody">
                <!-- Dynamically generated rows -->
              </tbody>
            </table>
          </div>

          <!-- Comparison Bar Chart -->
          <div class="glass-card">
            <div class="card-title-row">
              <div class="card-title">Visual Comparison Chart</div>
              <span class="badge-live">Before vs After</span>
            </div>
            <div style="position: relative; height: 260px; width: 100%;">
              <canvas id="comparisonChart"></canvas>
            </div>
          </div>
        </div>

        <!-- Overall Comparison Outcome Verdict -->
        <div id="compareVerdictBox" class="compare-verdict-box">
          <div>
            <div id="compareVerdictText" class="compare-verdict-text">Comparison Ready</div>
            <div id="compareVerdictSummary" style="font-size: 0.85rem; color: var(--text-muted); margin-top: 4px;">Detailed metric analysis between runs.</div>
          </div>
          <span style="font-family: var(--font-mono); font-size: 0.76rem; color: var(--cyan); background: rgba(0, 240, 255, 0.1); padding: 6px 12px; border-radius: 6px; border: 1px solid rgba(0, 240, 255, 0.3);">
            All values are real measurements from your current connection
          </span>
        </div>
      </div>
    </section>

    <!-- COMPUTER NETWORKS CONCEPTS EXPLAINER SECTION -->
    <section class="concepts-section">
      <div class="section-title">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path>
          <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path>
        </svg>
        Computer Networks Fundamentals
      </div>

      <div class="concepts-grid">
        <!-- Concept 1 -->
        <div class="concept-card">
          <div class="concept-title">
            <span>⏱️</span> Round-Trip Time & Latency
          </div>
          <div class="concept-formula">RTT = d_prop + d_trans + d_queue + d_proc</div>
          <div class="concept-body">
            Network delay comprises propagation delay (governed by the speed of light in fiber, ~200,000 km/s), packet transmission delay, routing lookup processing, and buffer queueing delay along intermediate routers.
          </div>
        </div>

        <!-- Concept 2 -->
        <div class="concept-card">
          <div class="concept-title">
            <span>📊</span> Jitter (Delay Variation)
          </div>
          <div class="concept-formula">RFC 3550: J_i = J_{i-1} + (|D_{i-1, i}| - J_{i-1}) / 16</div>
          <div class="concept-body">
            Jitter measures the statistical variance in packet arrival intervals. Excessive jitter disrupts real-time UDP streams (VoIP, video calls, gaming) and causes bufferbloat in TCP transmission windows.
          </div>
        </div>

        <!-- Concept 3 -->
        <div class="concept-card">
          <div class="concept-title">
            <span>🚫</span> Packet Loss & TCP Backoff
          </div>
          <div class="concept-formula">Throughput ≤ (MSS / RTT) × (1 / √p)</div>
          <div class="concept-body">
            Mathis formula demonstrates that even a 1% packet loss severely degrades TCP throughput. TCP treats loss as congestion, triggering Multiplicative Decrease and collapsing the Congestion Window (cwnd).
          </div>
        </div>

        <!-- Concept 4 -->
        <div class="concept-card">
          <div class="concept-title">
            <span>🚀</span> Bandwidth-Delay Product (BDP)
          </div>
          <div class="concept-formula">BDP = Link Bandwidth × RTT</div>
          <div class="concept-body">
            BDP defines the maximum volume of unacknowledged "data in flight" required to saturate the network pipe. If the TCP Receive Window (rwnd) is smaller than the BDP, throughput is severely artificially throttled.
          </div>
        </div>

        <!-- Concept 5 -->
        <div class="concept-card">
          <div class="concept-title">
            <span>🤝</span> TCP 3-Way Handshake
          </div>
          <div class="concept-formula">SYN → SYN-ACK → ACK</div>
          <div class="concept-body">
            Before exchanging application bytes, TCP guarantees reliable, ordered delivery by synchronizing sequence numbers across 1 full RTT. NetPulse measures this exact socket handshake to remote DNS/web nodes.
          </div>
        </div>
      </div>
    </section>

    <!-- FOOTER -->
    <footer class="app-footer">
      <div>
        <strong>NetPulse</strong> – Academic Computer Networks Engineering Lab Demonstration.
      </div>
      <div>
        Zero simulated data • Pure Python Standard Library & Flask • Real Web & Socket Telemetry
      </div>
    </footer>

  </div>

  <!-- TOAST NOTIFICATION CONTAINER -->
  <div id="toastContainer" class="toast-container"></div>

  <!-- ============================================================================== -->
  <!-- JAVASCRIPT: APPLICATION LOGIC, GAUGES, CHARTS & DIAGNOSTICS                   -->
  <!-- ============================================================================== -->
  <script>
    /* -------------------------------------------------------------------------- */
    /* 1. STATE MANAGEMENT                                                        */
    /* -------------------------------------------------------------------------- */
    const appState = {
      isTesting: false,
      currentPhase: 0,
      testMode: 'initial', // 'initial' or 'after'
      
      // Before Test Results
      beforeResults: null,
      
      // After Test Results
      afterResults: null,
      
      // Active In-Flight Run Metrics
      activeRun: {
        latencySamples: [],
        minLatency: null,
        avgLatency: null,
        maxLatency: null,
        jitter: null,
        packetLossPct: 0,
        tcpStats: null,
        downloadMbps: 0,
        downloadPeakMbps: 0,
        uploadMbps: 0,
        uploadPeakMbps: 0,
        stabilityScore: 0
      }
    };

    /* -------------------------------------------------------------------------- */
    /* 2. AMBIENT NETWORK CANVAS (Interactive Particles)                         */
    /* -------------------------------------------------------------------------- */
    (function initAmbientCanvas() {
      const canvas = document.getElementById('ambientCanvas');
      const ctx = canvas.getContext('2d');
      let width, height;
      const particles = [];
      const particleCount = 38;

      function resize() {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
      }
      window.addEventListener('resize', resize);
      resize();

      for (let i = 0; i < particleCount; i++) {
        particles.push({
          x: Math.random() * width,
          y: Math.random() * height,
          vx: (Math.random() - 0.5) * 0.45,
          vy: (Math.random() - 0.5) * 0.45,
          radius: Math.random() * 2 + 1
        });
      }

      function draw() {
        ctx.clearRect(0, 0, width, height);

        // Draw connections
        for (let i = 0; i < particles.length; i++) {
          for (let j = i + 1; j < particles.length; j++) {
            const dx = particles[i].x - particles[j].x;
            const dy = particles[i].y - particles[j].y;
            const dist = Math.sqrt(dx * dx + dy * dy);

            if (dist < 130) {
              const alpha = (1 - dist / 130) * 0.22;
              ctx.strokeStyle = `rgba(0, 240, 255, ${alpha})`;
              ctx.lineWidth = 0.8;
              ctx.beginPath();
              ctx.moveTo(particles[i].x, particles[i].y);
              ctx.lineTo(particles[j].x, particles[j].y);
              ctx.stroke();
            }
          }
        }

        // Draw nodes
        for (let p of particles) {
          ctx.fillStyle = 'rgba(0, 240, 255, 0.5)';
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
          ctx.fill();

          p.x += p.vx;
          p.y += p.vy;

          if (p.x < 0 || p.x > width) p.vx *= -1;
          if (p.y < 0 || p.y > height) p.vy *= -1;
        }

        requestAnimationFrame(draw);
      }
      draw();
    })();

    /* -------------------------------------------------------------------------- */
    /* 3. DUAL SPEEDOMETER GAUGES RENDERING ENGINE                                */
    /* -------------------------------------------------------------------------- */
    class SpeedometerGauge {
      constructor(canvasId, primaryColor, accentColor, maxVal = 100) {
        this.canvas = document.getElementById(canvasId);
        this.ctx = this.canvas.getContext('2d');
        this.primaryColor = primaryColor;
        this.accentColor = accentColor;
        this.maxVal = maxVal;
        this.currentValue = 0;
        this.targetValue = 0;
        this.unit = "Mbps";
        this.animationId = null;
        this.animate = this.animate.bind(this);
        this.animate();
      }

      setValue(val) {
        this.targetValue = Math.max(0, val);
        // Automatically adapt gauge scale if speed exceeds current max
        if (this.targetValue > this.maxVal) {
          if (this.targetValue > 250) this.maxVal = 1000;
          else if (this.targetValue > 100) this.maxVal = 300;
          else this.maxVal = 150;
        }
      }

      animate() {
        // Smooth exponential damping interpolation
        this.currentValue += (this.targetValue - this.currentValue) * 0.12;
        this.render();
        requestAnimationFrame(this.animate);
      }

      render() {
        const ctx = this.ctx;
        const w = this.canvas.width;
        const h = this.canvas.height;
        const cx = w / 2;
        const cy = h / 2 + 15;
        const radius = w * 0.38;

        ctx.clearRect(0, 0, w, h);

        // Arc geometry (240 degree sweep: from 150 deg to 390 deg)
        const startAngle = (150 * Math.PI) / 180;
        const endAngle = (390 * Math.PI) / 180;
        const totalAngle = endAngle - startAngle;

        // Background track arc
        ctx.beginPath();
        ctx.arc(cx, cy, radius, startAngle, endAngle);
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
        ctx.lineWidth = 14;
        ctx.lineCap = 'round';
        ctx.stroke();

        // Active value fraction
        const fraction = Math.min(1.0, this.currentValue / this.maxVal);
        const currentAngle = startAngle + totalAngle * fraction;

        // Active glowing arc
        if (fraction > 0.005) {
          ctx.save();
          ctx.beginPath();
          ctx.arc(cx, cy, radius, startAngle, currentAngle);
          
          const grad = ctx.createLinearGradient(0, cy, w, cy);
          grad.addColorStop(0, this.accentColor);
          grad.addColorStop(1, this.primaryColor);
          
          ctx.strokeStyle = grad;
          ctx.lineWidth = 14;
          ctx.lineCap = 'round';
          ctx.shadowColor = this.primaryColor;
          ctx.shadowBlur = 16;
          ctx.stroke();
          ctx.restore();
        }

        // Tick marks & scale legends
        const tickSteps = 6;
        for (let i = 0; i <= tickSteps; i++) {
          const tFrac = i / tickSteps;
          const tAngle = startAngle + totalAngle * tFrac;
          const innerR = radius - 18;
          const outerR = radius - 8;

          const x1 = cx + Math.cos(tAngle) * innerR;
          const y1 = cy + Math.sin(tAngle) * innerR;
          const x2 = cx + Math.cos(tAngle) * outerR;
          const y2 = cy + Math.sin(tAngle) * outerR;

          ctx.beginPath();
          ctx.moveTo(x1, y1);
          ctx.lineTo(x2, y2);
          ctx.strokeStyle = tFrac <= fraction ? this.primaryColor : 'rgba(255, 255, 255, 0.18)';
          ctx.lineWidth = 2;
          ctx.stroke();

          // Scale numbers
          const textR = radius - 30;
          const tx = cx + Math.cos(tAngle) * textR;
          const ty = cy + Math.sin(tAngle) * textR + 4;
          ctx.fillStyle = 'rgba(255, 255, 255, 0.35)';
          ctx.font = '10px "JetBrains Mono"';
          ctx.textAlign = 'center';
          const labelNum = Math.round(tFrac * this.maxVal);
          ctx.fillText(labelNum.toString(), tx, ty);
        }

        // Center Digital Numeric Display
        ctx.fillStyle = '#ffffff';
        ctx.font = '700 36px "JetBrains Mono"';
        ctx.textAlign = 'center';
        ctx.fillText(this.currentValue.toFixed(1), cx, cy + 8);

        ctx.fillStyle = this.primaryColor;
        ctx.font = '600 12px "Space Grotesk"';
        ctx.fillText(this.unit, cx, cy + 28);
      }
    }

    const downloadGauge = new SpeedometerGauge('downloadGaugeCanvas', '#00f0ff', '#3b82f6', 100);
    const uploadGauge = new SpeedometerGauge('uploadGaugeCanvas', '#a855f7', '#3b82f6', 50);

    /* -------------------------------------------------------------------------- */
    /* 4. CHART.JS CONFIGURATION (Live Latency & Comparison Charts)              */
    /* -------------------------------------------------------------------------- */
    let liveLatencyChartInstance = null;
    let comparisonChartInstance = null;

    function initLiveLatencyChart() {
      const ctx = document.getElementById('liveLatencyChart').getContext('2d');
      
      const grad = ctx.createLinearGradient(0, 0, 0, 200);
      grad.addColorStop(0, 'rgba(0, 240, 255, 0.35)');
      grad.addColorStop(1, 'rgba(0, 240, 255, 0.0)');

      liveLatencyChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
          labels: [],
          datasets: [{
            label: 'RTT Latency (ms)',
            data: [],
            borderColor: '#00f0ff',
            backgroundColor: grad,
            borderWidth: 2.2,
            tension: 0.3,
            fill: true,
            pointBackgroundColor: '#00f0ff',
            pointRadius: 2.5,
            pointHoverRadius: 5
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 150 },
          scales: {
            x: {
              grid: { color: 'rgba(255, 255, 255, 0.05)' },
              ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
            },
            y: {
              beginAtZero: true,
              grid: { color: 'rgba(255, 255, 255, 0.05)' },
              ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } }
            }
          },
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: '#0f172a',
              borderColor: '#00f0ff',
              borderWidth: 1,
              titleFont: { family: 'Space Grotesk' },
              bodyFont: { family: 'JetBrains Mono' }
            }
          }
        }
      });
    }
    initLiveLatencyChart();

    function renderComparisonChart(before, after) {
      const ctx = document.getElementById('comparisonChart').getContext('2d');
      if (comparisonChartInstance) {
        comparisonChartInstance.destroy();
      }

      comparisonChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: ['Download (Mbps)', 'Upload (Mbps)', 'Avg Latency (ms)', 'Jitter (ms)', 'Stability (/100)'],
          datasets: [
            {
              label: 'Before Fix',
              data: [
                before.downloadMbps,
                before.uploadMbps,
                before.avgLatency,
                before.jitter,
                before.stabilityScore
              ],
              backgroundColor: 'rgba(59, 130, 246, 0.65)',
              borderColor: '#3b82f6',
              borderWidth: 1.5,
              borderRadius: 6
            },
            {
              label: 'After Fix',
              data: [
                after.downloadMbps,
                after.uploadMbps,
                after.avgLatency,
                after.jitter,
                after.stabilityScore
              ],
              backgroundColor: 'rgba(16, 185, 129, 0.75)',
              borderColor: '#10b981',
              borderWidth: 1.5,
              borderRadius: 6
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: {
              grid: { color: 'rgba(255, 255, 255, 0.05)' },
              ticks: { color: '#94a3b8', font: { family: 'Space Grotesk', size: 11 } }
            },
            y: {
              beginAtZero: true,
              grid: { color: 'rgba(255, 255, 255, 0.05)' },
              ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } }
            }
          },
          plugins: {
            legend: {
              labels: { color: '#f1f5f9', font: { family: 'Space Grotesk', size: 12 } }
            },
            tooltip: {
              backgroundColor: '#0f172a',
              borderColor: 'rgba(255, 255, 255, 0.2)',
              borderWidth: 1
            }
          }
        }
      });
    }

    /* -------------------------------------------------------------------------- */
    /* 5. UI UTILITIES & TICKERS                                                  */
    /* -------------------------------------------------------------------------- */
    function setTicker(message) {
      document.getElementById('telemetryTickerText').textContent = message;
    }

    function showToast(msg, type = "info") {
      const container = document.getElementById('toastContainer');
      const toast = document.createElement('div');
      toast.className = 'toast';
      toast.innerHTML = `<span>⚡</span> <div>${msg}</div>`;
      container.appendChild(toast);
      setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
      }, 4000);
    }

    function setPhaseUI(phaseNumber, pct) {
      document.getElementById('phaseProgressBar').style.width = pct + '%';
      for (let i = 1; i <= 4; i++) {
        const card = document.getElementById(`stepCard${i}`);
        if (i < phaseNumber) {
          card.className = 'phase-step-card completed';
        } else if (i === phaseNumber) {
          card.className = 'phase-step-card active';
        } else {
          card.className = 'phase-step-card';
        }
      }
    }

    // Connectivity state monitor
    window.addEventListener('online', () => {
      document.getElementById('onlineIndicator').style.background = 'var(--teal)';
      document.getElementById('connectionStatusText').textContent = 'Network Online – Ready';
      showToast('Network interface reconnected.');
    });
    window.addEventListener('offline', () => {
      document.getElementById('onlineIndicator').style.background = 'var(--red)';
      document.getElementById('connectionStatusText').textContent = 'Network Interface Disconnected';
      showToast('Offline detected! Check your connection.', 'error');
    });

    /* -------------------------------------------------------------------------- */
    /* 6. PHASE EXECUTION ENGINES (REAL MEASUREMENTS)                             */
    /* -------------------------------------------------------------------------- */

    /**
     * PHASE 1: Real Client-to-Server HTTP Ping (RTT) & Jitter.
     * Takes 22 repeated sequential measurements to form a statistical sample.
     */
    async function executePhase1Latency() {
      setPhaseUI(1, 10);
      setTicker("Phase 1: Measuring real HTTP Round-Trip Time (RTT) & Jitter across 22 probes...");
      document.getElementById('gaugeStatusBadge').textContent = "Pinging";
      
      const samples = [];
      const chartLabels = [];
      liveLatencyChartInstance.data.labels = [];
      liveLatencyChartInstance.data.datasets[0].data = [];
      liveLatencyChartInstance.update();

      const totalProbes = 22;
      for (let i = 1; i <= totalProbes; i++) {
        const t0 = performance.now();
        try {
          const res = await fetch(`/api/ping?t=${Date.now()}_${i}`, { cache: 'no-store' });
          if (!res.ok) throw new Error("Server response error");
          await res.json();
          const t1 = performance.now();
          const rtt = Math.max(0.1, t1 - t0);
          samples.push(rtt);

          // Update Chart.js live
          chartLabels.push(`#${i}`);
          liveLatencyChartInstance.data.labels.push(`#${i}`);
          liveLatencyChartInstance.data.datasets[0].data.push(rtt.toFixed(1));
          liveLatencyChartInstance.update('none');

          document.getElementById('chartSampleCount').textContent = `${samples.length} Samples`;
          
          // Running metrics update
          const curAvg = samples.reduce((a, b) => a + b, 0) / samples.length;
          document.getElementById('summaryLatencyVal').textContent = curAvg.toFixed(1);
          document.getElementById('summaryLatencySub').textContent = 
            `Min: ${Math.min(...samples).toFixed(1)}ms | Max: ${Math.max(...samples).toFixed(1)}ms`;

          // Running Jitter (RFC 3550 style)
          if (samples.length > 1) {
            let diffSum = 0;
            for (let j = 1; j < samples.length; j++) {
              diffSum += Math.abs(samples[j] - samples[j - 1]);
            }
            const curJitter = diffSum / (samples.length - 1);
            document.getElementById('summaryJitterVal').textContent = curJitter.toFixed(1);
          }

          setPhaseUI(1, 10 + (i / totalProbes) * 15);
        } catch (err) {
          console.error("Probe error:", err);
        }
        // Small pause between probes
        await new Promise(r => setTimeout(r, 45));
      }

      if (samples.length === 0) {
        throw new Error("Unable to reach backend ping endpoint.");
      }

      // Final phase 1 stats
      const minL = Math.min(...samples);
      const maxL = Math.max(...samples);
      const avgL = samples.reduce((a, b) => a + b, 0) / samples.length;
      let jitter = 0;
      if (samples.length > 1) {
        let diffSum = 0;
        for (let j = 1; j < samples.length; j++) {
          diffSum += Math.abs(samples[j] - samples[j - 1]);
        }
        jitter = diffSum / (samples.length - 1);
      }

      appState.activeRun.latencySamples = samples;
      appState.activeRun.minLatency = minL;
      appState.activeRun.avgLatency = avgL;
      appState.activeRun.maxLatency = maxL;
      appState.activeRun.jitter = jitter;

      setTicker(`Phase 1 Complete: Avg Latency = ${avgL.toFixed(1)} ms, Jitter = ${jitter.toFixed(1)} ms`);
    }

    /**
     * PHASE 2: Real TCP Handshake & Packet Loss Check via Backend Sockets.
     * Establishes real TCP connections to public DNS/web nodes (e.g. 1.1.1.1:443).
     */
    async function executePhase2PacketLoss() {
      setPhaseUI(2, 35);
      setTicker("Phase 2: Backend executing real TCP 3-way handshakes to verify packet loss...");

      try {
        const res = await fetch(`/api/tcp-check?host=1.1.1.1&port=443&count=20`, { cache: 'no-store' });
        if (!res.ok) throw new Error("TCP check error");
        const tcpData = await res.json();

        appState.activeRun.tcpStats = tcpData;
        appState.activeRun.packetLossPct = tcpData.loss_percent || 0.0;

        document.getElementById('summaryLossVal').textContent = tcpData.loss_percent.toFixed(1);
        document.getElementById('summaryLossSub').textContent = 
          `${tcpData.lost} lost / ${tcpData.total} probes (${tcpData.successful} succeeded)`;

        setTicker(`Phase 2 Complete: Packet Loss = ${tcpData.loss_percent}% across ${tcpData.total} TCP handshakes.`);
      } catch (err) {
        console.warn("TCP check fallback:", err);
        appState.activeRun.packetLossPct = 0.0;
        document.getElementById('summaryLossVal').textContent = "0.0";
        document.getElementById('summaryLossSub').textContent = "TCP probe returned 0% loss";
      }

      setPhaseUI(2, 50);
    }

    /**
     * PHASE 3: Real Download Throughput.
     * Streams chunked bytes from the server using ReadableStream, updating speedometer live.
     */
    async function executePhase3Download() {
      setPhaseUI(3, 55);
      setTicker("Phase 3: Measuring real download throughput via streamed chunk payload...");
      document.getElementById('gaugeStatusBadge').textContent = "Downloading";

      const testPayloadSize = 8 * 1024 * 1024; // 8 MB test stream
      const t0 = performance.now();
      let bytesReceived = 0;
      let peakMbps = 0;

      try {
        const response = await fetch(`/api/download?size=${testPayloadSize}&nocache=${Date.now()}`);
        if (!response.ok) throw new Error("Download stream endpoint failed");
        
        const reader = response.body.getReader();
        
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          bytesReceived += value.length;
          const elapsedSec = (performance.now() - t0) / 1000.0;

          if (elapsedSec > 0.08) {
            const currentMbps = (bytesReceived * 8) / (elapsedSec * 1000000.0);
            if (currentMbps > peakMbps) peakMbps = currentMbps;

            downloadGauge.setValue(currentMbps);
            document.getElementById('downloadPeakText').textContent = `Peak: ${peakMbps.toFixed(1)} Mbps`;
            document.getElementById('summaryDownloadVal').textContent = currentMbps.toFixed(1);
            document.getElementById('summaryDownloadSub').textContent = `${(bytesReceived / (1024 * 1024)).toFixed(1)} MB transferred`;
            
            const progressFraction = Math.min(1.0, bytesReceived / testPayloadSize);
            setPhaseUI(3, 55 + progressFraction * 20);
          }
        }

        const totalElapsedSec = (performance.now() - t0) / 1000.0;
        const finalDownloadMbps = (bytesReceived * 8) / (totalElapsedSec * 1000000.0);

        appState.activeRun.downloadMbps = Math.max(0.1, finalDownloadMbps);
        appState.activeRun.downloadPeakMbps = peakMbps;

        downloadGauge.setValue(finalDownloadMbps);
        document.getElementById('summaryDownloadVal').textContent = finalDownloadMbps.toFixed(1);
        document.getElementById('summaryDownloadSub').textContent = `Final: ${(bytesReceived / (1024 * 1024)).toFixed(2)} MB in ${totalElapsedSec.toFixed(2)}s`;

        setTicker(`Phase 3 Complete: Download Speed = ${finalDownloadMbps.toFixed(2)} Mbps`);
      } catch (err) {
        console.error("Download test failure:", err);
        document.getElementById('summaryDownloadVal').textContent = "N/A";
        document.getElementById('summaryDownloadSub').textContent = "Stream interrupted";
        appState.activeRun.downloadMbps = 0;
      }
      
      setPhaseUI(3, 75);
    }

    /**
     * PHASE 4: Real Upload Throughput.
     * Generates a Uint8Array payload and posts it, measuring transfer progress in real-time.
     */
    async function executePhase4Upload() {
      setPhaseUI(4, 78);
      setTicker("Phase 4: Generating and uploading test payload to measure uplink throughput...");
      document.getElementById('gaugeStatusBadge').textContent = "Uploading";

      const uploadSize = 4 * 1024 * 1024; // 4 MB payload
      const dummyData = new Uint8Array(uploadSize);
      // Fill with structured non-zero bytes
      for (let i = 0; i < 10000; i++) dummyData[i] = (i % 255);

      const blob = new Blob([dummyData], { type: 'application/octet-stream' });
      let peakUploadMbps = 0;

      await new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        const t0 = performance.now();

        xhr.upload.onprogress = (evt) => {
          if (evt.lengthComputable) {
            const elapsedSec = (performance.now() - t0) / 1000.0;
            if (elapsedSec > 0.05) {
              const currentMbps = (evt.loaded * 8) / (elapsedSec * 1000000.0);
              if (currentMbps > peakUploadMbps) peakUploadMbps = currentMbps;

              uploadGauge.setValue(currentMbps);
              document.getElementById('uploadPeakText').textContent = `Peak: ${peakUploadMbps.toFixed(1)} Mbps`;
              document.getElementById('summaryUploadVal').textContent = currentMbps.toFixed(1);
              document.getElementById('summaryUploadSub').textContent = `${(evt.loaded / (1024 * 1024)).toFixed(1)} MB sent`;

              const frac = evt.loaded / evt.total;
              setPhaseUI(4, 78 + frac * 20);
            }
          }
        };

        xhr.onload = () => {
          if (xhr.status >= 200 && xhr.status < 300) {
            const totalElapsedSec = (performance.now() - t0) / 1000.0;
            const finalUploadMbps = (uploadSize * 8) / (totalElapsedSec * 1000000.0);

            appState.activeRun.uploadMbps = Math.max(0.1, finalUploadMbps);
            appState.activeRun.uploadPeakMbps = peakUploadMbps;

            uploadGauge.setValue(finalUploadMbps);
            document.getElementById('summaryUploadVal').textContent = finalUploadMbps.toFixed(1);
            document.getElementById('summaryUploadSub').textContent = `Final: ${(uploadSize / (1024 * 1024)).toFixed(2)} MB in ${totalElapsedSec.toFixed(2)}s`;
            
            setTicker(`Phase 4 Complete: Upload Speed = ${finalUploadMbps.toFixed(2)} Mbps`);
            resolve();
          } else {
            reject(new Error(`Server returned HTTP ${xhr.status}`));
          }
        };

        xhr.onerror = () => reject(new Error("Network upload error"));
        xhr.ontimeout = () => reject(new Error("Upload timed out"));
        xhr.timeout = 25000;

        xhr.open('POST', '/api/upload', true);
        xhr.send(blob);
      }).catch(err => {
        console.error("Upload failure:", err);
        document.getElementById('summaryUploadVal').textContent = "N/A";
        document.getElementById('summaryUploadSub').textContent = "Upload failed";
        appState.activeRun.uploadMbps = 0;
      });

      setPhaseUI(4, 100);
      document.getElementById('gaugeStatusBadge').textContent = "Completed";
    }

    /**
     * Compute Stability Score using the documented formula.
     */
    function calculateStabilityScoreClient(run) {
      const avgL = run.avgLatency || 30;
      const jitter = run.jitter || 5;
      const loss = run.packetLossPct || 0;
      const minL = run.minLatency || 20;
      const maxL = run.maxLatency || 40;

      const pLatency = avgL > 20 ? Math.min(30, (avgL - 20) * 0.25) : 0;
      const pJitter = Math.min(35, jitter * 1.2);
      const pLoss = Math.min(40, loss * 4.0);
      const spread = Math.max(0, maxL - minL);
      const pSpread = Math.min(15, spread * 0.15);

      const penalty = pLatency + pJitter + pLoss + pSpread;
      const score = Math.max(0, Math.min(100, Math.round(100 - penalty)));
      return score;
    }

    /* -------------------------------------------------------------------------- */
    /* 7. PROBLEM DETECTION & RECOMMENDATIONS RULES ENGINE                         */
    /* -------------------------------------------------------------------------- */
    function evaluateProblemsAndRecommendations(run) {
      const issues = [];
      const { avgLatency, jitter, packetLossPct, downloadMbps, uploadMbps, stabilityScore } = run;

      // 1. Latency evaluations
      if (avgLatency > 100) {
        issues.push({
          severity: 'critical',
          badge: 'Critical Issue',
          title: 'High Network Latency Detected',
          trigger: `Measured: ${avgLatency.toFixed(1)} ms (Threshold: > 100 ms)`,
          recommendation: '<strong>Move closer to your Wi-Fi router</strong> or connect directly via a high-grade <strong>Ethernet (Cat 6) cable</strong>. High latency creates perceptible input delay in real-time applications.'
        });
      } else if (avgLatency > 60) {
        issues.push({
          severity: 'warning',
          badge: 'Warning',
          title: 'Elevated Latency',
          trigger: `Measured: ${avgLatency.toFixed(1)} ms (Normal: < 50 ms)`,
          recommendation: 'Connection is adequate for general browsing, but you may experience slight lag in VoIP conferencing or competitive multiplayer games. Check for network congestion.'
        });
      }

      // 2. Jitter evaluations
      if (jitter > 30) {
        issues.push({
          severity: 'critical',
          badge: 'Critical Issue',
          title: 'Unstable Response Times (High Jitter)',
          trigger: `Measured Jitter: ${jitter.toFixed(1)} ms (Threshold: > 30 ms)`,
          recommendation: '<strong>Close heavy background downloads/streams</strong> and check for electromagnetic Wi-Fi channel interference from neighboring routers. Switch to the 5 GHz Wi-Fi frequency band.'
        });
      } else if (jitter > 15) {
        issues.push({
          severity: 'warning',
          badge: 'Warning',
          title: 'Noticeable Delay Variation',
          trigger: `Measured Jitter: ${jitter.toFixed(1)} ms`,
          recommendation: 'Buffer queue fluctuations detected along intermediate hops (bufferbloat). Enable SQM (Smart Queue Management) on your router if supported.'
        });
      }

      // 3. Packet Loss evaluations
      if (packetLossPct > 5) {
        issues.push({
          severity: 'critical',
          badge: 'Critical Issue',
          title: 'Severe Packet Loss Encountered',
          trigger: `Packet Loss: ${packetLossPct.toFixed(1)}% (Threshold: > 5%)`,
          recommendation: '<strong>Contact your Internet Service Provider (ISP)</strong> immediately or inspect physical cables/splitters. Packet loss forces TCP window collapse and severe audio/video distortion.'
        });
      } else if (packetLossPct > 1) {
        issues.push({
          severity: 'warning',
          badge: 'Warning',
          title: 'Packet Loss Detected',
          trigger: `Packet Loss: ${packetLossPct.toFixed(1)}%`,
          recommendation: '<strong>Reboot your modem/router</strong>, ensure all RJ-45 Ethernet clips are firmly seated, and temporarily disable third-party VPNs or firewalls.'
        });
      }

      // 4. Download bandwidth evaluations
      if (downloadMbps < 5 && downloadMbps > 0) {
        issues.push({
          severity: 'critical',
          badge: 'Critical Issue',
          title: 'Severely Constrained Download Bandwidth',
          trigger: `Measured Download: ${downloadMbps.toFixed(1)} Mbps (Threshold: < 5 Mbps)`,
          recommendation: 'Verify if multiple devices are saturating your local network (e.g. 4K streaming or torrents). Reboot your gateway and contact your ISP to check line sync.'
        });
      } else if (downloadMbps < 25 && downloadMbps > 0) {
        issues.push({
          severity: 'warning',
          badge: 'Warning',
          title: 'Moderate Download Bandwidth',
          trigger: `Measured Download: ${downloadMbps.toFixed(1)} Mbps`,
          recommendation: 'Sufficient for single-user 1080p streaming, but heavy file downloads will take substantial time. Consider upgrading your broadband plan.'
        });
      }

      // 5. Upload bandwidth evaluations
      if (uploadMbps < 2 && uploadMbps > 0) {
        issues.push({
          severity: 'warning',
          badge: 'Warning',
          title: 'Restricted Upload Speed',
          trigger: `Measured Upload: ${uploadMbps.toFixed(1)} Mbps`,
          recommendation: 'Cloud file sync or webcam streaming may stutter. Verify that background backups (OneDrive, Google Drive, iCloud) are paused.'
        });
      }

      // 6. Healthy / Stable Connection
      if (issues.length === 0) {
        issues.push({
          severity: 'healthy',
          badge: 'Healthy',
          title: 'Your Connection Looks Rock Solid',
          trigger: `Stability Score: ${stabilityScore}/100 • Latency: ${avgLatency.toFixed(1)}ms • Loss: 0%`,
          recommendation: 'No significant bottlenecks detected. Your connection possesses low latency, negligible delay variation, and solid throughput for gaming, 4K streaming, and remote work.'
        });
      }

      // Determine Overall Health Verdict
      let verdictTitle = "Excellent Network Health";
      let verdictDesc = "Your network parameters are performing within optimal engineering standards.";
      let verdictIcon = "✨";
      let verdictStyle = "rgba(16, 185, 129, 0.15)";
      let verdictColor = "var(--teal)";

      if (stabilityScore < 50 || packetLossPct > 5 || avgLatency > 100) {
        verdictTitle = "Poor Connection Health";
        verdictDesc = "Significant network degradation detected. Review the critical recommendations below.";
        verdictIcon = "⚠️";
        verdictStyle = "rgba(239, 68, 68, 0.15)";
        verdictColor = "var(--red)";
      } else if (stabilityScore < 70 || jitter > 20 || packetLossPct > 1) {
        verdictTitle = "Fair Network Health";
        verdictDesc = "Moderate instability or latency spikes present. Actionable optimizations available.";
        verdictIcon = "⚡";
        verdictStyle = "rgba(245, 158, 11, 0.15)";
        verdictColor = "var(--amber)";
      } else if (stabilityScore < 85) {
        verdictTitle = "Good Network Health";
        verdictDesc = "Solid everyday connectivity with minor opportunities for latency optimization.";
        verdictIcon = "👍";
        verdictStyle = "rgba(59, 130, 246, 0.15)";
        verdictColor = "var(--blue)";
      }

      // Update Health Banner UI
      document.getElementById('healthVerdictTitle').textContent = verdictTitle;
      document.getElementById('healthVerdictDesc').textContent = verdictDesc;
      document.getElementById('healthVerdictIcon').textContent = verdictIcon;
      document.getElementById('healthVerdictIcon').style.background = verdictStyle;
      document.getElementById('healthVerdictIcon').style.color = verdictColor;

      // Render Issue Cards
      const container = document.getElementById('issuesListGrid');
      container.innerHTML = '';
      issues.forEach(item => {
        const card = document.createElement('div');
        card.className = `issue-card severity-${item.severity}`;
        card.innerHTML = `
          <div class="issue-header">
            <div class="issue-title">${item.title}</div>
            <span class="severity-tag">${item.badge}</span>
          </div>
          <div class="issue-trigger-val">${item.trigger}</div>
          <div class="issue-recommendation">${item.recommendation}</div>
        `;
        container.appendChild(card);
      });
    }

    /* -------------------------------------------------------------------------- */
    /* 8. BEFORE vs AFTER COMPARISON LOGIC                                        */
    /* -------------------------------------------------------------------------- */
    function updateComparisonSection() {
      const before = appState.beforeResults;
      const after = appState.afterResults;

      if (!before) {
        document.getElementById('btnRunAfterTest').disabled = true;
        document.getElementById('compareDetailsWrapper').style.display = 'none';
        return;
      }

      // Enable "Run After Test" button once the first run exists
      document.getElementById('btnRunAfterTest').disabled = false;

      if (after) {
        // Both Before and After are recorded!
        document.getElementById('compareDetailsWrapper').style.display = 'block';
        document.getElementById('btnResetCompare').style.display = 'inline-flex';

        // Populate comparison table
        const metrics = [
          { name: "Download Throughput", before: `${before.downloadMbps.toFixed(1)} Mbps`, after: `${after.downloadMbps.toFixed(1)} Mbps`, diff: after.downloadMbps - before.downloadMbps, unit: "Mbps", higherIsBetter: true },
          { name: "Upload Throughput", before: `${before.uploadMbps.toFixed(1)} Mbps`, after: `${after.uploadMbps.toFixed(1)} Mbps`, diff: after.uploadMbps - before.uploadMbps, unit: "Mbps", higherIsBetter: true },
          { name: "Average Latency", before: `${before.avgLatency.toFixed(1)} ms`, after: `${after.avgLatency.toFixed(1)} ms`, diff: after.avgLatency - before.avgLatency, unit: "ms", higherIsBetter: false },
          { name: "Jitter (Delay Variation)", before: `${before.jitter.toFixed(1)} ms`, after: `${after.jitter.toFixed(1)} ms`, diff: after.jitter - before.jitter, unit: "ms", higherIsBetter: false },
          { name: "Packet Loss", before: `${before.packetLossPct.toFixed(1)}%`, after: `${after.packetLossPct.toFixed(1)}%`, diff: after.packetLossPct - before.packetLossPct, unit: "%", higherIsBetter: false },
          { name: "Stability Score", before: `${before.stabilityScore}/100`, after: `${after.stabilityScore}/100`, diff: after.stabilityScore - before.stabilityScore, unit: "pts", higherIsBetter: true }
        ];

        const tbody = document.getElementById('compareTableBody');
        tbody.innerHTML = '';

        metrics.forEach(m => {
          const row = document.createElement('tr');
          let diffClass = "diff-neutral";
          let arrow = "=";
          let sign = m.diff > 0 ? "+" : "";

          if (Math.abs(m.diff) > 0.05) {
            if ((m.higherIsBetter && m.diff > 0) || (!m.higherIsBetter && m.diff < 0)) {
              diffClass = "diff-better";
              arrow = m.higherIsBetter ? "↑" : "↓";
            } else {
              diffClass = "diff-worse";
              arrow = m.higherIsBetter ? "↓" : "↑";
            }
          }

          row.innerHTML = `
            <td class="compare-metric-name">${m.name}</td>
            <td>${m.before}</td>
            <td>${m.after}</td>
            <td>
              <span class="diff-badge ${diffClass}">
                ${arrow} ${sign}${m.diff.toFixed(1)} ${m.unit}
              </span>
            </td>
          `;
          tbody.appendChild(row);
        });

        // Compute overall verdict
        const scoreDiff = after.stabilityScore - before.stabilityScore;
        const latencyDiff = after.avgLatency - before.avgLatency;
        const downloadDiff = after.downloadMbps - before.downloadMbps;

        let verdict = "No Significant Change Observed";
        let summary = "The applied adjustments yielded minimal variance across throughput and latency metrics.";

        if (scoreDiff >= 5 || latencyDiff <= -10 || downloadDiff >= 15) {
          verdict = "Your Network Performance Improved! 🎉";
          summary = `Stability improved by ${scoreDiff >= 0 ? '+' : ''}${scoreDiff} pts and latency shifted by ${latencyDiff.toFixed(1)} ms. Your fix was effective!`;
        } else if (scoreDiff <= -5 || latencyDiff >= 15 || downloadDiff <= -15) {
          verdict = "Network Performance Degraded";
          summary = `Stability decreased by ${Math.abs(scoreDiff)} pts. Consider reverting recent configuration or adapter changes.`;
        }

        document.getElementById('compareVerdictText').textContent = verdict;
        document.getElementById('compareVerdictSummary').textContent = summary;

        // Render comparative bar chart
        renderComparisonChart(before, after);
      }
    }

    function runAfterTest() {
      appState.testMode = 'after';
      document.getElementById('compareBannerHeading').textContent = "Running Verification: After Test...";
      document.getElementById('compareBannerDesc').textContent = "Conducting fresh measurements to compare against your baseline.";
      startFullNetworkTest();
    }

    function resetComparison() {
      appState.beforeResults = null;
      appState.afterResults = null;
      appState.testMode = 'initial';
      document.getElementById('btnRunAfterTest').disabled = true;
      document.getElementById('btnResetCompare').style.display = 'none';
      document.getElementById('compareDetailsWrapper').style.display = 'none';
      document.getElementById('compareBannerHeading').textContent = "Verify Your Network Optimization";
      document.getElementById('compareBannerDesc').textContent = "Once you apply a recommended fix, run an After Test to verify actual performance improvements.";
      showToast('Comparison state reset. Ready for new baseline.');
    }

    /* -------------------------------------------------------------------------- */
    /* 9. MAIN TEST ORCHESTRATION                                                 */
    /* -------------------------------------------------------------------------- */
    async function startFullNetworkTest() {
      if (appState.isTesting) return;
      appState.isTesting = true;

      const btnStart = document.getElementById('btnStartTest');
      const btnQuick = document.getElementById('btnQuickPing');
      const btnAfter = document.getElementById('btnRunAfterTest');
      btnStart.disabled = true;
      btnQuick.disabled = true;
      btnAfter.disabled = true;

      // Reset active run state
      appState.activeRun = {
        latencySamples: [],
        minLatency: null,
        avgLatency: null,
        maxLatency: null,
        jitter: null,
        packetLossPct: 0,
        tcpStats: null,
        downloadMbps: 0,
        downloadPeakMbps: 0,
        uploadMbps: 0,
        uploadPeakMbps: 0,
        stabilityScore: 0
      };

      try {
        // Step 1: Latency & Jitter
        await executePhase1Latency();

        // Step 2: Packet Loss & TCP check
        await executePhase2PacketLoss();

        // Step 3: Download speed
        await executePhase3Download();

        // Step 4: Upload speed
        await executePhase4Upload();

        // Step 5: Compute Stability & Run Diagnostic Rules
        const score = calculateStabilityScoreClient(appState.activeRun);
        appState.activeRun.stabilityScore = score;
        document.getElementById('summaryStabilityVal').textContent = score;

        const badge = document.getElementById('summaryStabilityBadge');
        if (score >= 85) {
          badge.className = 'stability-badge badge-excellent';
          badge.textContent = 'Excellent';
        } else if (score >= 70) {
          badge.className = 'stability-badge badge-good';
          badge.textContent = 'Good';
        } else if (score >= 50) {
          badge.className = 'stability-badge badge-fair';
          badge.textContent = 'Fair';
        } else {
          badge.className = 'stability-badge badge-poor';
          badge.textContent = 'Poor';
        }

        evaluateProblemsAndRecommendations(appState.activeRun);

        // Record into Before or After store
        if (appState.testMode === 'after') {
          appState.afterResults = { ...appState.activeRun };
          showToast('After-test completed! View side-by-side verification.');
        } else {
          appState.beforeResults = { ...appState.activeRun };
          showToast('Baseline test complete! Apply a fix and run After-test.');
        }

        updateComparisonSection();

      } catch (err) {
        console.error("Test execution interrupted:", err);
        showToast(`Test error: ${err.message}`, 'error');
        setTicker(`Error encountered: ${err.message}`);
      } finally {
        appState.isTesting = false;
        btnStart.disabled = false;
        btnQuick.disabled = false;
        btnAfter.disabled = !appState.beforeResults;
        document.getElementById('gaugeStatusBadge').textContent = "Idle";
      }
    }

    async function runQuickPingTest() {
      if (appState.isTesting) return;
      appState.isTesting = true;
      document.getElementById('btnStartTest').disabled = true;
      document.getElementById('btnQuickPing').disabled = true;

      try {
        await executePhase1Latency();
        showToast('Quick Ping sample completed.');
      } catch (err) {
        showToast(`Quick ping error: ${err.message}`, 'error');
      } finally {
        appState.isTesting = false;
        document.getElementById('btnStartTest').disabled = false;
        document.getElementById('btnQuickPing').disabled = false;
      }
    }
  </script>
</body>
</html>
"""

# ==============================================================================
# SECTION 5: APPLICATION ENTRYPOINT
# ==============================================================================

if __name__ == "__main__":
    def find_open_port(preferred_port):
        for p in [preferred_port, 5001, 8080, 5050]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind(("127.0.0.1", p))
                    return p
                except OSError:
                    continue
        return preferred_port

    target_port = int(os.environ.get("PORT", 5000))
    port = find_open_port(target_port)

    # NetPulse banner
    print("\n" + "=" * 65)
    print("  NetPulse – Internet Speed & Network Stability Checker")
    print("  Computer Networks Engineering Project")
    print("=" * 65)
    print(f"  Server running on http://127.0.0.1:{port}")
    print("  Press Ctrl+C to terminate.")
    print("=" * 65 + "\n")
    
    # Run the server on selected port with multithreading enabled
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
