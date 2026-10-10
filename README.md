<<<<<<< HEAD
# NetPulse – Internet Speed & Network Stability Checker

A complete, single-file full-stack computer networks diagnostic tool built for Computer Networks engineering coursework.

---

## 🚀 How to Run

### 1. Install Dependencies
NetPulse requires **only Flask** (all other utilities use Python's built-in standard library):
```bash
pip install flask
```

### 2. Start the Server
Run the single file:
```bash
python app.py
```

### 3. Open in Browser
Navigate to:
```
http://127.0.0.1:5000
```

---

## 📡 Networking Concepts Demonstrated (For Project Report)

1. **Round-Trip Time (RTT) & Latency Decomposition**:
   - $RTT = t_{\text{propagation}} + t_{\text{transmission}} + t_{\text{queueing}} + t_{\text{processing}}$
   - Measured through repeated sequential HTTP requests with microsecond timestamps (`performance.now()` & `time.perf_counter()`).

2. **Delay Variation (Jitter - RFC 3550)**:
   - Evaluates the mean absolute deviation of consecutive RTT samples:
     $$\text{Jitter} = \frac{1}{N-1} \sum_{i=1}^{N-1} |RTT_{i+1} - RTT_i|$$
   - Demonstrates bufferbloat and Wi-Fi CSMA/CA channel contention.

3. **Layer-4 TCP 3-Way Handshake Timing & Packet Loss**:
   - Web browsers cannot emit raw ICMP echo requests due to sandbox limitations. NetPulse leverages the Python backend (`socket.create_connection`) to execute true TCP handshakes (SYN $\rightarrow$ SYN-ACK $\rightarrow$ ACK) to public internet nodes (e.g. Cloudflare `1.1.1.1:443`, Google `8.8.8.8:53`).
   - Quantifies packet loss from connection timeouts and dropped packets.

4. **Network Throughput vs. Bandwidth**:
   - Measures actual sustained bitrates for Download and Upload:
     $$\text{Throughput (Mbps)} = \frac{\text{Bytes transferred} \times 8}{\text{Elapsed seconds} \times 1,000,000}$$
   - Demonstrates TCP Slow Start and window sizing dynamics during live chunked streaming.

5. **Stability Scoring Model**:
   - Combines latency baseline penalties, jitter weightings, packet loss drop-offs, and maximum spread into a composite 0–100 reliability index.

6. **Empirical A/B Verification (Before vs. After)**:
   - Stores baseline measurements and compares them against post-fix results with side-by-side metric diffs, color-coded indicators, and Chart.js bar graphs.
=======
# internet-speed-ai
it is used for testing the seep of internet and compare them.
>>>>>>> 8f8634be55c444f463175b7d0a282e1cb4c0f8cf
