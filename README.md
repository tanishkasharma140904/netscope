# 🛡️ NetScope AI — Real-Time Network Threat Intelligence Platform

<div align="center">

### 🚀 Advanced Cybersecurity Monitoring & Threat Detection Dashboard

Live Packet Capture • Threat Intelligence • Session Analytics • Geo Intelligence • Executive Security Dashboard

---

🌐 Live Frontend (Netlify)  
https://netscope.netlify.app/

🎥 Project Demonstration Video  
https://drive.google.com/file/d/1u2OObHZdwFR1x7Av7jBglGHCWZK0mTWx/view?usp=sharing

💻 GitHub Repository  
https://github.com/tanishkasharma140904/netscope

</div>

---

# 📖 About The Project

NetScope AI is a real-time cybersecurity monitoring platform that captures live network traffic, analyzes sessions, detects suspicious activity, classifies threats, and visualizes security insights through an interactive dashboard.

The system combines:

✅ Live Packet Capture

✅ Threat Intelligence Engine

✅ Session Tracking

✅ Port Analysis

✅ Geo Intelligence

✅ Network Inventory

✅ Executive Security Reporting

✅ Real-Time WebSocket Streaming

The platform was built as a cybersecurity-focused full-stack project using FastAPI, React, Scapy, SQLite, and WebSockets.

---

# 🎯 Project Objective

Modern networks generate massive amounts of traffic.

Traditional monitoring tools often provide only raw packet information.

NetScope AI aims to transform raw traffic into meaningful security intelligence by:

- Monitoring live traffic
- Tracking hosts and sessions
- Detecting anomalies
- Classifying threats
- Presenting security insights visually
- Providing executive-level security summaries

---

# 🏗️ System Architecture

text                     INTERNET                          │                          ▼                ┌──────────────────┐               │  Packet Capture  │               │      Scapy       │               └────────┬─────────┘                        │                        ▼                ┌──────────────────┐               │ Threat Analysis  │               │ Detection Engine │               └────────┬─────────┘                        │                        ▼                ┌──────────────────┐               │ Session Tracking │               └────────┬─────────┘                        │                        ▼                ┌──────────────────┐               │ SQLite Database  │               └────────┬─────────┘                        │              ┌─────────┴─────────┐              ▼                   ▼       REST APIs             WebSockets       FastAPI             Real-Time Feed               ▼                   ▼        ┌──────────────────────────┐       │ React Dashboard Frontend │       └──────────────────────────┘ 

---

# ⚙️ Technologies Used

## Backend

- Python
- FastAPI
- Scapy
- SQLite
- SQLAlchemy
- WebSockets
- Uvicorn

## Frontend

- React
- Vite
- Tailwind CSS
- Axios

## Database

- SQLite

## Deployment

- Netlify (Frontend)
- Render (Backend)

---

# ✨ Key Features

## 📊 Live Network Statistics

Displays:

- Total packets
- TCP packets
- UDP packets
- ICMP packets
- Bandwidth usage
- Packets per second

---

## 🔗 Session Analytics

Tracks:

- Active sessions
- Session duration
- Session bandwidth
- Most active sessions
- Largest sessions

---

## 🌍 Geo Intelligence

Analyzes:

- Internal hosts
- External hosts
- External communication
- Geographic traffic insights

---

## 🚨 Threat Intelligence

Detects:

### ⚠ Host Dominance

Identifies hosts generating abnormal traffic volumes.

### ⚠ Port Scanning

Detects reconnaissance behavior.

### ⚠ Network Anomalies

Detects unusual traffic patterns.

---

## 🖥 Network Inventory

Maintains:

- Host inventory
- Traffic counts
- First seen timestamps
- Last seen timestamps

---

## 🧠 Application Intelligence

Classifies:

- HTTPS
- DNS
- HTTP
- Other applications

---

## 🏢 Executive Security Center

Provides:

- Threat score
- Risk level
- Security health
- Total hosts
- Total alerts
- Top threats

---

# 📂 Project Structure

text NetScope-AI │ ├── backend │   ├── api │   ├── database │   ├── services │   ├── websocket │   └── main.py │ ├── frontend │   ├── src │   ├── public │   └── vite.config.js │ ├── phase1 │   ├── netscope_phase11_ultimate.py │   ├── logs │   └── reports │ └── venv 

---

# 🚀 Running NetScope AI Locally

This is the exact workflow used during development and demonstration.

---

## Step 1 — Open Terminal

Navigate to project directory:

bash cd ~/Desktop/NetScope-AI 

---

## Step 2 — Activate Virtual Environment

bash source venv/bin/activate 

You should see:

text (venv) 

---

## Step 3 — Start Backend

Run:

bash sudo uvicorn backend.main:app --host 0.0.0.0 --port 8000 

Administrator permissions are required because Scapy performs live packet capture.

---

## Step 4 — Verify Backend Startup

Expected messages:

text 🚀 NetScope Sniffer Thread Started  💾 NetScope Database Persistence Thread Started  🖥 NetScope Terminal CLI Thread Started  🚀 NetScope WebSocket Broadcaster Task Started 

After startup, live packet statistics begin appearing in the terminal.

---

## Step 5 — Open New Terminal

Keep backend running.

Open a second terminal window.

Navigate to frontend:

bash cd ~/Desktop/NetScope-AI/frontend 

---

## Step 6 — Start React Frontend

bash npm run dev 

Vite starts the frontend.

Example:

text Local: http://localhost:3002/ 

Port may vary.

---

## Step 7 — Open Dashboard

Open the Vite URL shown in the terminal.

Example:

text http://localhost:3002 

Dashboard should display:

✅ Live Statistics

✅ Threat Center

✅ Session Analytics

✅ Geo Intelligence

✅ Executive Security Dashboard

✅ Network Inventory

---

# 📡 API Documentation

When backend is running:

## Swagger UI

text http://localhost:8000/docs 

Interactive API explorer.

---

## ReDoc Documentation

text http://localhost:8000/redoc 

Professional API documentation.

---

## Root Endpoint

text http://localhost:8000 

API status information.

---

# ⚡ WebSocket Endpoints

Real-time telemetry streams.

### Statistics Stream

text ws://localhost:8000/ws/live/stats 

---

### Threat Stream

text ws://localhost:8000/ws/live/threats 

---

### Hosts Stream

text ws://localhost:8000/ws/live/hosts 

---

### WebSocket Test Page

text http://localhost:8000/static/test_websocket.html 

---

# 🌐 Deployment Information

## Frontend Deployment

Netlify:

https://netscope.netlify.app/

---

## Backend Deployment

Render:

Deployed successfully.

---

# ⚠ Important Deployment Note

The dashboard frontend and backend are deployed online.

However, live packet capture functionality cannot operate fully in cloud hosting environments.

### Why?

The project relies on:

text Scapy Packet Sniffing 

which requires:

- Direct access to network interfaces
- Administrative privileges
- Raw packet capture permissions

Cloud platforms such as:

- Render
- Netlify
- Railway
- Vercel

do not allow access to the host machine's network interfaces.

Therefore:

text Live Traffic Capture = Works Locally  Live Traffic Capture ≠ Works On Cloud Deployment 

---

# 🎥 Recommended Demonstration

For full functionality:

text 1. Start Backend         ↓ 2. Start Frontend         ↓ 3. Open Dashboard         ↓ 4. Generate Internet Traffic         ↓ 5. Observe Live Packet Capture         ↓ 6. Observe Threat Detection         ↓ 7. Observe Session Analytics         ↓ 8. Open API Documentation         ↓ 9. Demonstrate WebSocket Streams         ↓ 10. Review Executive Dashboard 

---

# 👩‍💻 Author

Tanishka Sharma

Cybersecurity • Full Stack Development • Network Monitoring • Threat Intelligence

---

# ⭐ NetScope AI

**Real-Time Network Threat Intelligence Platfo