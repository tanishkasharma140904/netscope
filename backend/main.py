# =============================================================
#   NetScope AI — FastAPI Entrypoint
#   Configures the API, registers routes, and starts background threads
# =============================================================

import os
import sys
import threading
import time
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Ensure the root directory is on the path so we can import packages correctly
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# Import Scapy sniffer functions
from phase1.netscope_phase11_ultimate import start_sniffing, print_stats

# Import routers
from backend.api.routes import (
    stats,
    top_talkers,
    ports,
    sessions,
    threats,
    inventory,
    applications,
    executive_summary,
    history,
    forensics,
)

# Import database persistence service
from backend.services.persistence_service import start_persistence_service

# Import WebSocket modules (Stage 3)
import asyncio
from fastapi.staticfiles import StaticFiles
from backend.websocket import routes as ws_routes
from backend.websocket.broadcaster import websocket_broadcaster_loop

# Initialize FastAPI App
app = FastAPI(
    title="NetScope AI — Threat Intelligence API",
    description="A real-time cybersecurity API providing live network traffic and threat telemetry.",
    version="1.0.0",
)

# Enable CORS for frontend flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Routers
app.include_router(stats.router, prefix="/api", tags=["Statistics"])
app.include_router(top_talkers.router, prefix="/api", tags=["Top Talkers"])
app.include_router(ports.router, prefix="/api", tags=["Port Analysis"])
app.include_router(sessions.router, prefix="/api", tags=["Session Tracking"])
app.include_router(threats.router, prefix="/api", tags=["Threat Intelligence"])
app.include_router(inventory.router, prefix="/api", tags=["Network Inventory"])
app.include_router(applications.router, prefix="/api", tags=["Application Intelligence"])
app.include_router(executive_summary.router, prefix="/api", tags=["Executive Summary"])
app.include_router(history.router, prefix="/api")
app.include_router(forensics.router, prefix="/api", tags=["Forensics"])
app.include_router(ws_routes.router)

# Mount Static Files (Stage 3)
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")


# Background Sniffer and Console Output Startup
@app.on_event("startup")
def startup_event():
    # 1. Start the Scapy Packet Sniffer Thread
    sniffer_thread = threading.Thread(
        target=start_sniffing,
        daemon=True,
        name="PacketSniffer"
    )
    sniffer_thread.start()
    print("   🚀  NetScope Sniffer Thread Started successfully.")

    # 2. Start the Database Persistence Service Daemon Thread (Stage 2)
    start_persistence_service()

    # 3. Start the Real-Time WebSocket Broadcaster Loop (Stage 3)
    asyncio.create_task(websocket_broadcaster_loop())

    # 4. Start the Terminal Display Output Thread (preserving today's live CLI output)
    def terminal_loop():

        # Wait a couple of seconds so startup logs don't get mixed
        time.sleep(2)
        print("\n" + "═" * 56)
        print("   🚀  NetScope AI Live CLI Dashboard Enabled")
        print("   🔄  Refreshing Terminal Statistics every 5 seconds...")
        print("═" * 56 + "\n")
        try:
            while True:
                time.sleep(5)
                print_stats()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"   ⚠️  Console print error: {e}")

    terminal_thread = threading.Thread(
        target=terminal_loop,
        daemon=True,
        name="TerminalCLI"
    )
    terminal_thread.start()
    print("   🖥   NetScope Terminal CLI Thread Started successfully.")

@app.get("/")
def read_root():
    return {
        "message": "Welcome to NetScope AI - Threat Intelligence API",
        "docs_url": "/docs",
        "status": "online"
    }

