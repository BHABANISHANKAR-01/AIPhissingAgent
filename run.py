"""
AI Penetration Testing Assistant — Entry Point
"""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.app import app
from backend.config import HOST, PORT, DEBUG

if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║      🔒 AI Penetration Testing Assistant v1.0          ║
    ║      For Controlled/Educational Environments Only       ║
    ╠══════════════════════════════════════════════════════════╣
    ║  Dashboard:  http://localhost:5000                      ║
    ║  API:        http://localhost:5000/api/health            ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    app.run(host=HOST, port=PORT, debug=DEBUG, threaded=True)
