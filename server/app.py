"""
Server app module - re-exports from incident_response.server.app.

This file exists at server/app.py for OpenEnv validator compatibility.
The actual implementation is in incident_response/server/app.py.
"""

from incident_response.server.app import app, main

__all__ = ["app", "main"]

if __name__ == "__main__":
    main()
