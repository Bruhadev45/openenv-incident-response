"""
Server app module for OpenEnv validator compatibility.

This file exists at server/app.py as required by the OpenEnv spec.
"""

import os
import uvicorn

# Re-export the FastAPI app from the main module
from incident_response.server.app import app

__all__ = ["app", "main"]


def main() -> None:
    """Run the server using uvicorn."""
    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")
    uvicorn.run(
        "server.app:app",
        host=host,
        port=port,
        reload=os.environ.get("ENV", "production") != "production",
    )


if __name__ == "__main__":
    main()
