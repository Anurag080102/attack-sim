#!/usr/bin/env python3
"""
Attack-Sim Entry Point

Run this script to start the Flask development server.
Usage: python run.py
"""
import os
from app import create_app

# Get configuration from environment variable, default to development
config_name = os.environ.get("FLASK_CONFIG", "development")

# Create the Flask application
app = create_app(config_name)

if __name__ == "__main__":
    # Get host and port from environment variables
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", 5000))

    print(f"\n{'=' * 50}")
    print("  Attack-Sim - Security Testing Tool")
    print(f"{'=' * 50}")
    print(f"  Running on: http://{host}:{port}")
    print(f"  Configuration: {config_name}")
    print(f"{'=' * 50}\n")

    # Run the development server
    app.run(host=host, port=port, debug=app.config.get("DEBUG", False))
