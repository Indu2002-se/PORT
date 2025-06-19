"""
Main entry point for Vercel deployment
"""
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Run setup script
try:
    from vercel_setup import setup_vercel_environment
    setup_vercel_environment()
except Exception as e:
    logger.error(f"Error running setup script: {e}")

# Import the Flask app after setup
from scanner_tool.flask_web_interface import app, ensure_directories, create_templates, create_css, create_js

# Initialize required directories and files
try:
    ensure_directories()
    create_templates()
    create_css()
    create_js()
    logger.info("Successfully initialized application directories and files")
except Exception as e:
    logger.error(f"Error initializing directories and files: {e}")

# Set debug mode to False for production
app.debug = False

# This is the entry point for Vercel
if __name__ == "__main__":
    app.run() 