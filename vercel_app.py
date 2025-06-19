"""
Vercel serverless function entry point
"""
from scanner_tool.flask_web_interface import app, ensure_directories, create_templates, create_css, create_js

# Initialize required directories and files
try:
    ensure_directories()
    create_templates()
    create_css()
    create_js()
except Exception as e:
    print(f"Warning: Could not initialize directories: {e}")

# Disable debug mode for production
app.debug = False

# Export the app for Vercel
application = app 