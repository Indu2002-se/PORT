"""
WSGI entry point for the Flask application
"""
from scanner_tool.flask_web_interface import app, ensure_directories, create_templates, create_css, create_js

# Initialize directories and files
ensure_directories()
create_templates()
create_css()
create_js()

# Set debug mode to False for production
app.debug = False

# Export the app for WSGI servers
application = app 