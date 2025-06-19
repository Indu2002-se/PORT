
"""
Main entry point for the port scanner web application

This is a fully web-based multithreaded port scanner application.
It uses Flask for the web interface and provides the ability to scan 
networks for open ports using multiple threads for better performance.
"""

# Step 1: Import the Flask app and setup functions from flask_web_interface module
from scanner_tool.flask_web_interface import app, ensure_directories, create_templates, create_css, create_js

# Step 2: Initialize required directories and files before app startup
# This ensures all necessary file structure is in place
ensure_directories()  # Create directory structure for the application
create_templates()    # Generate HTML templates if they don't exist
create_css()          # Generate CSS stylesheets if they don't exist
create_js()           # Generate JavaScript files if they don't exist

# Step 3: Define the application entry point with Flask app run parameters
if __name__ == "__main__":
    # Step 4: Start the Flask web server
    # - host='0.0.0.0' makes the app accessible from any network interface
    # - port=5000 is the standard Flask development port
    # - debug=True enables automatic reloading and detailed error messages
    app.run(host='0.0.0.0', port=4000, debug=True)
