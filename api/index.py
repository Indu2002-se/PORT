"""
Serverless function entry point for Vercel deployment using WSGI
"""
from flask import Flask
import sys
import os

# Add the parent directory to sys.path to allow imports from the main app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the Flask app from our main application
from main import app

# Create a handler function for Vercel
def handler(request, response):
    """
    Handle the serverless function request for Vercel
    """
    # Process the request using the Flask app
    return app

def start_response(status, response_headers, exc_info=None):
    """
    WSGI start_response function
    """
    return None

# Export the app for Vercel
app.debug = False 