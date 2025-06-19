"""
Test script to verify the application works in a Vercel-like environment
"""
import os
import sys
import logging
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_vercel_environment():
    """
    Test the application in a Vercel-like environment
    """
    try:
        logger.info("Testing Vercel environment...")
        
        # Import the app
        from index import app
        
        # Test that the app exists
        assert app is not None
        logger.info("App imported successfully")
        
        # Test that the app has routes
        assert len(app.url_map._rules) > 0
        logger.info(f"App has {len(app.url_map._rules)} routes")
        
        # Test that the app can handle a request
        with app.test_client() as client:
            response = client.get('/')
            assert response.status_code == 200
            logger.info(f"App returned status code {response.status_code} for '/'")
        
        logger.info("Vercel environment test passed")
        return True
    except Exception as e:
        logger.error(f"Error testing Vercel environment: {e}")
        return False

# Run the test when this script is executed
if __name__ == "__main__":
    test_vercel_environment() 