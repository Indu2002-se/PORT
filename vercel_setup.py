"""
Setup script for Vercel deployment
"""
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def setup_vercel_environment():
    """
    Set up the environment for Vercel deployment
    """
    try:
        logger.info("Setting up Vercel environment...")
        
        # Create necessary directories
        os.makedirs('scan_results', exist_ok=True)
        os.makedirs('instance', exist_ok=True)
        
        logger.info("Vercel environment setup complete")
        return True
    except Exception as e:
        logger.error(f"Error setting up Vercel environment: {e}")
        return False

# Run the setup when this script is executed
if __name__ == "__main__":
    setup_vercel_environment() 