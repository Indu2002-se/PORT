#!/bin/bash

# Build script for Vercel deployment

echo "Running build script for Vercel deployment..."

# Create necessary directories
mkdir -p scan_results
mkdir -p instance

# Run setup script
python vercel_setup.py

echo "Build script completed" 