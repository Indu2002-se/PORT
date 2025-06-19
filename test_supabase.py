#!/usr/bin/env python3
"""
Test Supabase Integration
A simple script to test that Supabase is properly configured.
"""

import os
import sys
from supabase import create_client, Client

# Hardcoded Supabase credentials (for testing only)
SUPABASE_URL = "https://tuhtempenltbwzjhrzmx.supabase.co"
SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InR1aHRlbXBlbmx0Ynd6amhyem14Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTAzMjE5NjgsImV4cCI6MjA2NTg5Nzk2OH0.9eqF00LfCu1k_u8zxVEKhQs3bYwgVbvQ5pzW1zuzvAw"

def test_supabase_connection():
    """Test connecting to Supabase and basic operations."""
    try:
        print(f"Connecting to Supabase at {SUPABASE_URL}...")
        
        # Initialize the Supabase client
        supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        
        # Test basic query
        print("Testing query to users table...")
        response = supabase.table('users').select('*').limit(5).execute()
        
        # Check if the query was successful
        if hasattr(response, 'data'):
            user_count = len(response.data)
            print(f"Success! Found {user_count} users in the database.")
            return True
        else:
            print("Error: Could not query the users table.")
            return False
            
    except Exception as e:
        print(f"Error connecting to Supabase: {str(e)}")
        return False

if __name__ == "__main__":
    print("Starting Supabase Integration Test")
    print("----------------------------------")
    
    success = test_supabase_connection()
    
    if success:
        print("\n✅ Supabase integration test passed!")
        sys.exit(0)
    else:
        print("\n❌ Supabase integration test failed!")
        sys.exit(1) 