from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
import os
from functools import wraps
import re
from dotenv import load_dotenv
from supabase import create_client, Client
import json

# Load environment variables
load_dotenv()

auth = Blueprint('auth', __name__)

def get_supabase() -> Client:
    """Get Supabase client instance."""
    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_KEY")
    if not supabase_url or not supabase_key:
        raise ValueError("Supabase URL and Key must be set in environment variables.")
    return create_client(supabase_url, supabase_key)

def init_db():
    """Initialize database connection - this is kept for compatibility with existing code."""
    # Supabase tables are already created via migrations
    pass

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or 'access_token' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or 'access_token' not in session:
            return redirect(url_for('auth.login'))
        
        # Check if user is admin
        try:
            supabase = get_supabase()
            user_data = supabase.table('admin_users').select('*').eq('id', session['user_id']).execute()
            if not user_data.data or len(user_data.data) == 0:
                flash('Admin access required', 'error')
                return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Error checking admin status: {str(e)}', 'error')
            return redirect(url_for('dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return redirect(url_for('auth.signup'))
            
        try:
            supabase = get_supabase()
            
            # Register the user with Supabase Auth
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": {
                        "username": username,
                        "is_admin": False
                    }
                }
            })
            
            # Update the username in the public users table
            if auth_response.user:
                # The trigger will create the user in public.users
                # We need to update the username since it defaulted to email
                supabase.rpc(
                    'update_username', 
                    {'user_id': auth_response.user.id, 'new_username': username}
                ).execute()
                
                flash('Registration successful! Please confirm your email address.', 'success')
                return redirect(url_for('auth.login'))
            else:
                flash('Registration failed. Please try again.', 'error')
                return redirect(url_for('auth.signup'))
                
        except Exception as e:
            error_msg = str(e)
            if "User already registered" in error_msg:
                flash('Email already exists', 'error')
            else:
                flash(f'An error occurred during registration: {error_msg}', 'error')
            return redirect(url_for('auth.signup'))
            
    return render_template('auth/signup.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')  # Changed from username to email
        password = request.form.get('password')
        
        if not email or not password:
            flash('Please fill in all fields', 'error')
            return redirect(url_for('auth.login'))
            
        try:
            supabase = get_supabase()
            
            # Sign in with Supabase Auth
            auth_response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })
            
            if auth_response.user:
                # Store user session data
                session['user_id'] = auth_response.user.id
                session['access_token'] = auth_response.session.access_token
                session['refresh_token'] = auth_response.session.refresh_token
                
                # Get user data from the users table
                user_data = supabase.table('users').select('username').eq('id', auth_response.user.id).execute()
                
                if user_data.data and len(user_data.data) > 0:
                    session['username'] = user_data.data[0]['username']
                else:
                    session['username'] = email
                
                flash('Welcome back!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password', 'error')
                
        except Exception as e:
            error_msg = str(e)
            if "Invalid login credentials" in error_msg:
                flash('Invalid email or password', 'error')
            else:
                flash(f'An error occurred during login: {error_msg}', 'error')
            
    return render_template('auth/login.html')

@auth.route('/logout')
def logout():
    try:
        if 'access_token' in session:
            supabase = get_supabase()
            supabase.auth.sign_out()
    except Exception:
        # Even if sign out fails, clear the session
        pass
        
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index')) 