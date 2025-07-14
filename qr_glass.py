#!/usr/bin/env python3
import os
import time
import threading
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver  # Add this import
from watchdog.events import FileSystemEventHandler
from PIL import Image
import cv2
from pyzbar import pyzbar
from flask import Flask, jsonify
from supabase import create_client
from dotenv import load_dotenv
import uuid
from datetime import datetime, timezone
import requests
import logging
import jwt
import secrets

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = os.urandom(24)

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__)))

# Build full path to .env file
dotenv_path = os.path.join(project_root, 'mentra.env')
load_dotenv(dotenv_path)

# Load API key and package name from environment variables for AugmentOS
AUGMENTOS_API_KEY = os.environ.get('DEV_AUGMENT_API_KEY')
PACKAGE_NAME = os.environ.get('DEV_AUGMENT_PACKAGE')
JWT_SECRET = os.environ.get('JWT_SECRET_KEY')

# Stream data folder path
STREAM_DATA_FOLDER = os.path.join(project_root, 'stream_data')

JWT_ALGORITHM = 'HS256'

def sanitize_user_id(user_id):
    """Sanitize user ID by replacing '@' and '.' with underscores."""
    if not user_id:
        return ""
    return str(user_id).replace('@', '_').replace('.', '_')

def generate_qr_token(user_id, scanned_url=None):
    """
    Generate a secure JWT token containing user ID and optionally the scanned URL
    
    Args:
        user_id (str): The authenticated user's ID
        scanned_url (str, optional): The scanned QR code URL
        
    Returns:
        str: JWT token as secure_token
    """
    # Ensure user_id is a string and sanitize it
    user_id_str = str(user_id) if user_id else ""
    
    # Create payload with minimized data - just what's needed for security
    payload = {
        'user_id': user_id_str,
        'iat': int(time.time()),  # Issued at time
        'exp': int(time.time()) + 300,  # Expire after 5 minutes (5 min = 300 sec)
        'jti': secrets.token_hex(8)  # Unique token ID for preventing replay attacks
    }
    
    # Add scanned URL if provided - only essential field besides user_id
    if scanned_url:
        payload['scanned_url'] = str(scanned_url)
    
    try:
        # Create and return the token - this will be the only data transferred
        secure_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        logging.info(f"Generated secure token for user: {user_id_str}")
        return secure_token
    except Exception as e:
        logging.error(f"Error generating secure token: {str(e)}")
        raise

def verify_token(secure_token):
    """
    Verify and decode a secure JWT token
    
    Args:
        secure_token (str): The JWT token to verify
        
    Returns:
        dict: The decoded payload if valid
        None: If the token is invalid or expired
    """
    if not secure_token:
        logging.warning("Empty secure token provided for verification")
        return None
        
    try:
        # Decode and verify the secure token - extracts original payload
        payload = jwt.decode(secure_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        logging.info(f"Successfully verified secure token for user: {payload.get('user_id')}")
        return payload
    except jwt.ExpiredSignatureError:
        # Token expired
        logging.warning("Secure token verification failed: Token expired")
        return None
    except jwt.InvalidTokenError as e:
        # Token invalid
        logging.warning(f"Secure token verification failed: Invalid token - {str(e)}")
        return None
    except Exception as e:
        # Unexpected error
        logging.error(f"Secure token verification error: {str(e)}")
        return None

def exchange_token_for_user_id(temp_token):
    """Exchange the temporary token for a user ID via the AugmentOS API"""
    endpoint = 'https://prod.augmentos.cloud/api/auth/exchange-user-token'
    
    logging.info(f"Sending request to {endpoint} with token: {temp_token}")
    
    try:
        response = requests.post(
            endpoint,
            json={
                'aos_temp_token': temp_token,
                'packageName': PACKAGE_NAME
            },
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {AUGMENTOS_API_KEY}'
            },
            timeout=5
        )
        
        logging.info(f"Response status: {response.status_code}")
        logging.info(f"Response body: {response.text[:200]}...")
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success') and data.get('userId'):
                return sanitize_user_id(data['userId'])
            elif "max entries" in response.text.lower():
                raise Exception("Rate limit reached: Maximum entries exceeded. Please try again later.")
            else:
                raise Exception(f"Unexpected response: {data}")
        
        try:
            data = response.json()
            error_message = data.get('error', f'Status {response.status_code}')
            
            if "max entries" in response.text.lower():
                error_message = "Rate limit reached: Maximum entries exceeded. Please try again later."
            
        except:
            error_message = f'Status {response.status_code}: {response.text}'
        
        raise Exception(f"Token exchange failed: {error_message}")
        
    except requests.exceptions.RequestException as e:
        logging.error(f"Network error: {str(e)}")
        raise Exception(f"Connection error: {str(e)}")

def detect_qr_codes(image_path):
    """Detect QR codes in an image and return their data"""
    try:
        # Read image using OpenCV
        image = cv2.imread(image_path)
        if image is None:
            logging.warning(f"Could not read image: {image_path}")
            return []
        
        # Convert to RGB (pyzbar works better with RGB)
        rgb_image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        
        # Detect QR codes
        qr_codes = pyzbar.decode(rgb_image)
        
        results = []
        for qr_code in qr_codes:
            # Extract the QR code data
            qr_data = qr_code.data.decode('utf-8')
            qr_type = qr_code.type
            results.append({
                'data': qr_data,
                'type': qr_type
            })
            
        return results
        
    except Exception as e:
        logging.error(f"Error detecting QR codes in {image_path}: {str(e)}")
        return []

def process_qr_code(qr_data, user_id):
    """Process detected QR code data and trigger authentication"""
    if not user_id:
        logging.error("No user ID available for authentication")
        print("❌ UPDATE: No user ID available for authentication")
        return
    
    try:
        # Ensure both parameters are strings
        user_id_str = str(user_id)
        qr_data_str = str(qr_data)
        
        # Generate secure token containing both user_id and scanned_url
        secure_token = generate_qr_token(user_id_str, qr_data_str)
        
        logging.info(f"Processing QR code for user {user_id_str}: {qr_data_str}")
        print(f"🔐 UPDATE: Generated secure token for user {user_id_str}")
        
        # Send to desktop app
        desktop_response = requests.post(
            "https://qr-dashboard.sukanthoriginal.com/api/scan",
            json={
                'secure_token': secure_token
            },
            timeout=3
        )
        desktop_response.raise_for_status()
        logging.info(f"Successfully forwarded to desktopview: {desktop_response.status_code}")
        print(f"✅ UPDATE: Successfully authenticated user {user_id_str}")
        
    except Exception as e:
        logging.error(f"Failed to process QR code: {str(e)}")
        print(f"❌ UPDATE: Authentication failed - {str(e)}")

class FrameHandler(FileSystemEventHandler):
    """Handler for new frame files in the stream_data folder"""
    
    def __init__(self):
        self.processed_files = set()
        
    def on_created(self, event):
        if event.is_directory:
            return
            
        # Only process JPEG files
        if event.src_path.lower().endswith(('.jpg', '.jpeg')):
            # Small delay to ensure file is fully written
            time.sleep(0.1)
            self.process_frame(event.src_path)
    
    def on_modified(self, event):
        if event.is_directory:
            return
            
        # Only process JPEG files
        if event.src_path.lower().endswith(('.jpg', '.jpeg')):
            # Small delay to ensure file is fully written
            time.sleep(0.1)
            self.process_frame(event.src_path)
    
    def extract_user_id_from_path(self, file_path):
        """Extract user_id from file path: stream_data/user_id/filename.jpg"""
        try:
            # Get relative path from stream_data folder
            rel_path = os.path.relpath(file_path, STREAM_DATA_FOLDER)
            # Extract user_id (first directory in the path)
            user_id = rel_path.split(os.sep)[0]
            return user_id
        except Exception as e:
            logging.error(f"Error extracting user_id from path {file_path}: {str(e)}")
            return None
    
    def process_frame(self, file_path):
        """Process a single frame for QR codes"""
        # Avoid processing the same file multiple times
        if file_path in self.processed_files:
            return
            
        self.processed_files.add(file_path)
        
        # Clean up old processed files to prevent memory issues
        if len(self.processed_files) > 100:
            self.processed_files.clear()
        
        # Extract user_id from file path
        user_id = self.extract_user_id_from_path(file_path)
        if not user_id:
            logging.error(f"Could not extract user_id from path: {file_path}")
            return
        
        # Extract just the filename for cleaner logging
        filename = os.path.basename(file_path)
        
        logging.info(f"📷 Processing frame for user {user_id}: {filename}")
        print(f"🔄 UPDATE: Processing new frame - {user_id}/{filename}")
        
        try:
            # Detect QR codes in the frame
            qr_codes = detect_qr_codes(file_path)
            
            if qr_codes:
                logging.info(f"🎯 Found {len(qr_codes)} QR code(s) in {filename}")
                print(f"🎯 UPDATE: QR codes detected - {len(qr_codes)} code(s) for user {user_id}")
                
                for qr_code in qr_codes:
                    logging.info(f"QR Code detected for user {user_id}: {qr_code['data']}")
                    print(f"📱 UPDATE: QR Code found - {qr_code['data']}")
                    process_qr_code(qr_code['data'], user_id)
                
            else:
                logging.debug(f"No QR codes found in {filename}")
                
        except Exception as e:
            logging.error(f"Error processing frame {file_path}: {str(e)}")
            print(f"❌ UPDATE: Error processing frame - {str(e)}")

        # Delete the frame after processing
        try:
            os.remove(file_path)
            logging.debug(f"Deleted processed frame: {filename}")
            print(f"🗑️ UPDATE: Cleaned up frame - {filename}")


        except Exception as e:
            logging.error(f"Error deleting frame {file_path}: {str(e)}")
            print(f"❌ UPDATE: Failed to delete frame - {str(e)}")


def start_frame_monitoring():
    """Start monitoring the stream_data folder for new frames"""
    # Create stream_data folder if it doesn't exist
    os.makedirs(STREAM_DATA_FOLDER, exist_ok=True)
    
    # Set up file system observer - Force polling mode for Docker compatibility
    event_handler = FrameHandler()
    
    # Use PollingObserver instead of regular Observer for Docker volumes
    observer = PollingObserver()
    observer.schedule(event_handler, STREAM_DATA_FOLDER, recursive=True)
    
    # Start monitoring
    observer.start()
    logging.info(f"Started polling-based monitoring of {STREAM_DATA_FOLDER} and all user subfolders for new frames")
    print(f"🚀 UPDATE: Started polling-based monitoring of {STREAM_DATA_FOLDER} for QR codes")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logging.info("Stopped frame monitoring")
        print("🛑 UPDATE: Stopped frame monitoring")
    
    observer.join()

def set_user_id(user_id):
    """Set the current user ID for authentication (deprecated - now auto-detected from folder structure)"""
    logging.info(f"Note: User ID is now auto-detected from folder structure: stream_data/{user_id}/")

# Optional: Keep a minimal API endpoint for compatibility
@app.route('/set_user/<user_id>', methods=['POST'])
def set_user_endpoint(user_id):
    """API endpoint for compatibility (user ID is now auto-detected)"""
    return jsonify({'success': True, 'message': 'User ID is auto-detected from folder structure'})

@app.route('/status', methods=['GET'])
def status():
    """Get current application status"""
    # List all user folders being monitored
    user_folders = []
    if os.path.exists(STREAM_DATA_FOLDER):
        for item in os.listdir(STREAM_DATA_FOLDER):
            item_path = os.path.join(STREAM_DATA_FOLDER, item)
            if os.path.isdir(item_path):
                user_folders.append(item)
    
    return jsonify({
        'status': 'running',
        'monitoring_folder': STREAM_DATA_FOLDER,
        'user_folders': user_folders,
        'monitoring_mode': 'polling'
    })

if __name__ == "__main__":
    # Start frame monitoring in a separate thread
    monitoring_thread = threading.Thread(target=start_frame_monitoring, daemon=True)
    monitoring_thread.start()
    
    # Run minimal Flask app for status/control (optional)
    app.run(host='0.0.0.0', port=96, debug=False)

application = app