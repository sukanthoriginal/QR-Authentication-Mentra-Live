# QR Code Authentication using Mentra Live

## Overview
This is a multi-component QR code authentication system that allows users to authenticate on a web dashboard by scanning QR codes with a Mentra Live. The system consists of three main components:

---

## Components

### 1. Token Handler (`token_handler.py`)
**Purpose**: JWT token management utilities
- Generates secure JWT tokens with user ID and optional scanned URL  
- Verifies and decodes JWT tokens  
- Uses 5-minute expiration for security  
- Includes replay attack protection with unique token IDs (`jti`)  

---

### 2. QR Glass Handler (`qr_glass.py`)
**Purpose**: Processes camera frames from AR glasses to detect QR codes  
- Uses OpenCV and pyzbar for QR code detection  
- Exchanges temporary tokens with AugmentOS API for user authentication  
- Forwards successful authentications to desktop dashboard  

---

### 3. Web Dashboard (`qr_web.py`)
**Purpose**: Web interface for QR code authentication  
- Generates QR codes for browser sessions  
- Handles WebSocket connections for real-time updates  
- Manages user sessions and authentication state  
- Provides dashboard interface post-authentication  

---

## Architecture Flow

1. User opens web dashboard → QR code generated  
2. User scans QR with AR glasses → Frame 
3. QR detection system processes frame → Extracts QR data  
4. System exchanges temp token → Gets user ID from MentraOS  
5. Secure JWT token generated → Sent to dashboard  
6. Dashboard authenticates user → Redirects to dashboard  

---

## Key Features

### 🔐 Security
- JWT tokens with 5-minute expiration  
- Replay attack protection with unique token IDs  
- Secure session management  
- Rate limiting protection  

### ⚡ Real-time Processing
- File system monitoring for new camera frames  
- WebSocket connections for instant authentication  
- Thread-safe operations with locks  
- Automatic cleanup of expired sessions/QR codes  

### 👥 Multi-user Support
- Session isolation  
- Concurrent user handling  

---

## Technical Stack

- **Backend**: Flask, Flask-SocketIO  
- **Authentication**: JWT tokens  
- **QR Processing**: OpenCV, pyzbar, qrcode  
- **Real-time**: WebSockets  
- **Monitoring**: watchdog (file system events)  
- **External API**: MentraOS for user verification  

---

## Configuration

- **JWT expiration**: 5 minutes  
- **QR code expiration**: 60 seconds  
- **Session lifetime**: 1 hour  
- **Cleanup interval**: 60 seconds

---

## Sequence Diagram

![Sequence Diagram](https://github.com/sukanthoriginal/QR-Auth-Mentra-Live/blob/main/sequence_digram.png?raw=true)

---


