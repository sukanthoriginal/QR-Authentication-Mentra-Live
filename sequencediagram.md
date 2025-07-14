sequenceDiagram
    participant User as User
    participant Browser as Web Browser
    participant WebApp as Web Dashboard<br/>(qr_web.py)
    participant FileSystem as File System<br/>(stream_data/)
    participant QRGlass as QR Glass Handler<br/>(qr_glass.py)

    %% Phase 1: Initial Setup
    Note over User,WebApp: Phase 1: QR Code Generation
    User->>Browser: Navigate to /
    Browser->>WebApp: GET /
    WebApp->>WebApp: Create browser_session ID
    WebApp->>WebApp: generate_qr_for_session()
    WebApp->>WebApp: Create QR with session payload
    WebApp->>Browser: Return page with QR code
    Browser->>WebApp: Establish WebSocket connection

    %% Phase 2: QR Code Scanning & Processing
    Note over User,QRGlass: Phase 2: QR Scanning & Detection
    User->>User: Scans QR code with AR glasses
    User->>FileSystem: Camera captures frame<br/>saves to stream_data/user_id/frame.jpg
    
    QRGlass->>FileSystem: Monitor stream_data folder<br/>(watchdog FileSystemEventHandler)
    FileSystem-->>QRGlass: New frame detected (on_created)
    QRGlass->>QRGlass: extract_user_id_from_path()
    QRGlass->>QRGlass: detect_qr_codes() using OpenCV/pyzbar
    QRGlass->>QRGlass: Decode QR data (session payload)

    %% Phase 3: Authentication Processing
    Note over QRGlass,WebApp: Phase 3: Authentication
    QRGlass->>QRGlass: generate_qr_token(user_id, scanned_url)
    QRGlass->>QRGlass: Create JWT with user_id + QR data
    QRGlass->>WebApp: POST /api/scan<br/>{secure_token: jwt_token}
    
    WebApp->>WebApp: verify_token(secure_token)
    WebApp->>WebApp: Extract user_id from JWT
    WebApp->>WebApp: Find browser_session from QR payload
    WebApp->>WebApp: auth_manager.add_session()
    
    %% Phase 4: Real-time Notification
    Note over WebApp,Browser: Phase 4: Authentication Complete
    WebApp->>Browser: WebSocket emit('authentication_successful')
    Browser->>Browser: Auto-redirect to /dashboard
    WebApp-->>QRGlass: Return success response
    
    %% Phase 5: Dashboard Access
    Note over User,WebApp: Phase 5: Authenticated Access
    Browser->>WebApp: GET /dashboard
    WebApp->>WebApp: Check session authentication
    WebApp->>Browser: Return dashboard page
    User->>Browser: Views authenticated dashboard