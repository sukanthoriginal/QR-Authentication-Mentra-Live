"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const sdk_1 = require("@mentra/sdk");
const ejs = __importStar(require("ejs"));
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const PACKAGE_NAME = process.env.PACKAGE_NAME ??
    (() => {
        throw new Error('PACKAGE_NAME is not set in .env file');
    })();
const MENTRAOS_API_KEY = process.env.MENTRAOS_API_KEY ??
    (() => {
        throw new Error('MENTRAOS_API_KEY is not set in .env file');
    })();
const PORT = parseInt(process.env.PORT || '3000');
/**
 * Photo Taker App with webview functionality for displaying photos
 * Extends AppServer to provide photo taking and webview display capabilities
 */
class ExampleMentraOSApp extends sdk_1.AppServer {
    constructor() {
        super({
            packageName: PACKAGE_NAME,
            apiKey: MENTRAOS_API_KEY,
            port: PORT,
        });
        this.photos = new Map(); // Store photos by userId
        this.latestPhotoTimestamp = new Map(); // Track latest photo timestamp per user
        this.isStreamingPhotos = new Map(); // Track if we are streaming photos for a user
        this.nextPhotoTime = new Map(); // Track next photo time for a user
        this.setupWebviewRoutes();
        this.ensureStreamDataDir();
    }
    /**
     * Ensure stream_data directory exists
     */
    ensureStreamDataDir() {
        const streamDataDir = path.join(process.cwd(), 'stream_data');
        if (!fs.existsSync(streamDataDir)) {
            fs.mkdirSync(streamDataDir, { recursive: true });
        }
    }
    /**
     * Handle new session creation and button press events
     */
    async onSession(session, sessionId, userId) {
        // this gets called whenever a user launches the app
        this.logger.info(`Session started for user ${userId}`);
        // set the initial state of the user
        this.isStreamingPhotos.set(userId, true); // Auto-start streaming
        this.nextPhotoTime.set(userId, Date.now());
        // Create user directory
        const userDir = path.join(process.cwd(), 'stream_data', userId);
        if (!fs.existsSync(userDir)) {
            fs.mkdirSync(userDir, { recursive: true });
        }
        // this gets called whenever a user presses a button
        session.events.onButtonPress(async (button) => {
            this.logger.info(`Button pressed: ${button.buttonId}, type: ${button.pressType}`);
            if (button.pressType === 'long') {
                // the user held the button, so we toggle the streaming mode
                this.isStreamingPhotos.set(userId, !this.isStreamingPhotos.get(userId));
                this.logger.info(`Streaming photos for user ${userId} is now ${this.isStreamingPhotos.get(userId)}`);
                return;
            }
            else {
                session.layouts.showTextWall('Button pressed, about to take photo', { durationMs: 4000 });
                // the user pressed the button, so we take a single photo
                try {
                    // first, get the photo
                    const photo = await session.camera.requestPhoto();
                    // if there was an error, log it
                    this.logger.info(`Photo taken for user ${userId}, timestamp: ${photo.timestamp}`);
                    this.cachePhoto(photo, userId);
                }
                catch (error) {
                    this.logger.error(`Error taking photo: ${error}`);
                }
            }
        });
        // repeatedly check if we are in streaming mode and if we are ready to take another photo
        setInterval(async () => {
            if (this.isStreamingPhotos.get(userId) && Date.now() > (this.nextPhotoTime.get(userId) ?? 0)) {
                try {
                    // set the next photos for 1 second from now
                    this.nextPhotoTime.set(userId, Date.now() + 5000);
                    // actually take the photo
                    const photo = await session.camera.requestPhoto();
                    // cache the photo for display and save to file
                    this.cachePhoto(photo, userId);
                    this.savePhotoToFile(photo, userId);
                }
                catch (error) {
                    this.logger.error(`Error auto-taking photo: ${error}`);
                }
            }
        }, 1000);
    }
    async onStop(sessionId, userId, reason) {
        // clean up the user's state
        this.isStreamingPhotos.set(userId, false);
        this.nextPhotoTime.delete(userId);
        this.logger.info(`Session stopped for user ${userId}, reason: ${reason}`);
    }
    /**
     * Save photo to file system
     */
    async savePhotoToFile(photo, userId) {
        try {
            const userDir = path.join(process.cwd(), 'stream_data', userId);
            const extension = photo.mimeType.split('/')[1] || 'jpg';
            const filename = `${photo.timestamp.getTime()}.${extension}`;
            const filepath = path.join(userDir, filename);
            fs.writeFileSync(filepath, photo.buffer);
            this.logger.info(`Photo saved to ${filepath}`);
        }
        catch (error) {
            this.logger.error(`Error saving photo to file: ${error}`);
        }
    }
    /**
     * Cache a photo for display
     */
    async cachePhoto(photo, userId) {
        // create a new stored photo object which includes the photo data and the user id
        const cachedPhoto = {
            requestId: photo.requestId,
            buffer: photo.buffer,
            timestamp: photo.timestamp,
            userId: userId,
            mimeType: photo.mimeType,
            filename: photo.filename,
            size: photo.size,
        };
        // this example app simply stores the photo in memory for display in the webview, but you could also send the photo to an AI api,
        // or store it in a database or cloud storage, send it to roboflow, or do other processing here
        // cache the photo for display
        this.photos.set(userId, cachedPhoto);
        // update the latest photo timestamp
        this.latestPhotoTimestamp.set(userId, cachedPhoto.timestamp.getTime());
        this.logger.info(`Photo cached for user ${userId}, timestamp: ${cachedPhoto.timestamp}`);
    }
    /**
     * Set up webview routes for photo display functionality
     */
    setupWebviewRoutes() {
        const app = this.getExpressApp();
        // API endpoint to get the latest photo for the authenticated user
        app.get('/api/latest-photo', (req, res) => {
            const userId = req.authUserId;
            if (!userId) {
                res.status(401).json({ error: 'Not authenticated' });
                return;
            }
            const photo = this.photos.get(userId);
            if (!photo) {
                res.status(404).json({ error: 'No photo available' });
                return;
            }
            res.json({
                requestId: photo.requestId,
                timestamp: photo.timestamp.getTime(),
                hasPhoto: true,
            });
        });
        // API endpoint to get photo data
        app.get('/api/photo/:requestId', (req, res) => {
            const userId = req.authUserId;
            const requestId = req.params.requestId;
            if (!userId) {
                res.status(401).json({ error: 'Not authenticated' });
                return;
            }
            const photo = this.photos.get(userId);
            if (!photo || photo.requestId !== requestId) {
                res.status(404).json({ error: 'Photo not found' });
                return;
            }
            res.set({
                'Content-Type': photo.mimeType,
                'Cache-Control': 'no-cache',
            });
            res.send(photo.buffer);
        });
        // Main webview route - displays the photo viewer interface
        app.get('/webview', async (req, res) => {
            const userId = req.authUserId;
            if (!userId) {
                res.status(401).send(`
          <html>
            <head><title>Photo Viewer - Not Authenticated</title></head>
            <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
              <h1>Please open this page from the MentraOS app</h1>
            </body>
          </html>
        `);
                return;
            }
            const templatePath = path.join(process.cwd(), 'views', 'photo-viewer.ejs');
            const html = await ejs.renderFile(templatePath, {});
            res.send(html);
        });
    }
}
// Start the server
// DEV CONSOLE URL: https://console.mentra.glass/
// Get your webhook URL from ngrok (or whatever public URL you have)
const app = new ExampleMentraOSApp();
app.start().catch(console.error);
