const express = require('express');
const cors = require('cors');
const { Client, LocalAuth, MessageMedia } = require('whatsapp-web.js');
const qrcode = require('qrcode');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 5000;

// Environment variables
const PHP_API_URL = process.env.PHP_API_URL || 'https://imw-edu.com/whatsapp-api/api.php';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://imw-edu.com';
const NODE_ENV = process.env.NODE_ENV || 'development';

// CORS Configuration
app.use(cors({
    origin: FRONTEND_URL,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Configure multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// Create directories
['uploads', 'auth_data'].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// WhatsApp Client Management
const clients = new Map();
const qrCodes = new Map();
const clientInitializing = new Map();

// Helper function to call PHP API
async function callPHPAPI(endpoint, method = 'GET', data = null, token = null) {
    try {
        const config = {
            method,
            url: `${PHP_API_URL}${endpoint}`,
            headers: {
                'Content-Type': 'application/json'
            },
            timeout: 10000
        };

        if (token) {
            config.headers['Authorization'] = `Bearer ${token}`;
        }

        if (data) {
            config.data = data;
        }

        const response = await axios(config);
        return response.data;
    } catch (error) {
        if (error.response) {
            const phpError = new Error(error.response.data.error || `PHP API error: ${error.response.status}`);
            phpError.status = error.response.status;
            throw phpError;
        }
        throw error;
    }
}

function extractToken(req) {
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        return authHeader.substring(7);
    }
    return null;
}

// Middleware to verify JWT tokens (for dashboard/UI)
async function verifyAuth(req, res, next) {
    const token = extractToken(req);
    
    if (!token) {
        console.error('❌ No token provided in request');
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        console.log(`🔑 Verifying JWT token for request: ${req.method} ${req.path}`);
        
        // Verify token by calling PHP API
        const userData = await callPHPAPI('/auth/me', 'GET', null, token);
        
        if (!userData || !userData.user) {
            console.error('❌ Invalid user data received from PHP API');
            return res.status(401).json({ error: 'Invalid user data' });
        }
        
        console.log(`✅ JWT Token verified for user ${userData.user.id} (${userData.user.email})`);
        req.userId = userData.user.id;
        req.token = token;
        req.user = userData.user;
        req.authType = 'jwt';
        next();
    } catch (error) {
        console.error('❌ JWT Auth verification failed:', error.message);
        console.error('   Error details:', error.response?.data || error.message);
        
        // Check if it's a token signature error specifically
        if (error.message.includes('signature') || error.message.includes('Invalid token')) {
            return res.status(401).json({ 
                error: 'Invalid token signature',
                details: 'Please log out and log in again'
            });
        }
        
        return res.status(401).json({ error: 'Authentication failed' });
    }
}

// NEW: Middleware to verify API tokens (for external API calls)
async function verifyApiToken(req, res, next) {
    const token = extractToken(req);
    
    if (!token) {
        console.error('❌ No API token provided');
        return res.status(401).json({ error: 'API token required' });
    }

    try {
        console.log(`🔑 Verifying API token for request: ${req.method} ${req.path}`);
        console.log(`   Token preview: ${token.substring(0, 10)}...`);
        
        // Verify API token by calling PHP API
        const result = await callPHPAPI('/tokens/verify', 'POST', { token });
        
        if (!result || !result.valid) {
            console.error('❌ Invalid API token');
            return res.status(401).json({ error: 'Invalid or expired API token' });
        }
        
        console.log(`✅ API Token verified for user ${result.user_id}`);
        req.userId = result.user_id;
        req.token = token;
        req.apiTokenData = result;
        req.authType = 'api_token';
        
        // Update token usage stats
        try {
            await callPHPAPI('/tokens/update-usage', 'POST', { token });
        } catch (error) {
            console.error('Warning: Failed to update token usage:', error.message);
        }
        
        next();
    } catch (error) {
        console.error('❌ API Token verification failed:', error.message);
        console.error('   Error details:', error.response?.data || error.message);
        
        return res.status(401).json({ 
            error: 'Invalid API token',
            details: error.response?.data?.error || 'Token verification failed'
        });
    }
}

// NEW: Combined middleware - accepts both JWT and API tokens
async function verifyAnyToken(req, res, next) {
    const token = extractToken(req);
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication token required' });
    }

    // Check token length to determine type
    // JWT tokens are much longer (3 parts separated by dots)
    // API tokens are typically 64 characters (sha256 hash)
    
    const isJWT = token.includes('.') && token.split('.').length === 3;
    
    if (isJWT) {
        console.log('🔑 Detected JWT token, using JWT auth');
        return verifyAuth(req, res, next);
    } else {
        console.log('🔑 Detected API token, using API token auth');
        return verifyApiToken(req, res, next);
    }
}

// Request logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
});

// Health check
app.get('/api/health', (req, res) => {
    res.status(200).json({ 
        status: 'ok',
        message: 'WhatsApp Server is running',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        activeClients: clients.size,
        environment: NODE_ENV
    });
});

// Token validation routes
app.post('/api/auth/validate-token', async (req, res) => {
    try {
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({ error: 'Token is required' });
        }

        const result = await callPHPAPI('/auth/token/validate', 'POST', { token });
        res.json(result);
    } catch (error) {
        res.status(401).json({ error: error.message });
    }
});

app.post('/api/auth/store-token', verifyAuth, async (req, res) => {
    try {
        const { deviceInfo } = req.body;
        
        const result = await callPHPAPI('/auth/token/store', 'POST', { 
            device_info: deviceInfo || 'Web Browser' 
        }, req.token);
        
        res.json(result);
    } catch (error) {
        console.error('Error storing token:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/auth/remove-token', verifyAuth, async (req, res) => {
    try {
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({ error: 'Token is required' });
        }

        const result = await callPHPAPI('/auth/token/remove', 'POST', { token }, req.token);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Helper to safely delete auth folder
async function safeDeleteAuthFolder(authPath, maxRetries = 5, delay = 1000) {
    for (let i = 0; i < maxRetries; i++) {
        try {
            if (fs.existsSync(authPath)) {
                await new Promise(resolve => setTimeout(resolve, delay));
                
                fs.rmSync(authPath, { 
                    recursive: true, 
                    force: true,
                    maxRetries: 3,
                    retryDelay: 500
                });
                
                console.log(`✓ Successfully deleted auth data: ${authPath}`);
                return true;
            }
            return true;
        } catch (error) {
            if (i === maxRetries - 1) {
                console.error(`✗ Failed to delete auth folder after ${maxRetries} attempts:`, error.message);
                return false;
            }
            console.log(`↻ Retry ${i + 1}/${maxRetries} to delete auth folder...`);
            await new Promise(resolve => setTimeout(resolve, delay * (i + 1)));
        }
    }
    return false;
}

// Helper to check if auth folder exists and has valid session
function hasValidAuthSession(userId) {
    const authPath = path.join('./auth_data', `session-user-${userId}`);
    return fs.existsSync(authPath);
}

// Helper to clean stale auth data
async function cleanStaleAuthData(userId) {
    const authPath = path.join('./auth_data', `session-user-${userId}`);
    if (fs.existsSync(authPath)) {
        console.log(`🧹 Cleaning stale auth data for user ${userId}`);
        await safeDeleteAuthFolder(authPath);
    }
}
function configureClientHeartbeat(client, userId, token) {
    let heartbeatInterval = null;
    let reconnectAttempts = 0;
    const MAX_RECONNECT_ATTEMPTS = 5;
    let isDestroyed = false; // Track if client is being destroyed

    // Send periodic keep-alive pings with proper error handling
    const startHeartbeat = () => {
        // Clear any existing interval
        if (heartbeatInterval) {
            clearInterval(heartbeatInterval);
        }

        heartbeatInterval = setInterval(async () => {
            // Skip if client is destroyed
            if (isDestroyed) {
                stopHeartbeat();
                return;
            }

            try {
                // Check if client exists and browser is alive
                if (!client || !client.pupBrowser || client.pupBrowser.process?.killed) {
                    console.log(`⚠️ Heartbeat: Client or browser not available for user ${userId}`);
                    stopHeartbeat();
                    return;
                }

                // Safely check state with timeout
                const statePromise = client.getState();
                const timeoutPromise = new Promise((_, reject) => 
                    setTimeout(() => reject(new Error('State check timeout')), 5000)
                );

                const state = await Promise.race([statePromise, timeoutPromise]);
                
                if (state === 'CONNECTED') {
                    console.log(`💓 Heartbeat - Client alive for user ${userId}`);
                    reconnectAttempts = 0; // Reset on successful ping
                } else if (state !== 'CONNECTING') {
                    console.warn(`⚠️ Heartbeat detected disconnected state: ${state}`);
                }
            } catch (error) {
                // Only log non-navigation errors
                if (!error.message.includes('Execution context was destroyed') &&
                    !error.message.includes('navigation') &&
                    !error.message.includes('Session closed')) {
                    console.error(`❌ Heartbeat error for user ${userId}:`, error.message);
                } else {
                    console.log(`⚠️ Heartbeat stopped due to page navigation for user ${userId}`);
                    stopHeartbeat();
                }
            }
        }, 30000); // Check every 30 seconds

        return heartbeatInterval;
    };

    const stopHeartbeat = () => {
        if (heartbeatInterval) {
            clearInterval(heartbeatInterval);
            heartbeatInterval = null;
            console.log(`🛑 Heartbeat stopped for user ${userId}`);
        }
    };

    // Handle connection loss with auto-reconnect
    client.on('auth_failure', async (msg) => {
        console.error(`❌ Auth failure for user ${userId}:`, msg);
        isDestroyed = true;
        stopHeartbeat();
        clientInitializing.delete(userId);
        qrCodes.delete(userId);
        
        // Wait before cleaning auth data
        setTimeout(async () => {
            await cleanStaleAuthData(userId);
        }, 2000);
    });

    client.on('disconnected', async (reason) => {
        console.log(`🔌 Client disconnected for user ${userId}. Reason: ${reason}`);
        isDestroyed = true;
        stopHeartbeat();
        
        try {
            // Update database first
            await callPHPAPI('/whatsapp/session/disconnect', 'POST', {}, token);
            
            // Clean up in-memory state
            qrCodes.delete(userId);
            clients.delete(userId);
            clientInitializing.delete(userId);
            
            console.log(`🧹 Session data cleared for user ${userId} after disconnect`);
            
            // Clean auth data after a delay to ensure client is fully destroyed
            setTimeout(async () => {
                await cleanStaleAuthData(userId);
            }, 3000);
        } catch (error) {
            console.error(`❌ Error cleaning up after disconnect for user ${userId}:`, error.message);
        }
    });

    // Handle page navigation/logout
    client.on('change_state', (state) => {
        console.log(`🔄 State change for user ${userId}: ${state}`);
        if (state === 'CONFLICT' || state === 'UNPAIRED') {
            console.log(`⚠️ Client conflict/unpaired for user ${userId}, stopping heartbeat`);
            isDestroyed = true;
            stopHeartbeat();
        }
    });

    // Start heartbeat after successful connection
    client.on('ready', async () => {
        const info = client.info;
        try {
            await callPHPAPI('/whatsapp/session/update', 'POST', {
                phone_number: info.wid.user,
                pushname: info.pushname,
                is_active: true
            }, token);
            
            // Only start heartbeat if not destroyed
            if (!isDestroyed) {
                startHeartbeat();
                console.log(`✅ Client ready with heartbeat started for user ${userId}: ${info.pushname}`);
            }
        } catch (error) {
            console.error('❌ Error updating session:', error.message);
        }
    });

    // Override destroy method to set flag
    const originalDestroy = client.destroy.bind(client);
    client.destroy = async function() {
        isDestroyed = true;
        stopHeartbeat();
        return originalDestroy();
    };

    return { startHeartbeat, stopHeartbeat };
}
// Initialize WhatsApp Client
async function initializeClientForUser(userId, token, forceNew = false) {
    if (clientInitializing.get(userId)) {
        console.log(`⏳ Client already initializing for user ${userId}, waiting...`);
        let attempts = 0;
        while (clientInitializing.get(userId) && attempts < 30) {
            await new Promise(resolve => setTimeout(resolve, 1000));
            attempts++;
        }
        return clients.get(userId) || null;
    }

    clientInitializing.set(userId, true);
    console.log(`🔄 Starting client initialization for user ${userId} (forceNew: ${forceNew})`);

    if (forceNew) {
        console.log(`🧹 Force cleaning auth data for user ${userId}`);
        await cleanStaleAuthData(userId);
        
        await new Promise(resolve => setTimeout(resolve, 500));
        const authPath = path.join('./auth_data', `session-user-${userId}`);
        if (fs.existsSync(authPath)) {
            console.log(`⚠️ Auth data still exists, force deleting again...`);
            try {
                fs.rmSync(authPath, { recursive: true, force: true, maxRetries: 3 });
            } catch (error) {
                console.error(`✗ Failed to force delete: ${error.message}`);
            }
        }
    }

    try {
        const client = new Client({
            authStrategy: new LocalAuth({ 
                dataPath: './auth_data',
                clientId: `user-${userId}`
            }),
            puppeteer: {
                headless: true,
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-zygote',
                    '--single-process',
                    '--disable-gpu',
                    '--disable-web-resources'  // NEW: Prevent resource timeouts
                ]
            }
        });

        let qrGenerated = false;
        let authenticated = false;

        client.on('qr', async (qr) => {
            qrGenerated = true;
            const qrData = await qrcode.toDataURL(qr);
            qrCodes.set(userId, qrData);
            console.log(`📱 QR Code generated for user ${userId}`);
        });

        client.on('authenticated', async () => {
            authenticated = true;
            console.log(`✓ User ${userId} authenticated`);
            qrCodes.delete(userId);
        });

        // CONFIGURE HEARTBEAT AND EVENT HANDLERS
        const { startHeartbeat, stopHeartbeat } = configureClientHeartbeat(client, userId, token);

        client.on('message', async (message) => {
            try {
                const contact = await message.getContact();
                const myInfo = client.info;

                await callPHPAPI('/stats/update', 'POST', {
                    field: 'received',
                    increment: 1
                }, token);

                const hasMedia = message.hasMedia;
                let mediaType = null;
                let mediaUrl = null;

                if (hasMedia) {
                    try {
                        const media = await message.downloadMedia();
                        if (media) {
                            mediaType = media.mimetype.split('/')[0];
                            const extension = media.mimetype.split('/')[1] || 'bin';
                            const filename = `${Date.now()}_${message.id.id}.${extension}`;
                            const filepath = path.join('uploads', filename);
                            fs.writeFileSync(filepath, media.data, 'base64');
                            mediaUrl = `/uploads/${filename}`;
                        }
                    } catch (mediaError) {
                        console.error('✗ Error downloading media:', mediaError);
                    }
                }

                await callPHPAPI('/messages/save', 'POST', {
                    message_id: message.id.id,
                    type: 'received',
                    from_number: contact.number,
                    from_name: contact.name || contact.pushname || contact.number,
                    to_number: myInfo.wid.user,
                    to_name: myInfo.pushname,
                    message_body: message.body || null,
                    has_media: hasMedia,
                    media_type: mediaType,
                    media_url: mediaUrl,
                    status: 'received',
                    timestamp: message.timestamp
                }, token);

                console.log(`✓ Message saved for user ${userId}`);
            } catch (error) {
                console.error('✗ Error saving received message:', error);
            }
        });

        console.log(`🚀 Initializing WhatsApp client for user ${userId}...`);
        await client.initialize();
        
        let waitTime = 0;
        while (waitTime < 15000 && !qrGenerated && !authenticated) {
            await new Promise(resolve => setTimeout(resolve, 500));
            waitTime += 500;
        }
        
        try {
            const state = await client.getState();
            console.log(`📊 Client state after initialization for user ${userId}: ${state}`);
            
            if (state === 'CONNECTED' && !qrGenerated && forceNew) {
                console.error(`❌ ERROR: Client connected without QR despite forceNew! This should not happen.`);
                console.log(`🔄 Destroying and retrying...`);
                
                await client.destroy();
                stopHeartbeat();
                await cleanStaleAuthData(userId);
                clientInitializing.delete(userId);
                
                await new Promise(resolve => setTimeout(resolve, 2000));
                
                const authPath = path.join('./auth_data', `session-user-${userId}`);
                if (fs.existsSync(authPath)) {
                    const parentDir = path.join('./auth_data');
                    const sessionDirs = fs.readdirSync(parentDir).filter(f => f.includes(`user-${userId}`));
                    sessionDirs.forEach(dir => {
                        const fullPath = path.join(parentDir, dir);
                        console.log(`🧹 Removing: ${fullPath}`);
                        fs.rmSync(fullPath, { recursive: true, force: true, maxRetries: 5 });
                    });
                }
                
                return await initializeClientForUser(userId, token, forceNew);
            }
            
            if (!qrGenerated && state !== 'CONNECTED') {
                console.log(`⏳ Waiting for QR code generation for user ${userId}...`);
            }
            
        } catch (error) {
            console.log(`✗ Error checking state: ${error.message}`);
        }
        
        clients.set(userId, client);
        clientInitializing.delete(userId);
        console.log(`✓ Client successfully initialized for user ${userId}`);
        
        return client;
    } catch (error) {
        console.error(`✗ Error initializing client for user ${userId}:`, error);
        clientInitializing.delete(userId);
        await cleanStaleAuthData(userId);
        throw error;
    }
}

// WhatsApp Routes
app.post('/api/whatsapp/initialize', verifyAuth, async (req, res) => {
    try {
        console.log(`📱 Initialize request for user ${req.userId}`);
        
        // ALWAYS destroy existing client first to force fresh connection
        if (clients.has(req.userId)) {
            const client = clients.get(req.userId);
            console.log(`🧹 Destroying existing client for user ${req.userId} to force fresh connection`);
            try {
                await client.destroy();
            } catch (error) {
                console.log(`✗ Error destroying client: ${error.message}`);
            }
            clients.delete(req.userId);
        }

        // Clean any QR codes
        qrCodes.delete(req.userId);
        clientInitializing.delete(req.userId);

        // Check database session and clean it
        try {
            const session = await callPHPAPI('/whatsapp/session/get', 'GET', null, req.token);
            if (session?.is_active) {
                console.log(`🧹 Cleaning database session for user ${req.userId}`);
                await callPHPAPI('/whatsapp/session/disconnect', 'POST', {}, req.token);
            }
        } catch (error) {
            console.log(`No database session to clean for user ${req.userId}`);
        }

        // ALWAYS clean auth data to force QR generation
        console.log(`🧹 Cleaning auth data for user ${req.userId} to force QR generation`);
        await cleanStaleAuthData(req.userId);

        // Wait a moment for cleanup to complete
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Now initialize fresh client
        console.log(`🔄 Starting FRESH WhatsApp initialization for user ${req.userId}`);
        await initializeClientForUser(req.userId, req.token, true);
        
        res.json({ 
            success: true, 
            message: 'WhatsApp client initializing, please scan QR code' 
        });
    } catch (error) {
        console.error('✗ Initialize error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/whatsapp/qr', verifyAuth, async (req, res) => {
    try {
        const client = clients.get(req.userId);
        
        // Check actual client state
        if (client) {
            try {
                const state = await client.getState();
                console.log(`QR request - Client state for user ${req.userId}: ${state}`);
                
                if (state === 'CONNECTED') {
                    const session = await callPHPAPI('/whatsapp/session/get', 'GET', null, req.token);
                    return res.json({ 
                        qr: null, 
                        ready: true, 
                        session 
                    });
                }
            } catch (error) {
                console.log(`✗ Error checking client state: ${error.message}`);
            }
        }

        const qr = qrCodes.get(req.userId);
        console.log(`QR code ${qr ? 'exists' : 'does not exist'} for user ${req.userId}`);
        
        res.json({ 
            qr: qr || null, 
            ready: false,
            session: null
        });
    } catch (error) {
        console.error('✗ QR fetch error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/whatsapp/status', verifyAuth, async (req, res) => {
    try {
        const client = clients.get(req.userId);
        let isConnected = false;
        let clientState = 'NONE';
        
        if (client) {
            try {
                clientState = await client.getState();
                isConnected = clientState === 'CONNECTED';
                console.log(`Status check - Client state for user ${req.userId}: ${clientState}`);
            } catch (error) {
                console.log(`✗ Error checking client state: ${error.message}`);
                clients.delete(req.userId);
            }
        }

        let session = null;
        try {
            session = await callPHPAPI('/whatsapp/session/get', 'GET', null, req.token);
        } catch (error) {
            // Session doesn't exist, that's ok
        }
        
        // If DB says connected but client isn't, clean up DB
        if (session?.is_active && !isConnected) {
            console.log(`🧹 Cleaning stale DB session for user ${req.userId}`);
            try {
                await callPHPAPI('/whatsapp/session/disconnect', 'POST', {}, req.token);
            } catch (error) {
                console.error('✗ Error cleaning stale session:', error);
            }
            
            return res.json({
                connected: false,
                session: null,
                clientActive: false,
                clientState
            });
        }
        
        res.json({
            connected: isConnected && session?.is_active,
            session: session || null,
            clientActive: isConnected,
            clientState
        });
    } catch (error) {
        console.error('✗ Status check error:', error.message);
        
        if (error.message.includes('401') || error.message.includes('Invalid token') || error.message.includes('Unauthorized')) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/whatsapp/disconnect', verifyAuth, async (req, res) => {
    try {
        console.log(`🔌 Disconnect request for user ${req.userId}`);
        
        const client = clients.get(req.userId);
        
        if (client) {
            try {
                await client.destroy();
                console.log(`✓ Client destroyed for user ${req.userId}`);
            } catch (destroyError) {
                console.error('✗ Error destroying client:', destroyError.message);
            }
            
            clients.delete(req.userId);
        }

        qrCodes.delete(req.userId);
        clientInitializing.delete(req.userId);

        try {
            await callPHPAPI('/whatsapp/session/disconnect', 'POST', {}, req.token);
        } catch (error) {
            console.error('✗ Error updating DB session:', error);
        }

        console.log(`✓ WhatsApp disconnected for user ${req.userId}`);
        
        // Clean auth data immediately
        await cleanStaleAuthData(req.userId);
        
        res.json({ 
            success: true, 
            message: 'WhatsApp disconnected successfully' 
        });
        
    } catch (error) {
        console.error('✗ Error disconnecting WhatsApp:', error);
        res.status(500).json({ error: error.message });
    }
});

// Manual cleanup endpoint - IMPORTANT for debugging
app.post('/api/whatsapp/force-cleanup', verifyAuth, async (req, res) => {
    try {
        console.log(`🧹 Force cleanup requested for user ${req.userId}`);
        
        // Destroy client if exists
        if (clients.has(req.userId)) {
            const client = clients.get(req.userId);
            try {
                await client.destroy();
            } catch (error) {
                console.log(`Error destroying client: ${error.message}`);
            }
            clients.delete(req.userId);
        }
        
        // Clear all state
        qrCodes.delete(req.userId);
        clientInitializing.delete(req.userId);
        
        // Update database
        try {
            await callPHPAPI('/whatsapp/session/disconnect', 'POST', {}, req.token);
        } catch (error) {
            console.log(`Error updating DB: ${error.message}`);
        }
        
        // Force clean auth data
        await cleanStaleAuthData(req.userId);
        
        // Double check and force delete
        await new Promise(resolve => setTimeout(resolve, 1000));
        const authPath = path.join('./auth_data', `session-user-${req.userId}`);
        if (fs.existsSync(authPath)) {
            console.log(`🧹 Auth data still exists, force removing...`);
            fs.rmSync(authPath, { recursive: true, force: true, maxRetries: 5 });
        }
        
        // Check all session directories for this user
        const parentDir = path.join('./auth_data');
        if (fs.existsSync(parentDir)) {
            const allDirs = fs.readdirSync(parentDir);
            const userDirs = allDirs.filter(d => d.includes(`user-${req.userId}`));
            console.log(`Found ${userDirs.length} directories for user ${req.userId}`);
            
            userDirs.forEach(dir => {
                const fullPath = path.join(parentDir, dir);
                console.log(`🧹 Removing: ${fullPath}`);
                try {
                    fs.rmSync(fullPath, { recursive: true, force: true, maxRetries: 5 });
                } catch (error) {
                    console.error(`Failed to remove ${fullPath}:`, error.message);
                }
            });
        }
        
        res.json({
            success: true,
            message: 'Complete cleanup performed',
            cleaned: {
                client: true,
                qrCode: true,
                initializing: true,
                database: true,
                authData: true
            }
        });
    } catch (error) {
        console.error('✗ Force cleanup error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Messaging Routes - Accept both JWT and API tokens
app.post('/api/send-message', verifyAnyToken, async (req, res) => {
    try {
        const { number, message } = req.body;
        
        if (!number || !message) {
            return res.status(400).json({ error: 'Number and message are required' });
        }
        
        const client = clients.get(req.userId);

        if (!client) {
            return res.status(400).json({ 
                error: 'WhatsApp not connected',
                details: 'Please connect your WhatsApp first'
            });
        }

        const state = await client.getState();
        if (state !== 'CONNECTED') {
            return res.status(400).json({ error: 'WhatsApp not ready to send messages' });
        }

        const chatId = number.includes('@c.us') ? number : `${number}@c.us`;
        
        console.log(`📤 Sending message to ${chatId} for user ${req.userId} (Auth: ${req.authType})`);
        const sentMessage = await client.sendMessage(chatId, message);
        console.log(`✓ Message sent successfully: ${sentMessage.id.id}`);

        let contactName = number;
        try {
            const contact = await client.getContactById(chatId);
            contactName = contact.name || contact.pushname || number;
        } catch (err) {
            console.log('Could not get contact name:', err.message);
        }

        const myInfo = client.info;

        // Use API token if available, otherwise use JWT
        const authToken = req.authType === 'api_token' ? req.token : req.token;

        const savedMessage = await callPHPAPI('/messages/save', 'POST', {
            message_id: sentMessage.id.id,
            type: 'sent',
            from_number: myInfo.wid.user,
            from_name: myInfo.pushname,
            to_number: number,
            to_name: contactName,
            message_body: message,
            has_media: false,
            status: 'sent',
            timestamp: sentMessage.timestamp
        }, authToken);

        await callPHPAPI('/stats/update', 'POST', {
            field: 'sent',
            increment: 1
        }, authToken);

        res.json({ 
            success: true, 
            message: 'Message sent successfully',
            messageId: sentMessage.id.id,
            dbId: savedMessage.id
        });
    } catch (error) {
        console.error('✗ Error sending message:', error);
        
        try {
            const authToken = req.authType === 'api_token' ? req.token : req.token;
            await callPHPAPI('/stats/update', 'POST', {
                field: 'failed',
                increment: 1
            }, authToken);
        } catch (e) {}
        
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/send-media', verifyAnyToken, upload.single('file'), async (req, res) => {
    try {
        const { number, caption } = req.body;
        
        if (!number) {
            return res.status(400).json({ error: 'Number is required' });
        }
        
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        const client = clients.get(req.userId);

        if (!client) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const chatId = number.includes('@c.us') ? number : `${number}@c.us`;
        const media = MessageMedia.fromFilePath(req.file.path);
        
        console.log(`📤 Sending media to ${chatId} for user ${req.userId} (Auth: ${req.authType})`);
        const sentMessage = await client.sendMessage(chatId, media, { caption });
        console.log(`✓ Media sent successfully: ${sentMessage.id.id}`);

        let contactName = number;
        try {
            const contact = await client.getContactById(chatId);
            contactName = contact.name || contact.pushname || number;
        } catch (err) {
            console.log('Could not get contact name:', err.message);
        }

        const myInfo = client.info;
        const mediaType = req.file.mimetype.split('/')[0];
        const authToken = req.authType === 'api_token' ? req.token : req.token;

        const savedMessage = await callPHPAPI('/messages/save', 'POST', {
            message_id: sentMessage.id.id,
            type: 'sent',
            from_number: myInfo.wid.user,
            from_name: myInfo.pushname,
            to_number: number,
            to_name: contactName,
            message_body: caption || null,
            has_media: true,
            media_type: mediaType,
            media_url: `/uploads/${req.file.filename}`,
            status: 'sent',
            timestamp: sentMessage.timestamp
        }, authToken);

        await callPHPAPI('/stats/update', 'POST', {
            field: 'sent',
            increment: 1
        }, authToken);

        res.json({ 
            success: true, 
            message: 'Media sent successfully',
            messageId: sentMessage.id.id,
            dbId: savedMessage.id
        });
    } catch (error) {
        console.error('✗ Error sending media:', error);
        
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        
        try {
            const authToken = req.authType === 'api_token' ? req.token : req.token;
            await callPHPAPI('/stats/update', 'POST', {
                field: 'failed',
                increment: 1
            }, authToken);
        } catch (e) {}
        
        res.status(500).json({ success: false, error: error.message });
    }
});

// Public endpoints - only accept API tokens
app.get('/api/chats', verifyApiToken, async (req, res) => {
    try {
        const client = clients.get(req.userId);
        if (!client) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const chats = await client.getChats();
        const chatList = chats.map(chat => ({
            id: chat.id._serialized,
            name: chat.name,
            isGroup: chat.isGroup,
            unreadCount: chat.unreadCount
        }));
        res.json(chatList);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/contacts', verifyApiToken, async (req, res) => {
    try {
        const client = clients.get(req.userId);
        if (!client) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const contacts = await client.getContacts();
        const contactList = contacts
            .filter(c => c.isMyContact && !c.isGroup)
            .map(c => ({
                id: c.id._serialized,
                name: c.name || c.pushname,
                number: c.number
            }));
        res.json(contactList);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Proxy routes to PHP API
app.post('/api/auth/register', async (req, res) => {
    try {
        const result = await callPHPAPI('/auth/register', 'POST', req.body);
        res.json(result);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const result = await callPHPAPI('/auth/login', 'POST', req.body);
        res.json(result);
    } catch (error) {
        res.status(401).json({ error: error.message });
    }
});

app.get('/api/auth/me', verifyAuth, async (req, res) => {
    try {
        const result = await callPHPAPI('/auth/me', 'GET', null, req.token);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/messages', verifyAuth, async (req, res) => {
    try {
        const result = await callPHPAPI(
            `/messages/list?type=${req.query.type || 'all'}&search=${req.query.search || ''}&limit=${req.query.limit || 50}&offset=${req.query.offset || 0}`,
            'GET',
            null,
            req.token
        );
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/messages/:id', verifyAuth, async (req, res) => {
    try {
        const result = await callPHPAPI(`/messages/${req.params.id}`, 'DELETE', null, req.token);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/messages', verifyAuth, async (req, res) => {
    try {
        const result = await callPHPAPI('/messages/clear', 'DELETE', null, req.token);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/stats', verifyAuth, async (req, res) => {
    try {
        const result = await callPHPAPI('/stats/get', 'GET', null, req.token);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/tokens/generate', verifyAuth, async (req, res) => {
    try {
        const result = await callPHPAPI('/tokens/generate', 'POST', req.body, req.token);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/tokens', verifyAuth, async (req, res) => {
    try {
        const result = await callPHPAPI('/tokens/list', 'GET', null, req.token);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/tokens/:id', verifyAuth, async (req, res) => {
    try {
        const result = await callPHPAPI(`/tokens/${req.params.id}`, 'DELETE', null, req.token);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/status', verifyAuth, async (req, res) => {
    try {
        const client = clients.get(req.userId);
        let isConnected = false;
        
        if (client) {
            const state = await client.getState();
            isConnected = state === 'CONNECTED';
        }
        
        const session = await callPHPAPI('/whatsapp/session/get', 'GET', null, req.token);
        const stats = await callPHPAPI('/stats/get', 'GET', null, req.token);
        
        res.json({
            ready: isConnected && session?.is_active,
            session: session || null,
            stats
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Cleanup on server shutdown
process.on('SIGTERM', async () => {
    console.log('🛑 SIGTERM received, cleaning up...');
    for (const [userId, client] of clients.entries()) {
        try {
            await client.destroy();
            console.log(`✓ Destroyed client for user ${userId}`);
        } catch (error) {
            console.error(`✗ Error destroying client for user ${userId}:`, error);
        }
    }
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('🛑 SIGINT received, cleaning up...');
    for (const [userId, client] of clients.entries()) {
        try {
            await client.destroy();
            console.log(`✓ Destroyed client for user ${userId}`);
        } catch (error) {
            console.error(`✗ Error destroying client for user ${userId}:`, error);
        }
    }
    process.exit(0);
});

app.listen(PORT, () => {
    console.log(`✓ WhatsApp Server running on port ${PORT}`);
    console.log(`✓ Environment: ${NODE_ENV}`);
    console.log(`✓ PHP API URL: ${PHP_API_URL}`);
    console.log(`✓ Frontend URL: ${FRONTEND_URL}`);
    console.log(`✓ Server ready to accept connections`);
});