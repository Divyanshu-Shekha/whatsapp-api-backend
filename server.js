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
// const PHP_API_URL = process.env.PHP_API_URL || 'http://localhost/whatsapp-api/api.php';
// const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
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
// WhatsApp Client Management
const clients = new Map();
const qrCodes = new Map();
const clientInitializing = new Map();
const initializationPromises = new Map(); // NEW: Track ongoing initialization promises
const eventListenersAttached = new Map(); // NEW: Track if listeners are already attached
const deviceTokens = new Map(); // Map of token -> {userId, phoneNumber, deviceId}
const userDevices = new Map(); // Map of userId -> [deviceIds]

// Key improvements in server.js:

// 1. Add token caching to reduce database calls
const tokenCache = new Map();
const TOKEN_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Helper to cache tokens
function cacheToken(token, userData) {
  tokenCache.set(token, {
    data: userData,
    timestamp: Date.now()
  });
  
  // Clear cache after TTL
  setTimeout(() => {
    tokenCache.delete(token);
  }, TOKEN_CACHE_TTL);
}

function getCachedToken(token) {
  const cached = tokenCache.get(token);
  if (!cached) return null;
  
  // Check if cache is still valid
  if (Date.now() - cached.timestamp > TOKEN_CACHE_TTL) {
    tokenCache.delete(token);
    return null;
  }
  
  return cached.data;
}


// Helper function to call PHP API
async function callPHPAPI(endpoint, method = 'GET', data = null, token = null, retries = 2) {
    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
            const config = {
                method,
                url: `${PHP_API_URL}${endpoint}`,
                headers: {
                    'Content-Type': 'application/json'
                },
                timeout: 15000 // Increased timeout
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
            // Don't retry on auth errors
            if (error.response?.status === 401 || error.response?.status === 403) {
                throw error;
            }
            
            // Retry on network errors or 500s
            if (attempt < retries && (!error.response || error.response.status >= 500)) {
                console.log(`Retrying PHP API call (${attempt + 1}/${retries})...`);
                await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)));
                continue;
            }
            
            if (error.response) {
                const phpError = new Error(error.response.data.error || `PHP API error: ${error.response.status}`);
                phpError.status = error.response.status;
                throw phpError;
            }
            throw error;
        }
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
        return res.status(401).json({ 
            error: 'No token provided',
            code: 'NO_TOKEN'
        });
    }

    try {
        // Check cache first
        const cachedData = getCachedToken(token);
        if (cachedData) {
            console.log(`✅ Using cached token data for user ${cachedData.user.id}`);
            req.userId = cachedData.user.id;
            req.token = token;
            req.user = cachedData.user;
            req.authType = 'jwt';
            return next();
        }
        
        console.log(`🔑 Verifying JWT token for request: ${req.method} ${req.path}`);
        
        // Verify token by calling PHP API
        const userData = await callPHPAPI('/auth/me', 'GET', null, token);
        
        if (!userData || !userData.user) {
            console.error('❌ Invalid user data received from PHP API');
            return res.status(401).json({ 
                error: 'Invalid user data',
                code: 'INVALID_USER_DATA'
            });
        }
        
        // Cache the token
        cacheToken(token, userData);
        
        console.log(`✅ JWT Token verified for user ${userData.user.id} (${userData.user.email})`);
        req.userId = userData.user.id;
        req.token = token;
        req.user = userData.user;
        req.authType = 'jwt';
        next();
    } catch (error) {
        console.error('❌ JWT Auth verification failed:', error.message);
        
        // Clear token from cache on error
        tokenCache.delete(token);
        
        // Provide specific error codes
        if (error.message.includes('signature') || error.message.includes('Invalid token')) {
            return res.status(401).json({ 
                error: 'Invalid token signature',
                code: 'INVALID_SIGNATURE',
                details: 'Please log out and log in again'
            });
        }
        
        if (error.message.includes('expired') || error.message.includes('jwt expired')) {
            return res.status(401).json({ 
                error: 'Token expired',
                code: 'TOKEN_EXPIRED',
                details: 'Your session has expired. Please login again.'
            });
        }
        
        return res.status(401).json({ 
            error: 'Authentication failed',
            code: 'AUTH_FAILED'
        });
    }
}


// NEW: Middleware to verify API tokens (for external API calls)
async function verifyApiToken(req, res, next) {
    const token = extractToken(req);
    
    if (!token) {
        console.error('❌ No API token provided');
        return res.status(401).json({ 
            error: 'API token required',
            code: 'NO_TOKEN'
        });
    }

    try {
        // Check cache first
        const cachedData = getCachedToken(`api_${token}`);
        if (cachedData) {
            console.log(`✅ Using cached API token data for user ${cachedData.user_id}`);
            req.userId = cachedData.user_id;
            req.token = token;
            req.apiTokenData = cachedData;
            req.authType = 'api_token';
            return next();
        }
        
        console.log(`🔑 Verifying API token for request: ${req.method} ${req.path}`);
        
        // Verify API token by calling PHP API
        const result = await callPHPAPI('/tokens/verify', 'POST', { token });
        
        if (!result || !result.valid) {
            console.error('❌ Invalid API token');
            return res.status(401).json({ 
                error: 'Invalid or expired API token',
                code: 'INVALID_API_TOKEN'
            });
        }
        
        // Cache the API token
        cacheToken(`api_${token}`, result);
        
        console.log(`✅ API Token verified for user ${result.user_id}`);
        req.userId = result.user_id;
        req.token = token;
        req.apiTokenData = result;
        req.authType = 'api_token';
        
        // Update token usage stats (async, don't wait)
        callPHPAPI('/tokens/update-usage', 'POST', { token }).catch(err => {
            console.error('Warning: Failed to update token usage:', err.message);
        });
        
        next();
    } catch (error) {
        console.error('❌ API Token verification failed:', error.message);
        
        // Clear from cache
        tokenCache.delete(`api_${token}`);
        
        return res.status(401).json({ 
            error: 'Invalid API token',
            code: 'INVALID_API_TOKEN',
            details: error.response?.data?.error || 'Token verification failed'
        });
    }
}

// Initialize WhatsApp Client for Device
async function initializeClientForUser(userId, token, forceNew = false) {
    const clientKey = userId;
    
    if (initializationPromises.has(clientKey)) {
        console.log(`⏳ Client initialization already in progress for user ${userId}, reusing promise...`);
        return await initializationPromises.get(clientKey);
    }

    const initPromise = (async () => {
        try {
            clientInitializing.set(clientKey, true);
            console.log(`🔄 Starting client initialization for user ${userId}`);

            // Clean existing client if exists
            if (clients.has(clientKey)) {
                const oldClient = clients.get(clientKey);
                console.log(`🧹 Destroying existing client for user ${userId}`);
                try {
                    await oldClient.destroy();
                } catch (error) {
                    console.log(`Error destroying old client: ${error.message}`);
                }
                clients.delete(clientKey);
                eventListenersAttached.delete(clientKey);
            }

            // Clean QR code and state
            qrCodes.delete(clientKey);
            clientInitializing.delete(clientKey);

            // Clean auth data if forceNew
            if (forceNew) {
                console.log(`🧹 Force cleaning auth data for user ${userId}`);
                await cleanStaleAuthData(userId);
                // Wait a bit for cleanup to complete
                await new Promise(resolve => setTimeout(resolve, 2000));
            }

            console.log(`🚀 Creating new WhatsApp client for user ${userId}`);
            
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
                        '--disable-web-resources'
                    ]
                }
            });

            // QR Code handler
            client.once('qr', async (qr) => {
                console.log(`📱 QR Code received for user ${userId}`);
                try {
                    const qrData = await qrcode.toDataURL(qr);
                    qrCodes.set(clientKey, qrData);
                    console.log(`✅ QR Code generated and stored for user ${userId}`);
                } catch (qrError) {
                    console.error(`❌ Error generating QR code: ${qrError.message}`);
                }
            });

            // Authentication handler
            client.once('authenticated', async () => {
                console.log(`✅ User ${userId} authenticated successfully`);
                qrCodes.delete(clientKey);
            });

            // Ready handler
            client.once('ready', async () => {
                console.log(`✅ WhatsApp client ready for user ${userId}`);
                try {
                    const info = client.info;
                    console.log(`📱 Client info: ${info.pushname} (${info.wid.user})`);
                    
                    // Update session in database
                    await callPHPAPI('/whatsapp/session/update', 'POST', {
                        phone_number: info.wid.user,
                        pushname: info.pushname,
                        is_active: true
                    }, token);
                    
                    console.log(`✅ Database session updated for user ${userId}`);
                } catch (error) {
                    console.error(`❌ Error updating session: ${error.message}`);
                }
            });

            // Configure heartbeat
            configureClientHeartbeat(client, userId, token);

            console.log(`🚀 Initializing WhatsApp client...`);
            await client.initialize();
            console.log(`✅ Client initialization started for user ${userId}`);
            
            clients.set(clientKey, client);
            clientInitializing.delete(clientKey);
            
            // Wait a moment to see if we get a QR code or immediate connection
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            // Check initial state
            try {
                const state = await client.getState();
                console.log(`📊 Initial client state for user ${userId}: ${state}`);
            } catch (stateError) {
                console.log(`⚠️ Could not check initial state: ${stateError.message}`);
            }
            
            console.log(`✅ Client successfully initialized for user ${userId}`);
            
            return client;
        } catch (error) {
            console.error(`❌ Error initializing client for user ${userId}:`, error.message);
            
            // Clean up everything on error
            clientInitializing.delete(clientKey);
            initializationPromises.delete(clientKey);
            eventListenersAttached.delete(clientKey);
            
            // Force clean auth data on error
            try {
                await cleanStaleAuthData(userId);
            } catch (cleanError) {
                console.error(`Error cleaning auth data: ${cleanError.message}`);
            }
            
            throw error;
        }
    })();

    initializationPromises.set(clientKey, initPromise);

    initPromise.finally(() => {
        initializationPromises.delete(clientKey);
    });

    return await initPromise;
}

// Add Device - Associate token with phone number
app.get('/api/devices', verifyAuth, async (req, res) => {
    try {
        const devices = await callPHPAPI('/devices/list', 'GET', null, req.token);
        
        // Enhance with real-time connection status
        const enhancedDevices = devices.map(device => {
            const clientKey = `${req.userId}-${device.device_id}`;
            const isConnected = clients.has(clientKey);
            let clientState = 'DISCONNECTED';
            
            if (isConnected) {
                try {
                    const client = clients.get(clientKey);
                    // Don't await here, just check if client exists
                    clientState = 'CONNECTED';
                } catch (error) {
                    clientState = 'ERROR';
                }
            }
            
            return {
                ...device,
                isConnected,
                clientState
            };
        });

        res.json(enhancedDevices);
    } catch (error) {
        console.error('Get devices error:', error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/devices/add', verifyAuth, async (req, res) => {
    try {
        const { token, phoneNumber, deviceName } = req.body;
        
        if (!token || !phoneNumber) {
            return res.status(400).json({ error: 'Token and phone number are required' });
        }

        // Clean phone number
        const cleanNumber = phoneNumber.replace(/[^\d]/g, '');

        // Verify token exists in database and belongs to user
        const tokenData = await callPHPAPI('/tokens/verify', 'POST', { token }, req.token);
        
        if (!tokenData || !tokenData.valid || tokenData.user_id !== req.userId) {
            return res.status(400).json({ error: 'Invalid token or token does not belong to you' });
        }

        // Check if token is already assigned
        try {
            const existingDevice = await callPHPAPI('/devices/by-token', 'POST', { token }, req.token);
            if (existingDevice && existingDevice.id) {
                return res.status(400).json({ 
                    error: 'This token is already assigned to: ' + (existingDevice.device_name || existingDevice.device_id)
                });
            }
        } catch (error) {
            // Token not assigned - this is good
        }

        const deviceId = `device-${Date.now()}`;
        
        // Store device-token mapping in memory
        deviceTokens.set(token, {
            userId: req.userId,
            phoneNumber: cleanNumber,
            deviceId: deviceId,
            deviceName: deviceName || `Device ${cleanNumber}`,
            createdAt: new Date(),
            isActive: false
        });

        // Add to user's devices
        if (!userDevices.has(req.userId)) {
            userDevices.set(req.userId, []);
        }
        userDevices.get(req.userId).push(deviceId);

        // Save to database
        await callPHPAPI('/devices/add', 'POST', {
            device_id: deviceId,
            device_name: deviceName || `Device ${cleanNumber}`,
            phone_number: cleanNumber,
            token: token
        }, req.token);

        res.json({ 
            success: true, 
            deviceId,
            message: 'Device added successfully' 
        });
    } catch (error) {
        console.error('Add device error:', error);
        
        if (error.response?.data?.error) {
            return res.status(error.response.status || 500).json({ 
                error: error.response.data.error 
            });
        }
        
        res.status(500).json({ error: error.message });
    }
});

// Update device (for webhook URL, etc.)
app.post('/api/devices/:deviceId/update', verifyAuth, async (req, res) => {
    try {
        const { deviceId } = req.params;
        const { webhook_url, phone_number, pushname, is_active } = req.body;
        
        await callPHPAPI(`/devices/${deviceId}/update`, 'POST', {
            webhook_url,
            phone_number,
            pushname,
            is_active
        }, req.token);

        res.json({ 
            success: true, 
            message: 'Device updated successfully' 
        });
    } catch (error) {
        console.error('Update device error:', error);
        res.status(500).json({ error: error.message });
    }
});


// Get all devices for user
app.get('/api/devices', verifyAuth, async (req, res) => {
    try {
        const devices = await callPHPAPI('/devices/list', 'GET', null, req.token);
        
        // Enhance with connection status
        const enhancedDevices = devices.map(device => {
            const isConnected = clients.has(`${req.userId}-${device.device_id}`);
            return {
                ...device,
                isConnected,
                clientState: isConnected ? 'CONNECTED' : 'DISCONNECTED'
            };
        });

        res.json(enhancedDevices);
    } catch (error) {
        console.error('Get devices error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Initialize WhatsApp for specific device
app.post('/api/devices/:deviceId/initialize', verifyAuth, async (req, res) => {
    try {
        const { deviceId } = req.params;
        
        // Get device info from database
        const device = await callPHPAPI(`/devices/${deviceId}`, 'GET', null, req.token);
        
        if (!device) {
            return res.status(404).json({ error: 'Device not found' });
        }

        const clientKey = `${req.userId}-${deviceId}`;
        
        // Check if already initializing
        if (initializationPromises.has(clientKey)) {
            return res.status(409).json({ 
                error: 'Initialization already in progress',
                message: 'Please wait for the current initialization to complete'
            });
        }

        // Clean existing client
        if (clients.has(clientKey)) {
            const client = clients.get(clientKey);
            try {
                await client.destroy();
            } catch (error) {
                console.log(`Error destroying client: ${error.message}`);
            }
            clients.delete(clientKey);
            eventListenersAttached.delete(clientKey);
        }

        qrCodes.delete(clientKey);
        clientInitializing.delete(clientKey);

        // Clean auth data
        await cleanStaleAuthData(`${req.userId}-${deviceId}`);
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Initialize client for this device
        await initializeClientForDevice(req.userId, deviceId, device.phone_number, req.token, true);
        
        res.json({ 
            success: true, 
            message: 'Device initializing, please scan QR code',
            deviceId 
        });
    } catch (error) {
        console.error('Device initialize error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get QR code for specific device
app.get('/api/devices/:deviceId/qr', verifyAuth, async (req, res) => {
    try {
        const { deviceId } = req.params;
        const clientKey = `${req.userId}-${deviceId}`;
        
        const client = clients.get(clientKey);
        
        if (client) {
            try {
                const state = await client.getState();
                
                if (state === 'CONNECTED') {
                    const device = await callPHPAPI(`/devices/${deviceId}`, 'GET', null, req.token);
                    return res.json({ 
                        qr: null, 
                        ready: true, 
                        device 
                    });
                }
            } catch (error) {
                console.log(`Error checking client state: ${error.message}`);
            }
        }

        const qr = qrCodes.get(clientKey);
        
        res.json({ 
            qr: qr || null, 
            ready: false,
            deviceId
        });
    } catch (error) {
        console.error('QR fetch error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Disconnect specific device
app.post('/api/devices/:deviceId/disconnect', verifyAuth, async (req, res) => {
    try {
        const { deviceId } = req.params;
        const clientKey = `${req.userId}-${deviceId}`;
        
        const client = clients.get(clientKey);
        
        if (client) {
            await safeDestroyClient(client, clientKey);
        }

        clients.delete(clientKey);
        qrCodes.delete(clientKey);
        clientInitializing.delete(clientKey);
        initializationPromises.delete(clientKey);

        // Update database
        await callPHPAPI(`/devices/${deviceId}/disconnect`, 'POST', {}, req.token);

        // Clean auth data
        await cleanStaleAuthData(`${req.userId}-${deviceId}`);
        
        res.json({ 
            success: true, 
            message: 'Device disconnected successfully' 
        });
        
    } catch (error) {
        console.error('Device disconnect error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Delete device
app.delete('/api/devices/:deviceId', verifyAuth, async (req, res) => {
    try {
        const { deviceId } = req.params;
        const clientKey = `${req.userId}-${deviceId}`;
        
        // Disconnect if connected
        const client = clients.get(clientKey);
        if (client) {
            await safeDestroyClient(client, clientKey);
        }

        // Clean up
        clients.delete(clientKey);
        qrCodes.delete(clientKey);
        
        // Remove from database
        await callPHPAPI(`/devices/${deviceId}`, 'DELETE', null, req.token);

        res.json({ 
            success: true, 
            message: 'Device deleted successfully' 
        });
    } catch (error) {
        console.error('Delete device error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/auth/check-token', async (req, res) => {
    try {
        const token = extractToken(req);
        
        if (!token) {
            return res.json({ valid: false, reason: 'NO_TOKEN' });
        }
        
        // Check cache first
        const cachedData = getCachedToken(token);
        if (cachedData) {
            return res.json({ 
                valid: true, 
                user: cachedData.user,
                cached: true 
            });
        }
        
        // Verify with PHP API
        const result = await callPHPAPI('/auth/token/validate', 'POST', { token });
        
        if (result.valid) {
            cacheToken(token, result);
        }
        
        res.json(result);
    } catch (error) {
        console.error('Token check error:', error.message);
        res.json({ 
            valid: false, 
            reason: 'VERIFICATION_FAILED',
            error: error.message 
        });
    }
});
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
    const token = extractToken(req);
    const isAuthenticated = token && getCachedToken(token) !== null;
    
    res.status(200).json({ 
        status: 'ok',
        message: 'WhatsApp Server is running',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        activeClients: clients.size,
        cachedTokens: tokenCache.size,
        environment: NODE_ENV,
        authenticated: isAuthenticated
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
// Enhanced safe delete function with better resource handling
async function safeDeleteAuthFolder(authPath, maxRetries = 8, baseDelay = 1000) {
    if (!fs.existsSync(authPath)) {
        return true;
    }

    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            // First, try to close any Chrome processes that might be using these files
            if (process.platform === 'win32') {
                try {
                    const { execSync } = require('child_process');
                    // Kill any Chrome processes that might be locking files
                    execSync('taskkill /f /im chrome.exe /t 2>nul || taskkill /f /im chromedriver.exe /t 2>nul', { stdio: 'ignore' });
                } catch (e) {
                    // Ignore errors - processes might not exist
                }
            }

            // Wait with exponential backoff
            const delay = baseDelay * Math.pow(2, attempt);
            if (attempt > 0) {
                console.log(`⏳ Retry ${attempt}/${maxRetries} to delete auth folder (waiting ${delay}ms)...`);
                await new Promise(resolve => setTimeout(resolve, delay));
            }

            // Try to remove individual files first before the folder
            const files = fs.readdirSync(authPath);
            for (const file of files) {
                const filePath = path.join(authPath, file);
                try {
                    if (fs.statSync(filePath).isFile()) {
                        fs.unlinkSync(filePath);
                    } else {
                        fs.rmSync(filePath, { recursive: true, force: true });
                    }
                } catch (fileError) {
                    console.log(`⚠️ Could not delete ${filePath}: ${fileError.message}`);
                    // Continue with other files
                }
            }

            // Now try to delete the main folder
            fs.rmSync(authPath, { 
                recursive: true, 
                force: true,
                maxRetries: 3,
                retryDelay: 1000
            });
            
            console.log(`✅ Successfully deleted auth data: ${authPath}`);
            return true;

        } catch (error) {
            if (attempt === maxRetries - 1) {
                console.error(`❌ Failed to delete auth folder after ${maxRetries} attempts: ${error.message}`);
                
                // Mark for deletion on next startup
                try {
                    const cleanupMarker = path.join('./auth_data', `cleanup-needed-${Date.now()}`);
                    fs.writeFileSync(cleanupMarker, authPath);
                } catch (e) {}
                
                return false;
            }
        }
    }
    return false;
}
// Function to kill any lingering Chrome processes
async function killChromeProcesses() {
    if (process.platform !== 'win32') return;

    try {
        const { execSync } = require('child_process');
        
        // List of processes that might lock files
        const processes = ['chrome.exe', 'chromedriver.exe', 'node.exe'];
        
        for (const proc of processes) {
            try {
                execSync(`tasklist /fi "imagename eq ${proc}" | find /i "${proc}" >nul && (
                    taskkill /f /im ${proc} /t
                    echo Killed ${proc}
                ) || echo ${proc} not running`, { stdio: 'ignore', shell: true });
            } catch (e) {
                // Process might not exist, which is fine
            }
        }
        
        // Additional cleanup for Windows
        try {
            execSync('wmic process where "name=\'chrome.exe\'" delete 2>nul', { stdio: 'ignore' });
        } catch (e) {}
        
    } catch (error) {
        console.log('⚠️ Chrome process cleanup warning:', error.message);
    }
}

// Helper to check if auth folder exists and has valid session
function hasValidAuthSession(userId) {
    const authPath = path.join('./auth_data', `session-user-${userId}`);
    return fs.existsSync(authPath);
}

// Helper to clean stale auth data
// Enhanced stale auth data cleaner
async function cleanStaleAuthData(userId) {
    const authPath = path.join('./auth_data', `session-user-${userId}`);
    
    if (!fs.existsSync(authPath)) {
        return true;
    }

    console.log(`🧹 Enhanced cleaning for user ${userId} auth data...`);
    
    // Kill processes first
    await killChromeProcesses();
    
    // Wait a bit for OS to release locks
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Use enhanced safe delete
    const result = await safeDeleteAuthFolder(authPath);
    
    if (!result) {
        console.log(`⚠️ Could not immediately delete auth data for user ${userId}, will retry later`);
        // Schedule retry after 30 seconds
        setTimeout(() => safeDeleteAuthFolder(authPath), 30000);
    }
    
    return result;
}
// Helper function to configure client heartbeat with fixes
function configureClientHeartbeat(client, userId, token) {
    // Check if already attached
    if (eventListenersAttached.get(userId)) {
        console.log(`⚠️ Event listeners already attached for user ${userId}, skipping...`);
        return;
    }
    
    eventListenersAttached.set(userId, true);
    
    let heartbeatInterval = null;
    let reconnectAttempts = 0;
    const MAX_RECONNECT_ATTEMPTS = 10;  // ✅ Increased from 3
    let isDestroyed = false;
    let lastHeartbeatTime = Date.now();

    const startHeartbeat = () => {
        if (heartbeatInterval) {
            clearInterval(heartbeatInterval);
        }

        console.log(`💓 Starting heartbeat for user ${userId}`);
        heartbeatInterval = setInterval(async () => {
            if (isDestroyed) {
                console.log(`🛑 Heartbeat stopped - client destroyed for user ${userId}`);
                stopHeartbeat();
                return;
            }

            try {
                // More robust browser check
                if (!client?.pupBrowser?.isConnected?.() || client.pupBrowser.process?.killed) {
                    console.log(`⚠️ Browser not available for user ${userId}, attempting recovery...`);
                    // Don't destroy, just skip this cycle
                    return;
                }

                const statePromise = client.getState();
                const timeoutPromise = new Promise((_, reject) => 
                    setTimeout(() => reject(new Error('State check timeout')), 8000)  // ✅ Increased timeout
                );

                const state = await Promise.race([statePromise, timeoutPromise]);
                lastHeartbeatTime = Date.now();
                
                if (state === 'CONNECTED') {
                    console.log(`💓 Heartbeat OK - Client alive for user ${userId}`);
                    reconnectAttempts = 0;
                } else if (state !== 'CONNECTING') {
                    console.warn(`⚠️ Heartbeat: Client state is ${state} for user ${userId}`);
                }
            } catch (error) {
                if (!error.message.includes('Execution context was destroyed') &&
                    !error.message.includes('navigation') &&
                    !error.message.includes('Session closed') &&
                    !error.message.includes('timeout')) {
                    console.error(`❌ Heartbeat error for user ${userId}:`, error.message);
                } else {
                    console.log(`⚠️ Heartbeat: ${error.message}`);
                }
            }
        }, 30000);

        return heartbeatInterval;
    };

    const stopHeartbeat = () => {
        if (heartbeatInterval) {
            clearInterval(heartbeatInterval);
            heartbeatInterval = null;
            console.log(`🛑 Heartbeat stopped for user ${userId}`);
        }
    };

    // ✅ Improved auth failure handler
    client.once('auth_failure', async (msg) => {
        console.error(`❌ Auth failure for user ${userId}:`, msg);
        isDestroyed = true;
        stopHeartbeat();
        eventListenersAttached.delete(userId);
        
        // Clean up gracefully
        setTimeout(async () => {
            try {
                await cleanStaleAuthData(userId);
            } catch (e) {
                console.log(`Error during cleanup: ${e.message}`);
            }
        }, 2000);
    });

    // ✅ Improved disconnected handler with persistent recovery
    client.once('disconnected', async (reason) => {
        console.log(`🔌 Client disconnected for user ${userId}. Reason: ${reason}`);

        isDestroyed = true;
        stopHeartbeat();

        // Keep client in map for potential recovery
        let reconnected = false;

        // Try to reconnect on unexpected disconnects
        if (['LOGOUT', 'NAVIGATION', 'RESTORED'].includes(reason)) {
            while (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
                reconnectAttempts++;
                const delay = 3000 * Math.pow(1.5, reconnectAttempts);  // ✅ Exponential backoff
                
                console.log(`🔄 Reconnect attempt #${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS} (waiting ${delay}ms)...`);
                await new Promise(resolve => setTimeout(resolve, delay));
                
                try {
                    await initializeClientForUser(userId, token, false);  // ✅ Don't force new
                    reconnected = true;
                    console.log(`✅ Auto-reconnect succeeded for user ${userId}`);
                    break;
                } catch (err) {
                    console.error(`❌ Reconnect attempt #${reconnectAttempts} failed:`, err.message);
                    
                    if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
                        console.error(`❌ Max reconnect attempts reached for user ${userId}`);
                    }
                }
            }
        }

        // Cleanup if reconnect failed
        if (!reconnected) {
            eventListenersAttached.delete(userId);
            clients.delete(userId);
            qrCodes.delete(userId);
            
            setTimeout(async () => {
                await cleanStaleAuthData(userId);
            }, 3000);
        }
    });

    // ✅ State change handler
    client.on('change_state', (state) => {
        console.log(`🔄 State change for user ${userId}: ${state}`);
        if (['CONFLICT', 'UNPAIRED', 'PHONE_OFFLINE'].includes(state)) {
            console.warn(`⚠️ Critical state change: ${state}`);
        }
    });

    // ✅ Ready handler - use ONCE
    client.once('ready', async () => {
        const info = client.info;
        try {
            await callPHPAPI('/whatsapp/session/update', 'POST', {
                phone_number: info.wid.user,
                pushname: info.pushname,
                is_active: true
            }, token);
            
            if (!isDestroyed) {
                startHeartbeat();
                console.log(`✅ Client ready and heartbeat started for user ${userId}: ${info.pushname}`);
            }
        } catch (error) {
            console.error('❌ Error updating session:', error.message);
        }
    });

    // ✅ Message handler - keep reference
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

    // ✅ Override destroy method
    const originalDestroy = client.destroy.bind(client);
    client.destroy = async function() {
        isDestroyed = true;
        stopHeartbeat();
        eventListenersAttached.delete(userId);
        try {
            return await originalDestroy();
        } catch (e) {
            console.log(`Error during destroy: ${e.message}`);
        }
    };

    return { startHeartbeat, stopHeartbeat };
}

function getRandomConnectedDevice(userId, devices) {
    // Get all connected devices for this user
    const connectedDevices = devices.filter(device => {
        const clientKey = `${userId}-${device.device_id}`;
        const client = clients.get(clientKey);
        if (!client) return false;
        
        try {
            // Quick check if client exists and is likely connected
            return client.pupBrowser?.isConnected?.() !== false;
        } catch {
            return false;
        }
    });
    
    if (connectedDevices.length === 0) return null;
    
    // Return random device
    const randomIndex = Math.floor(Math.random() * connectedDevices.length);
    return connectedDevices[randomIndex];
}

// Initialize WhatsApp Client
async function initializeClientForUser(userId, token, forceNew = false) {
    // Check if initialization is already in progress
    if (initializationPromises.has(userId)) {
        console.log(`⏳ Client initialization already in progress for user ${userId}, reusing promise...`);
        return await initializationPromises.get(userId);
    }

    // Create initialization promise
    const initPromise = (async () => {
        try {
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
                        '--disable-web-resources'
                    ]
                }
            });

            let qrGenerated = false;
            let authenticated = false;

            // QR handler - use ONCE
            client.once('qr', async (qr) => {
                qrGenerated = true;
                const qrData = await qrcode.toDataURL(qr);
                qrCodes.set(userId, qrData);
                console.log(`📱 QR Code generated for user ${userId}`);
            });

            // Authenticated handler - use ONCE
            client.once('authenticated', async () => {
                authenticated = true;
                console.log(`✓ User ${userId} authenticated`);
                qrCodes.delete(userId);
            });

            // Configure heartbeat and event handlers
            configureClientHeartbeat(client, userId, token);

            // Message handler
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
            // while (waitTime < 15000 && !qrGenerated && !authenticated) {
            //     await new Promise(resolve => setTimeout(resolve, 500));
            //     waitTime += 500;
            // }
            
            try {
                const state = await client.getState();
                console.log(`📊 Client state after initialization for user ${userId}: ${state}`);
                
                if (state === 'CONNECTED' && !qrGenerated && forceNew) {
                    console.error(`❌ ERROR: Client connected without QR despite forceNew!`);
                    console.log(`🔄 Destroying and retrying...`);
                    
                    await client.destroy();
                    eventListenersAttached.delete(userId);
                    await cleanStaleAuthData(userId);
                    clientInitializing.delete(userId);
                    initializationPromises.delete(userId);
                    
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
            initializationPromises.delete(userId);
            eventListenersAttached.delete(userId);
            await cleanStaleAuthData(userId);
            throw error;
        }
    })();

    // Store the promise
    initializationPromises.set(userId, initPromise);

    // Remove promise when done (success or failure)
    initPromise.finally(() => {
        initializationPromises.delete(userId);
    });

    return await initPromise;
}
// WhatsApp Routes
app.post('/api/whatsapp/initialize', verifyAuth, async (req, res) => {
    try {
        console.log(`📱 Initialize request for user ${req.userId}`);
        
        const clientKey = req.userId;
        
        // Check if already initializing
        if (initializationPromises.has(clientKey)) {
            console.log(`⚠️ Initialization already in progress for user ${req.userId}`);
            return res.status(429).json({ 
                error: 'Initialization already in progress',
                message: 'Please wait for the current initialization to complete'
            });
        }
        
        console.log(`🔄 Proceeding with WhatsApp initialization for user ${req.userId}`);
        
        // Initialize client with forceNew = true
        await initializeClientForUser(req.userId, req.token, true);
        
        console.log(`✅ Initialization process started for user ${req.userId}`);
        
        res.json({ 
            success: true, 
            message: 'WhatsApp client initializing, please scan QR code' 
        });
        
    } catch (error) {
        console.error('Initialize error:', error.message);
        
        res.status(500).json({ 
            error: error.message,
            message: 'Failed to initialize WhatsApp. Please try again.'
        });
    }
});

// Improved client destruction with better cleanup
async function safeDestroyClient(client, userId) {
    if (!client) return;

    try {
        console.log(`🛑 Starting safe destruction for user ${userId}...`);
        
        // Stop any heartbeats first
        if (eventListenersAttached.has(userId)) {
            eventListenersAttached.delete(userId);
        }

        // Remove from tracking maps
        clients.delete(userId);
        qrCodes.delete(userId);
        clientInitializing.delete(userId);
        initializationPromises.delete(userId);

        // Try to destroy client gracefully
        if (typeof client.destroy === 'function') {
            await client.destroy().catch(err => {
                console.log(`⚠️ Graceful destroy failed: ${err.message}`);
            });
        }

        // Kill Chrome processes
        await killChromeProcesses();

        console.log(`✅ Client safely destroyed for user ${userId}`);
    } catch (error) {
        console.error(`❌ Error in safeDestroyClient for user ${userId}:`, error.message);
    }
}

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
                const statePromise = client.getState();
                const timeoutPromise = new Promise((_, reject) => 
                    setTimeout(() => reject(new Error('State check timeout')), 3000)
                );
                
                clientState = await Promise.race([statePromise, timeoutPromise]);
                isConnected = clientState === 'CONNECTED';
                console.log(`Status check - Client state for user ${req.userId}: ${clientState}`);
            } catch (error) {
                console.log(`✗ Error checking client state: ${error.message}`);
                if (error.message.includes('timeout')) {
                    // Client might be frozen, remove it
                    clients.delete(req.userId);
                    clientState = 'TIMEOUT';
                }
            }
        }

        let session = null;
        try {
            session = await callPHPAPI('/whatsapp/session/get', 'GET', null, req.token);
        } catch (error) {
            console.log(`No session in DB for user ${req.userId}`);
        }
        
        // If DB says connected but client isn't, clean up DB
        if (session?.is_active && !isConnected) {
            console.log(`🧹 Cleaning stale DB session for user ${req.userId}`);
            try {
                await callPHPAPI('/whatsapp/session/disconnect', 'POST', {}, req.token);
                session = null;
            } catch (error) {
                console.error('✗ Error cleaning stale session:', error.message);
            }
        }
        
        res.json({
            connected: isConnected && session?.is_active,
            session: session || null,
            clientActive: isConnected,
            clientState,
            timestamp: Date.now()
        });
    } catch (error) {
        console.error('✗ Status check error:', error.message);
        
        res.status(500).json({ 
            error: error.message,
            code: 'STATUS_CHECK_FAILED'
        });
    }
});

// Export for use in main server file
module.exports = {
    verifyAuth,
    verifyApiToken,
    verifyAnyToken,
    callPHPAPI,
    cacheToken,
    getCachedToken,
    tokenCache
};

app.post('/api/whatsapp/disconnect', verifyAuth, async (req, res) => {
    try {
        console.log(`🔌 Enhanced disconnect request for user ${req.userId}`);
        
        const client = clients.get(req.userId);
        
        // Use safe destruction
        if (client) {
            await safeDestroyClient(client, req.userId);
        } else {
            // Still clean up even if no client object
            clients.delete(req.userId);
            qrCodes.delete(req.userId);
            clientInitializing.delete(req.userId);
            initializationPromises.delete(req.userId);
        }

        // Update database
        try {
            await callPHPAPI('/whatsapp/session/disconnect', 'POST', {}, req.token);
        } catch (error) {
            console.error('✗ Error updating DB session:', error);
        }

        // Enhanced auth data cleanup
        await cleanStaleAuthData(req.userId);
        
        console.log(`✅ WhatsApp fully disconnected for user ${req.userId}`);
        
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
// Replace the existing send-message route
// Also fix the send message route error handling
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
                details: 'Please connect to WhatsApp first',
                code: 'NOT_CONNECTED'
            });
        }

        const state = await client.getState();
        if (state !== 'CONNECTED') {
            return res.status(400).json({ 
                error: 'WhatsApp not ready',
                state: state,
                code: 'NOT_READY'
            });
        }

        const chatId = number.includes('@c.us') ? number : `${number}@c.us`;
        
        console.log(`📤 Sending message to ${chatId} (User: ${req.userId})`);
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

        const authToken = req.token;
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
            dbId: savedMessage?.id || null
        });
    } catch (error) {
        console.error('✗ Error sending message:', error.message);
        
        try {
            const authToken = req.token;
            await callPHPAPI('/stats/update', 'POST', {
                field: 'failed',
                increment: 1
            }, authToken);
        } catch (e) {
            console.error('Failed to update stats:', e.message);
        }
        
        res.status(500).json({ 
            success: false, 
            error: error.message || 'Failed to send message',
            code: 'SEND_MESSAGE_ERROR'
        });
    }
});


app.post('/api/send-media', verifyAnyToken, upload.single('file'), async (req, res) => {
    try {
        const { number, caption, deviceId } = req.body;
        
        if (!number) {
            return res.status(400).json({ error: 'Number is required' });
        }
        
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        let clientKey;
        let client;
        let actualDeviceId = deviceId;
        let selectedDevice;

        // Get all user's devices
        const authToken = req.token;
        const userDevices = await callPHPAPI('/devices/list', 'GET', null, authToken);

        if (req.authType === 'api_token') {
            const deviceData = await callPHPAPI('/devices/by-token', 'POST', 
                { token: req.token }, 
                authToken
            );

            if (deviceData && deviceData.device_id) {
                actualDeviceId = deviceData.device_id;
                clientKey = `${req.userId}-${deviceData.device_id}`;
                client = clients.get(clientKey);
                selectedDevice = deviceData;
            } else {
                selectedDevice = getRandomConnectedDevice(req.userId, userDevices);
                if (!selectedDevice) {
                    return res.status(400).json({ error: 'No connected devices found' });
                }
                actualDeviceId = selectedDevice.device_id;
                clientKey = `${req.userId}-${selectedDevice.device_id}`;
                client = clients.get(clientKey);
            }
        } else {
            if (deviceId) {
                clientKey = `${req.userId}-${deviceId}`;
                client = clients.get(clientKey);
                selectedDevice = userDevices.find(d => d.device_id === deviceId);
            } else {
                selectedDevice = getRandomConnectedDevice(req.userId, userDevices);
                if (!selectedDevice) {
                    return res.status(400).json({ error: 'No connected devices found' });
                }
                actualDeviceId = selectedDevice.device_id;
                clientKey = `${req.userId}-${selectedDevice.device_id}`;
                client = clients.get(clientKey);
            }
        }

        if (!client) {
            return res.status(400).json({ error: 'Device not connected' });
        }

        const chatId = number.includes('@c.us') ? number : `${number}@c.us`;
        const media = MessageMedia.fromFilePath(req.file.path);
        
        console.log(`📤 Sending media to ${chatId} from device ${selectedDevice?.device_name || actualDeviceId}`);
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
            timestamp: sentMessage.timestamp,
            device_id: actualDeviceId
        }, authToken);

        await callPHPAPI('/stats/update', 'POST', {
            field: 'sent',
            increment: 1
        }, authToken);

        await callPHPAPI(`/devices/${actualDeviceId}/update-stats`, 'POST', {
            field: 'sent',
            increment: 1
        }, authToken);

        // Send webhook notification
        if (selectedDevice?.webhook_url) {
            try {
                await axios.post(selectedDevice.webhook_url, {
                    event: 'media_sent',
                    message_id: sentMessage.id.id,
                    from: myInfo.wid.user,
                    to: number,
                    caption: caption,
                    media_type: mediaType,
                    timestamp: sentMessage.timestamp,
                    device_id: actualDeviceId,
                    device_name: selectedDevice.device_name
                }, { timeout: 5000 });
            } catch (webhookError) {
                console.error(`✗ Webhook failed: ${webhookError.message}`);
            }
        }

        res.json({ 
            success: true, 
            message: 'Media sent successfully',
            messageId: sentMessage.id.id,
            dbId: savedMessage.id,
            deviceId: actualDeviceId,
            deviceName: selectedDevice?.device_name || 'Unknown'
        });
    } catch (error) {
        console.error('✗ Error sending media:', error);
        
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        
        try {
            await callPHPAPI('/stats/update', 'POST', {
                field: 'failed',
                increment: 1
            }, req.token);
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
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

async function gracefulShutdown(signal) {
    console.log(`🛑 ${signal} received, starting graceful shutdown...`);
    
    // Clear token cache
    tokenCache.clear();
    
    // Destroy all WhatsApp clients
    for (const [userId, client] of clients.entries()) {
        try {
            console.log(`Destroying client for user ${userId}...`);
            await client.destroy();
        } catch (error) {
            console.error(`Error destroying client for user ${userId}:`, error.message);
        }
    }
    
    console.log('✓ Graceful shutdown complete');
    process.exit(0);
}

app.listen(PORT, () => {
    console.log(`✓ WhatsApp Server running on port ${PORT}`);
    console.log(`✓ Environment: ${NODE_ENV}`);
    console.log(`✓ PHP API URL: ${PHP_API_URL}`);
    console.log(`✓ Frontend URL: ${FRONTEND_URL}`);
    console.log(`✓ Server ready to accept connections`);
});