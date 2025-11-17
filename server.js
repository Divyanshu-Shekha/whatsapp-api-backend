const express = require('express');
const cors = require('cors');
const { default: makeWASocket, useMultiFileAuthState, DisconnectReason, isJidBroadcast, fetchLatestBaileysVersion } = require('@whiskeysockets/baileys');
const QRCode = require('qrcode');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const Pino = require('pino');

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

// Client Management
const clients = new Map();
const qrCodes = new Map();
const clientInitializing = new Map();
const initializationPromises = new Map();

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

// Middleware to verify JWT tokens
async function verifyAuth(req, res, next) {
    const token = extractToken(req);
    
    if (!token) {
        console.error('❌ No token provided in request');
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        console.log(`🔑 Verifying JWT token for request: ${req.method} ${req.path}`);
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
        return res.status(401).json({ error: 'Authentication failed' });
    }
}

// Middleware to verify API tokens
async function verifyApiToken(req, res, next) {
    const token = extractToken(req);
    
    if (!token) {
        console.error('❌ No API token provided');
        return res.status(401).json({ error: 'API token required' });
    }

    try {
        console.log(`🔑 Verifying API token for request: ${req.method} ${req.path}`);
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
        
        try {
            await callPHPAPI('/tokens/update-usage', 'POST', { token });
        } catch (error) {
            console.error('Warning: Failed to update token usage:', error.message);
        }
        
        next();
    } catch (error) {
        console.error('❌ API Token verification failed:', error.message);
        return res.status(401).json({ error: 'Invalid API token' });
    }
}

// Combined middleware
async function verifyAnyToken(req, res, next) {
    const token = extractToken(req);
    
    if (!token) {
        return res.status(401).json({ error: 'Authentication token required' });
    }

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

// Clean stale auth data
async function cleanStaleAuthData(userId) {
    const authPath = path.join('./auth_data', `user-${userId}`);
    if (fs.existsSync(authPath)) {
        console.log(`🧹 Cleaning stale auth data for user ${userId}`);
        await safeDeleteAuthFolder(authPath);
    }
}

// Initialize WhatsApp Client
async function initializeClientForUser(userId, token, forceNew = false) {
    if (initializationPromises.has(userId)) {
        console.log(`⏳ Client initialization already in progress for user ${userId}, reusing promise...`);
        return await initializationPromises.get(userId);
    }

    const initPromise = (async () => {
        try {
            clientInitializing.set(userId, true);
            console.log(`\n🔄 INITIALIZING CLIENT FOR USER ${userId} (forceNew: ${forceNew})`);

            if (forceNew) {
                console.log(`🧹 Cleaning auth data for user ${userId}...`);
                await cleanStaleAuthData(userId);
                await new Promise(resolve => setTimeout(resolve, 1000));
                console.log(`✅ Auth data cleaned`);
            }

            const authPath = `./auth_data/user-${userId}`;
            console.log(`📂 Auth Path: ${authPath}`);
            
            const { state, saveCreds } = await useMultiFileAuthState(authPath);
            console.log(`✅ Auth state loaded`);

            // Fetch latest version
            const { version } = await fetchLatestBaileysVersion();
            console.log(`📦 Using Baileys version: ${version.join('.')}`);

            console.log(`📋 Creating socket...`);
            
            const client = makeWASocket({
                version,
                auth: state,
                logger: Pino({ level: 'silent' }),
                printQRInTerminal: true,
                browser: ['Ubuntu', 'Chrome', '120.0.0.0'],
                markOnlineOnConnect: false,
                generateHighQualityLinkPreview: true,
                syncFullHistory: false,
                defaultQueryTimeoutMs: 60000,
                retryRequestDelayMs: 1000,
                maxRetries: 3,
                connectTimeoutMs: 30000,
                keepAliveIntervalMs: 10000,
                emitOwnEvents: true,
                fireInitQueries: true,
                mobile: false,
                txTimeout: 30000
            });

            console.log(`✅ Socket created`);

            // Store client immediately
            clients.set(userId, client);
            console.log(`✅ Client stored in map`);

            // Set up connection update handler
            let qrGenerated = false;
            let connectionOpened = false;

            client.ev.on('connection.update', async (update) => {
                const { connection, lastDisconnect, qr, isOnline } = update;

                console.log(`\n[🔗 CONNECTION UPDATE for user ${userId}]`);
                console.log(`  Connection: ${connection}`);
                console.log(`  QR Code: ${!!qr}`);
                console.log(`  Online: ${isOnline}`);
                console.log(`  Last Disconnect: ${lastDisconnect?.error?.message || 'None'}`);
                
                if (lastDisconnect?.error) {
                    console.log(`  Disconnect Reason: ${lastDisconnect.error.output?.statusCode}`);
                }

                // Handle QR code generation
                if (qr && !qrGenerated) {
                    try {
                        console.log(`\n🔲 QR CODE RECEIVED - Converting to Data URL...`);
                        const qrData = await QRCode.toDataURL(qr);
                        qrCodes.set(userId, qrData);
                        qrGenerated = true;
                        console.log(`✅ QR CODE STORED SUCCESSFULLY for user ${userId}`);
                        console.log(`📊 QR Code Length: ${qrData.length} chars`);
                    } catch (error) {
                        console.error('❌ Error converting QR to data URL:', error.message);
                    }
                }

                if (connection === 'connecting') {
                    console.log(`🔄 CONNECTING for user ${userId}...\n`);
                }

                if (connection === 'open') {
                    console.log(`\n🎉 CONNECTION OPENED for user ${userId}`);
                    connectionOpened = true;
                    qrCodes.delete(userId);
                    qrGenerated = false;
                    
                    try {
                        const userInfo = client.user;
                        if (userInfo && userInfo.id) {
                            const phoneNumber = userInfo.id.split(':')[0];
                            console.log(`📞 Phone Number: ${phoneNumber}`);
                            console.log(`👤 Push Name: ${userInfo.name || userInfo.pushname || 'User'}`);
                            
                            console.log(`📤 Updating session in database...`);
                            await callPHPAPI('/whatsapp/session/update', 'POST', {
                                phone_number: phoneNumber,
                                pushname: userInfo.name || userInfo.pushname || 'User',
                                is_active: true
                            }, token);
                            
                            console.log(`✅ Session updated in database\n`);
                        }
                    } catch (error) {
                        console.error('❌ Error updating session:', error.message);
                    }
                }

                if (connection === 'close') {
                    const statusCode = lastDisconnect?.error?.output?.statusCode;
                    const shouldReconnect = statusCode !== DisconnectReason.loggedOut;
                    
                    console.log(`\n🔌 CONNECTION CLOSED for user ${userId}`);
                    console.log(`   Status Code: ${statusCode}`);
                    console.log(`   Should Reconnect: ${shouldReconnect}`);
                    
                    if (!shouldReconnect) {
                        console.log(`🧹 Cleaning up disconnected client...`);
                        clients.delete(userId);
                        qrCodes.delete(userId);
                        clientInitializing.delete(userId);
                        initializationPromises.delete(userId);
                        
                        try {
                            await callPHPAPI('/whatsapp/session/disconnect', 'POST', {}, token);
                            await cleanStaleAuthData(userId);
                        } catch (error) {
                            console.error('❌ Error cleaning up after disconnect:', error.message);
                        }
                    }
                }
            });

            // Save credentials on update
            client.ev.on('creds.update', saveCreds);
            console.log(`✅ Credentials listener attached`);

            // Messages handler
            client.ev.on('messages.upsert', async (m) => {
                const message = m.messages[0];
                
                if (!message.message || message.key.fromMe || isJidBroadcast(message.key.remoteJid)) return;

                try {
                    const myInfo = client.user;

                    await callPHPAPI('/stats/update', 'POST', {
                        field: 'received',
                        increment: 1
                    }, token);

                    let hasMedia = false;
                    let mediaType = null;
                    let mediaUrl = null;
                    let messageBody = null;

                    // Extract message body
                    if (message.message.conversation) {
                        messageBody = message.message.conversation;
                    } else if (message.message.extendedTextMessage) {
                        messageBody = message.message.extendedTextMessage.text;
                    }

                    // Check for media
                    const mediaKeys = ['imageMessage', 'videoMessage', 'audioMessage', 'documentMessage'];
                    for (const key of mediaKeys) {
                        if (message.message[key]) {
                            hasMedia = true;
                            mediaType = key.replace('Message', '').toLowerCase();
                            
                            try {
                                const buffer = await client.downloadMediaMessage(message);
                                if (buffer) {
                                    const ext = key === 'documentMessage' ? 
                                        (message.message[key].fileName?.split('.').pop() || 'bin') : 
                                        mediaType;
                                    const filename = `${Date.now()}_${message.key.id}.${ext}`;
                                    const filepath = path.join('uploads', filename);
                                    fs.writeFileSync(filepath, buffer);
                                    mediaUrl = `/uploads/${filename}`;
                                }
                            } catch (mediaError) {
                                console.error('✗ Error downloading media:', mediaError);
                            }
                            break;
                        }
                    }

                    const phoneNumber = message.key.remoteJid.split('@')[0];
                    const myPhoneNumber = myInfo.id.split(':')[0];

                    await callPHPAPI('/messages/save', 'POST', {
                        message_id: message.key.id,
                        type: 'received',
                        from_number: phoneNumber,
                        from_name: phoneNumber,
                        to_number: myPhoneNumber,
                        to_name: myInfo.name || myInfo.pushname || 'User',
                        message_body: messageBody,
                        has_media: hasMedia,
                        media_type: mediaType,
                        media_url: mediaUrl,
                        status: 'received',
                        timestamp: message.messageTimestamp
                    }, token);

                    console.log(`✓ Message saved for user ${userId}`);
                } catch (error) {
                    console.error('✗ Error saving received message:', error);
                }
            });

            clientInitializing.delete(userId);

            // Wait for QR generation with timeout
            console.log(`⏳ Waiting for QR generation (max 15 seconds)...`);
            let waitTime = 0;
            const maxWait = 15000;
            
            while (waitTime < maxWait && !qrGenerated && !connectionOpened) {
                await new Promise(resolve => setTimeout(resolve, 500));
                waitTime += 500;
                
                if (waitTime % 5000 === 0) {
                    console.log(`⏰ Still waiting for QR... ${waitTime/1000}s`);
                }
            }

            if (qrGenerated) {
                console.log(`✅ QR Code generated successfully after ${waitTime}ms`);
            } else if (connectionOpened) {
                console.log(`✅ Connected successfully after ${waitTime}ms`);
            } else {
                console.log(`⚠️ Timeout waiting for QR/connection after ${waitTime}ms`);
            }

            console.log(`\n✅ INITIALIZATION COMPLETE FOR USER ${userId}`);
            console.log(`   QR Available: ${!!qrCodes.get(userId)}`);
            console.log(`   Connected: ${!!client.user}`);
            console.log(`   Client Ready: ${!!client}\n`);
            
            return client;
        } catch (error) {
            console.error(`\n❌ Error initializing client for user ${userId}:`, error.message);
            clientInitializing.delete(userId);
            initializationPromises.delete(userId);
            await cleanStaleAuthData(userId);
            throw error;
        }
    })();

    initializationPromises.set(userId, initPromise);

    initPromise.finally(() => {
        initializationPromises.delete(userId);
    });

    return await initPromise;
}

// WhatsApp Routes
app.post('/api/whatsapp/initialize', verifyAuth, async (req, res) => {
    try {
        console.log(`\n📱 Initialize request for user ${req.userId}`);
        
        if (initializationPromises.has(req.userId)) {
            console.log(`⚠️ Initialization already in progress for user ${req.userId}`);
            return res.status(409).json({ 
                error: 'Initialization already in progress',
                message: 'Please wait for the current initialization to complete'
            });
        }
        
        // Clean up existing client
        if (clients.has(req.userId)) {
            const client = clients.get(req.userId);
            console.log(`🧹 Destroying existing client for user ${req.userId}`);
            try {
                client.ev.removeAllListeners();
            } catch (error) {
                console.log(`⚠️ Error cleaning client: ${error.message}`);
            }
            clients.delete(req.userId);
        }

        qrCodes.delete(req.userId);
        clientInitializing.delete(req.userId);

        // Clean database session
        try {
            await callPHPAPI('/whatsapp/session/disconnect', 'POST', {}, req.token);
        } catch (error) {
            console.log(`No database session to clean for user ${req.userId}`);
        }

        // Clean auth data
        console.log(`🧹 Cleaning auth data for user ${req.userId}`);
        await cleanStaleAuthData(req.userId);
        await new Promise(resolve => setTimeout(resolve, 1000));

        console.log(`🔄 Starting FRESH WhatsApp initialization for user ${req.userId}`);
        const client = await initializeClientForUser(req.userId, req.token, true);
        
        const qr = qrCodes.get(req.userId);
        const isConnected = client && client.user;
        
        console.log(`\n📊 INITIALIZATION RESULT FOR USER ${req.userId}:`);
        console.log(`   QR Code: ${qr ? '✅ AVAILABLE' : '❌ NOT AVAILABLE'}`);
        console.log(`   Connected: ${isConnected ? '✅ YES' : '❌ NO'}`);
        console.log(`   Client in Map: ${clients.has(req.userId) ? '✅ YES' : '❌ NO'}`);
        
        res.json({ 
            success: true, 
            message: qr ? 'QR code generated successfully' : (isConnected ? 'Already connected' : 'Waiting for connection'),
            hasQR: !!qr,
            isConnected: !!isConnected,
            clientReady: !!client
        });
    } catch (error) {
        console.error('✗ Initialize error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/whatsapp/qr', verifyAuth, async (req, res) => {
    try {
        const client = clients.get(req.userId);
        const qr = qrCodes.get(req.userId);
        
        console.log(`\n📱 QR request for user ${req.userId}:`);
        console.log(`   - Client exists: ${!!client}`);
        console.log(`   - Client authenticated: ${!!(client?.user)}`);
        console.log(`   - QR code exists: ${!!qr}`);
        console.log(`   - All users with QR: ${Array.from(qrCodes.keys()).join(', ')}`);
        
        if (client && client.user) {
            console.log(`   - Client is authenticated - returning null QR`);
            try {
                const session = await callPHPAPI('/whatsapp/session/get', 'GET', null, req.token);
                return res.json({ 
                    qr: null, 
                    ready: true, 
                    session 
                });
            } catch (error) {
                console.log('Error fetching session:', error.message);
                return res.json({ 
                    qr: null, 
                    ready: true,
                    session: null
                });
            }
        }

        if (qr) {
            console.log(`   ✅ Returning QR code of length: ${qr.length}`);
        } else {
            console.log(`   ❌ No QR code available`);
        }

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
            isConnected = !!client.user;
            clientState = isConnected ? 'CONNECTED' : 'DISCONNECTED';
            console.log(`Status check - Client state for user ${req.userId}: ${clientState}`);
        }

        let session = null;
        try {
            session = await callPHPAPI('/whatsapp/session/get', 'GET', null, req.token);
        } catch (error) {
            // Session doesn't exist
        }
        
        res.json({
            connected: isConnected && session?.is_active,
            session: session || null,
            clientActive: isConnected,
            clientState
        });
    } catch (error) {
        console.error('✗ Status check error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/whatsapp/disconnect', verifyAuth, async (req, res) => {
    try {
        console.log(`🔌 Disconnect request for user ${req.userId}`);
        
        const client = clients.get(req.userId);
        
        if (client) {
            try {
                client.ev.removeAllListeners();
                console.log(`✓ Client destroyed for user ${req.userId}`);
            } catch (error) {
                console.error('✗ Error destroying client:', error.message);
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

app.post('/api/whatsapp/force-cleanup', verifyAuth, async (req, res) => {
    try {
        console.log(`🧹 Force cleanup requested for user ${req.userId}`);
        
        if (clients.has(req.userId)) {
            const client = clients.get(req.userId);
            try {
                client.ev.removeAllListeners();
            } catch (error) {
                console.log(`Error destroying client: ${error.message}`);
            }
            clients.delete(req.userId);
        }
        
        qrCodes.delete(req.userId);
        clientInitializing.delete(req.userId);
        
        try {
            await callPHPAPI('/whatsapp/session/disconnect', 'POST', {}, req.token);
        } catch (error) {
            console.log(`Error updating DB: ${error.message}`);
        }
        
        await cleanStaleAuthData(req.userId);
        
        await new Promise(resolve => setTimeout(resolve, 1000));
        const authPath = path.join('./auth_data', `user-${req.userId}`);
        if (fs.existsSync(authPath)) {
            console.log(`🧹 Auth data still exists, force removing...`);
            fs.rmSync(authPath, { recursive: true, force: true, maxRetries: 5 });
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

// Messaging Routes
app.post('/api/send-message', verifyAnyToken, async (req, res) => {
    try {
        const { number, message } = req.body;
        
        if (!number || !message) {
            return res.status(400).json({ error: 'Number and message are required' });
        }
        
        const client = clients.get(req.userId);

        if (!client || !client.user) {
            return res.status(400).json({ 
                error: 'WhatsApp not connected',
                details: 'Please connect your WhatsApp first'
            });
        }

        const jid = number.includes('@c.us') ? number : `${number}@c.us`;
        
        console.log(`📤 Sending message to ${jid} for user ${req.userId} (Auth: ${req.authType})`);
        const sentMessage = await client.sendMessage(jid, { text: message });
        console.log(`✓ Message sent successfully: ${sentMessage.key.id}`);

        let contactName = number;
        try {
            const contact = await client.getContactById(jid);
            contactName = contact?.name || contact?.pushname || number;
        } catch (err) {
            console.log('Could not get contact name:', err.message);
        }

        const myInfo = client.user;
        const phoneNumber = myInfo.id.split(':')[0];

        const savedMessage = await callPHPAPI('/messages/save', 'POST', {
            message_id: sentMessage.key.id,
            type: 'sent',
            from_number: phoneNumber,
            from_name: myInfo.name || myInfo.pushname || 'User',
            to_number: number,
            to_name: contactName,
            message_body: message,
            has_media: false,
            status: 'sent',
            timestamp: Math.floor(Date.now() / 1000)
        }, req.token);

        await callPHPAPI('/stats/update', 'POST', {
            field: 'sent',
            increment: 1
        }, req.token);

        res.json({ 
            success: true, 
            message: 'Message sent successfully',
            messageId: sentMessage.key.id,
            dbId: savedMessage.id
        });
    } catch (error) {
        console.error('✗ Error sending message:', error);
        
        try {
            await callPHPAPI('/stats/update', 'POST', {
                field: 'failed',
                increment: 1
            }, req.token);
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

        if (!client || !client.user) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const jid = number.includes('@c.us') ? number : `${number}@c.us`;
        const mediaBuffer = fs.readFileSync(req.file.path);
        const mimetype = req.file.mimetype;
        
        console.log(`📤 Sending media to ${jid} for user ${req.userId} (Auth: ${req.authType})`);
        
        const mediaMessage = {
            caption: caption || undefined
        };

        if (mimetype.startsWith('image')) {
            mediaMessage.image = mediaBuffer;
        } else if (mimetype.startsWith('video')) {
            mediaMessage.video = mediaBuffer;
        } else if (mimetype.startsWith('audio')) {
            mediaMessage.audio = mediaBuffer;
        } else {
            mediaMessage.document = mediaBuffer;
            mediaMessage.fileName = req.file.originalname;
        }

        const sentMessage = await client.sendMessage(jid, mediaMessage);
        console.log(`✓ Media sent successfully: ${sentMessage.key.id}`);

        let contactName = number;
        try {
            const contact = await client.getContactById(jid);
            contactName = contact?.name || contact?.pushname || number;
        } catch (err) {
            console.log('Could not get contact name:', err.message);
        }

        const myInfo = client.user;
        const phoneNumber = myInfo.id.split(':')[0];
        const mediaType = req.file.mimetype.split('/')[0];

        const savedMessage = await callPHPAPI('/messages/save', 'POST', {
            message_id: sentMessage.key.id,
            type: 'sent',
            from_number: phoneNumber,
            from_name: myInfo.name || myInfo.pushname || 'User',
            to_number: number,
            to_name: contactName,
            message_body: caption || null,
            has_media: true,
            media_type: mediaType,
            media_url: `/uploads/${req.file.filename}`,
            status: 'sent',
            timestamp: Math.floor(Date.now() / 1000)
        }, req.token);

        await callPHPAPI('/stats/update', 'POST', {
            field: 'sent',
            increment: 1
        }, req.token);

        res.json({ 
            success: true, 
            message: 'Media sent successfully',
            messageId: sentMessage.key.id,
            dbId: savedMessage.id
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

// Public endpoints - API tokens only
app.get('/api/chats', verifyApiToken, async (req, res) => {
    try {
        const client = clients.get(req.userId);
        if (!client || !client.user) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const chats = await client.getAllChats();
        const chatList = chats.map(chat => ({
            id: chat.id,
            name: chat.name,
            isGroup: chat.isGroup,
            unreadCount: chat.unreadCount || 0
        }));
        res.json(chatList);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/contacts', verifyApiToken, async (req, res) => {
    try {
        const client = clients.get(req.userId);
        if (!client || !client.user) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const contacts = await client.contacts;
        const contactList = Object.values(contacts)
            .filter(c => !c.isGroup && c.id !== 'status@broadcast')
            .map(c => ({
                id: c.id,
                name: c.name || c.pushname,
                number: c.id.split('@')[0]
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
            isConnected = !!client.user;
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
            client.ev.removeAllListeners();
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
            client.ev.removeAllListeners();
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