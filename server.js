const express = require('express');
const cors = require('cors');
const { Client, LocalAuth, MessageMedia } = require('whatsapp-web.js');
const qrcode = require('qrcode');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

const app = express();
const PORT = 5000;

// PHP API Configuration
// const PHP_API_URL = 'https://imw-edu.com/whatsapp-api/api.php'; // Adjust this to your PHP API URL
const PHP_API_URL = 'http://localhost/whatsapp-api/api.php'; // Adjust this to your PHP API URL


// In your Node.js backend (replace the current CORS config)
app.use(cors({
    origin: ['https://imw-edu.com', 'http://localhost:3000', 'https://imw-edu.com/whatsapp-api-frontend'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    origin: 'http://localhost:3000',
    credentials: true
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
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
});

// WhatsApp Client Management
const clients = new Map();
const qrCodes = new Map();

// Helper function to call PHP API
async function callPHPAPI(endpoint, method = 'GET', data = null, token = null) {
    try {
        const config = {
            method,
            url: `${PHP_API_URL}${endpoint}`,
            headers: {}
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
            throw new Error(error.response.data.error || 'API request failed');
        }
        throw error;
    }
}

// Fix the extractToken function
function extractToken(req) {
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
        return authHeader.substring(7); // Remove 'Bearer ' prefix
    }
    return null;
}

// Update the verifyAuth middleware to handle missing tokens better
async function verifyAuth(req, res, next) {
    const token = extractToken(req);
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        // Verify token by calling PHP API
        const userData = await callPHPAPI('/auth/me', 'GET', null, token);
        if (!userData || !userData.user) {
            return res.status(401).json({ error: 'Invalid user data' });
        }
        req.userId = userData.user.id;
        req.token = token;
        next();
    } catch (error) {
        console.error('Auth verification failed:', error.message);
        return res.status(401).json({ error: 'Invalid token' });
    }
}


// Add this before your routes for debugging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    console.log('Headers:', req.headers);
    next();
});

// ============================================
// HEALTH CHECK
// ============================================

app.get('/api/health', (req, res) => {
    res.status(200).json({ 
        status: 'ok',
        message: 'WhatsApp Server is running',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        activeClients: clients.size,
        qrCodesGenerated: qrCodes.size
    });
});

// ============================================
// WHATSAPP CLIENT INITIALIZATION
// ============================================

// ============================================
// TOKEN VALIDATION ROUTES
// ============================================

// Validate token from database
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

// Store token in database after login
app.post('/api/auth/store-token', verifyAuth, async (req, res) => {
    try {
        const { token, deviceInfo } = req.body;
        
        if (!token) {
            return res.status(400).json({ error: 'Token is required' });
        }

        const result = await callPHPAPI('/auth/token/store', 'POST', { 
            token, 
            device_info: deviceInfo || 'Web Browser' 
        }, req.token);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Remove token from database (logout)
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

async function initializeClientForUser(userId, token) {
    if (clients.has(userId)) {
        return clients.get(userId);
    }

    const client = new Client({
        authStrategy: new LocalAuth({ 
            dataPath: './auth_data',
            clientId: `user-${userId}`
        }),
        puppeteer: {
            headless: true,
            args: ['--no-sandbox', '--disable-setuid-sandbox']
        }
    });

    client.on('qr', async (qr) => {
        const qrData = await qrcode.toDataURL(qr);
        qrCodes.set(userId, qrData);
        console.log(`QR Code generated for user ${userId}`);
    });

    client.on('authenticated', async () => {
        console.log(`User ${userId} authenticated`);
        qrCodes.delete(userId);
    });

    client.on('ready', async () => {
        const info = client.info;
        
        // Update session via PHP API
        try {
            await callPHPAPI('/whatsapp/session/update', 'POST', {
                phone_number: info.wid.user,
                pushname: info.pushname,
                is_active: true
            }, token);
            
            console.log(`Client ready for user ${userId}:`, info.pushname);
        } catch (error) {
            console.error('Error updating session:', error.message);
        }
    });

    // Message listener - save to database via PHP API
    client.on('message', async (message) => {
        try {
            const contact = await message.getContact();
            const myInfo = client.info;

            // Update received stats
            await callPHPAPI('/stats/update', 'POST', {
                field: 'received',
                increment: 1
            }, token);

            // Handle media if present
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
                    console.error('Error downloading media:', mediaError);
                }
            }

            // Save message via PHP API
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

            console.log(`Message saved for user ${userId}`);
        } catch (error) {
            console.error('Error saving received message:', error);
        }
    });

    client.on('disconnected', async (reason) => {
        console.log(`Client disconnected for user ${userId}. Reason:`, reason);
        
        try {
            // Update session via PHP API
            await callPHPAPI('/whatsapp/session/disconnect', 'POST', {}, token);
            
            qrCodes.delete(userId);
            clients.delete(userId);

            console.log(`Session data cleared for user ${userId} after disconnect`);

            // Schedule auth folder deletion
            setTimeout(async () => {
                const authPath = path.join('./auth_data', `session-user-${userId}`);
                await safeDeleteAuthFolder(authPath);
            }, 3000);
            
        } catch (error) {
            console.error(`Error cleaning up after disconnect for user ${userId}:`, error.message);
        }
    });

    await client.initialize();
    clients.set(userId, client);
    return client;
}

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
                
                console.log(`Successfully deleted auth data: ${authPath}`);
                return true;
            }
            return true;
        } catch (error) {
            if (i === maxRetries - 1) {
                console.error(`Failed to delete auth folder after ${maxRetries} attempts:`, error.message);
                return false;
            }
            console.log(`Retry ${i + 1}/${maxRetries} to delete auth folder...`);
            await new Promise(resolve => setTimeout(resolve, delay * (i + 1)));
        }
    }
    return false;
}

// ============================================
// WHATSAPP ROUTES
// ============================================

// Initialize WhatsApp
app.post('/api/whatsapp/initialize', verifyAuth, async (req, res) => {
    try {
        const session = await callPHPAPI('/whatsapp/session/get', 'GET', null, req.token);

        if (session?.is_active) {
            return res.json({ 
                success: true, 
                message: 'WhatsApp already connected',
                connected: true
            });
        }

        await initializeClientForUser(req.userId, req.token);
        res.json({ success: true, message: 'WhatsApp client initializing' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get QR Code
app.get('/api/whatsapp/qr', verifyAuth, async (req, res) => {
    try {
        const session = await callPHPAPI('/whatsapp/session/get', 'GET', null, req.token);

        if (session?.is_active) {
            return res.json({ 
                qr: null, 
                ready: true, 
                session 
            });
        }

        const qr = qrCodes.get(req.userId);
        res.json({ 
            qr: qr || null, 
            ready: false,
            session: session || null
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get WhatsApp Status
app.get('/api/whatsapp/status', verifyAuth, async (req, res) => {
    try {
        const session = await callPHPAPI('/whatsapp/session/get', 'GET', null, req.token);
        const isClientActive = clients.has(req.userId);
        
        res.json({
            connected: session?.is_active && isClientActive,
            session: session || null,
            clientActive: isClientActive
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Disconnect WhatsApp
app.post('/api/whatsapp/disconnect', verifyAuth, async (req, res) => {
    try {
        const client = clients.get(req.userId);
        
        if (client) {
            try {
                await client.destroy();
                console.log(`Client destroyed for user ${req.userId}`);
            } catch (destroyError) {
                console.error('Error destroying client:', destroyError.message);
            }
            
            clients.delete(req.userId);
        }

        qrCodes.delete(req.userId);

        // Update session via PHP API
        await callPHPAPI('/whatsapp/session/disconnect', 'POST', {}, req.token);

        console.log(`WhatsApp disconnected for user ${req.userId}`);
        
        res.json({ 
            success: true, 
            message: 'WhatsApp disconnected successfully' 
        });

        // Schedule auth folder deletion
        setTimeout(async () => {
            const authPath = path.join('./auth_data', `session-user-${req.userId}`);
            await safeDeleteAuthFolder(authPath, 5, 2000);
        }, 3000);
        
    } catch (error) {
        console.error('Error disconnecting WhatsApp:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// MESSAGING ROUTES
// ============================================

// Send Message
app.post('/api/send-message', verifyAuth, async (req, res) => {
    try {
        const { number, message } = req.body;
        
        if (!number || !message) {
            return res.status(400).json({ error: 'Number and message are required' });
        }
        
        const client = clients.get(req.userId);

        if (!client) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const chatId = number.includes('@c.us') ? number : `${number}@c.us`;
        
        console.log(`Sending message to ${chatId} for user ${req.userId}`);
        const sentMessage = await client.sendMessage(chatId, message);
        console.log(`Message sent successfully: ${sentMessage.id.id}`);

        // Get contact info
        let contactName = number;
        try {
            const contact = await client.getContactById(chatId);
            contactName = contact.name || contact.pushname || number;
        } catch (err) {
            console.log('Could not get contact name:', err.message);
        }

        const myInfo = client.info;

        // Save to database via PHP API
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
        }, req.token);

        // Update stats
        await callPHPAPI('/stats/update', 'POST', {
            field: 'sent',
            increment: 1
        }, req.token);

        res.json({ 
            success: true, 
            message: 'Message sent successfully',
            messageId: sentMessage.id.id,
            dbId: savedMessage.id
        });
    } catch (error) {
        console.error('Error sending message:', error);
        
        try {
            await callPHPAPI('/stats/update', 'POST', {
                field: 'failed',
                increment: 1
            }, req.token);
        } catch (e) {}
        
        res.status(500).json({ success: false, error: error.message });
    }
});

// Send Media
app.post('/api/send-media', verifyAuth, upload.single('file'), async (req, res) => {
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
        
        console.log(`Sending media to ${chatId} for user ${req.userId}`);
        const sentMessage = await client.sendMessage(chatId, media, { caption });
        console.log(`Media sent successfully: ${sentMessage.id.id}`);

        // Get contact info
        let contactName = number;
        try {
            const contact = await client.getContactById(chatId);
            contactName = contact.name || contact.pushname || number;
        } catch (err) {
            console.log('Could not get contact name:', err.message);
        }

        const myInfo = client.info;
        const mediaType = req.file.mimetype.split('/')[0];

        // Save to database via PHP API
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
        }, req.token);

        // Update stats
        await callPHPAPI('/stats/update', 'POST', {
            field: 'sent',
            increment: 1
        }, req.token);

        res.json({ 
            success: true, 
            message: 'Media sent successfully',
            messageId: sentMessage.id.id,
            dbId: savedMessage.id
        });
    } catch (error) {
        console.error('Error sending media:', error);
        
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

// Get Chats
app.get('/api/chats', verifyAuth, async (req, res) => {
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

// Get Contacts
app.get('/api/contacts', verifyAuth, async (req, res) => {
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

// ============================================
// PROXY ROUTES TO PHP API
// ============================================

// Auth routes
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

// Message routes
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

// Stats route
app.get('/api/stats', verifyAuth, async (req, res) => {
    try {
        const result = await callPHPAPI('/stats/get', 'GET', null, req.token);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Token management routes
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

// Status route
app.get('/api/status', verifyAuth, async (req, res) => {
    try {
        const session = await callPHPAPI('/whatsapp/session/get', 'GET', null, req.token);
        const stats = await callPHPAPI('/stats/get', 'GET', null, req.token);
        
        res.json({
            ready: session?.is_active || false,
            session: session || null,
            stats
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// RESTORE SESSIONS ON STARTUP
// ============================================

async function restoreExistingSessions() {
    try {
        // Note: You may need to implement a PHP endpoint to get all active sessions
        // For now, we'll skip automatic restoration on server restart
        console.log('Server started. Clients will be initialized on demand.');
    } catch (error) {
        console.error('Error during startup:', error);
    }
}

app.listen(PORT, async () => {
    console.log(`WhatsApp Server running on http://localhost:${PORT}`);
    console.log(`Connected to PHP API at: ${PHP_API_URL}`);
    await restoreExistingSessions();
});
