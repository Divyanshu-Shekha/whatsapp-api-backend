const express = require('express');
const cors = require('cors');
const { Client, LocalAuth, MessageMedia } = require('whatsapp-web.js');
const qrcode = require('qrcode');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);

const app = express();
const PORT = 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// MySQL Connection Pool
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'whatsapp_web_bot',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Session Store
const sessionStore = new MySQLStore({
    clearExpired: true,
    checkExpirationInterval: 900000,
    expiration: 86400000
}, pool);

app.use(session({
    key: 'session_cookie',
    secret: JWT_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 86400000,
        httpOnly: true,
        secure: false // Set to true in production with HTTPS
    }
}));

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

// Database Initialization
async function initDatabase() {
    const connection = await pool.getConnection();
    try {
        await connection.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `);

        await connection.query(`
            CREATE TABLE IF NOT EXISTS whatsapp_sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT UNIQUE NOT NULL,
                phone_number VARCHAR(50),
                pushname VARCHAR(255),
                is_active BOOLEAN DEFAULT FALSE,
                session_data TEXT,
                last_connected TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        await connection.query(`
            CREATE TABLE IF NOT EXISTS api_tokens (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                token VARCHAR(64) UNIQUE NOT NULL,
                name VARCHAR(255) NOT NULL,
                expires_at TIMESTAMP NULL,
                last_used TIMESTAMP NULL,
                request_count INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        await connection.query(`
            CREATE TABLE IF NOT EXISTS message_stats (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                sent INT DEFAULT 0,
                received INT DEFAULT 0,
                failed INT DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        await connection.query(`
            CREATE TABLE IF NOT EXISTS messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                message_id VARCHAR(255),
                type ENUM('sent', 'received') NOT NULL,
                from_number VARCHAR(50),
                from_name VARCHAR(255),
                to_number VARCHAR(50),
                to_name VARCHAR(255),
                message_body TEXT,
                media_url VARCHAR(500),
                has_media BOOLEAN DEFAULT FALSE,
                media_type VARCHAR(50),
                status ENUM('pending', 'sent', 'delivered', 'read', 'failed') DEFAULT 'pending',
                timestamp BIGINT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_type (type),
                INDEX idx_created_at (created_at)
            )
        `);

        console.log('Database tables initialized');
    } finally {
        connection.release();
    }
}

initDatabase().catch(console.error);

// WhatsApp Client Management
const clients = new Map();
const qrCodes = new Map();


// Add this new middleware that accepts BOTH JWT and API tokens
async function verifyAuth(req, res, next) {
    // Try JWT first
    const jwtToken = req.headers['authorization']?.replace('Bearer ', '') || req.session.token;
    
    if (jwtToken) {
        try {
            const decoded = jwt.verify(jwtToken, JWT_SECRET);
            req.userId = decoded.userId;
            req.authType = 'jwt';
            return next();
        } catch (error) {
            // JWT failed, try API token
        }
    }
    
    // Try API token
    const apiToken = req.headers['authorization']?.replace('Bearer ', '');
    if (apiToken) {
        try {
            const [rows] = await pool.query(
                'SELECT * FROM api_tokens WHERE token = ? AND (expires_at IS NULL OR expires_at > NOW())',
                [apiToken]
            );

            if (rows.length > 0) {
                req.userId = rows[0].user_id;
                req.tokenId = rows[0].id;
                req.authType = 'api';
                
                // Update last used and request count
                await pool.query(
                    'UPDATE api_tokens SET last_used = NOW(), request_count = request_count + 1 WHERE id = ?',
                    [rows[0].id]
                );
                
                return next();
            }
        } catch (error) {
            console.error('API token verification error:', error);
        }
    }
    
    return res.status(401).json({ error: 'No valid authentication provided' });
}

// ============================================
// UPDATED MESSAGING ROUTES (ACCEPT BOTH AUTH TYPES)
// ============================================

// Send Message - NOW ACCEPTS BOTH JWT AND API TOKEN
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

        // Save to database
        const [result] = await pool.query(
            `INSERT INTO messages 
            (user_id, message_id, type, from_number, from_name, to_number, to_name, 
             message_body, has_media, status, timestamp) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                req.userId,
                sentMessage.id.id,
                'sent',
                myInfo.wid.user,
                myInfo.pushname,
                number,
                contactName,
                message,
                false,
                'sent',
                sentMessage.timestamp
            ]
        );

        console.log(`Message saved to database with ID: ${result.insertId}`);

        // Update stats
        await pool.query(
            'UPDATE message_stats SET sent = sent + 1 WHERE user_id = ?',
            [req.userId]
        );

        res.json({ 
            success: true, 
            message: 'Message sent successfully',
            messageId: sentMessage.id.id,
            dbId: result.insertId
        });
    } catch (error) {
        console.error('Error sending message:', error);
        
        await pool.query(
            'UPDATE message_stats SET failed = failed + 1 WHERE user_id = ?',
            [req.userId]
        );
        res.status(500).json({ success: false, error: error.message });
    }
});

// Send Media - NOW ACCEPTS BOTH JWT AND API TOKEN
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

        // Determine media type
        const mediaType = req.file.mimetype.split('/')[0];

        // Save to database
        const [result] = await pool.query(
            `INSERT INTO messages 
            (user_id, message_id, type, from_number, from_name, to_number, to_name, 
             message_body, has_media, media_type, media_url, status, timestamp) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                req.userId,
                sentMessage.id.id,
                'sent',
                myInfo.wid.user,
                myInfo.pushname,
                number,
                contactName,
                caption || null,
                true,
                mediaType,
                `/uploads/${req.file.filename}`,
                'sent',
                sentMessage.timestamp
            ]
        );

        console.log(`Media message saved to database with ID: ${result.insertId}`);

        // Update stats
        await pool.query(
            'UPDATE message_stats SET sent = sent + 1 WHERE user_id = ?',
            [req.userId]
        );

        res.json({ 
            success: true, 
            message: 'Media sent successfully',
            messageId: sentMessage.id.id,
            dbId: result.insertId
        });
    } catch (error) {
        console.error('Error sending media:', error);
        
        // Clean up file on error
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        
        await pool.query(
            'UPDATE message_stats SET failed = failed + 1 WHERE user_id = ?',
            [req.userId]
        );
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get Stats - NOW ACCEPTS BOTH JWT AND API TOKEN
app.get('/api/stats', verifyAuth, async (req, res) => {
    try {
        const [stats] = await pool.query(
            'SELECT * FROM message_stats WHERE user_id = ?',
            [req.userId]
        );
        res.json(stats[0] || { sent: 0, received: 0, failed: 0 });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get Chats - NOW ACCEPTS BOTH JWT AND API TOKEN
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

// Get Contacts - NOW ACCEPTS BOTH JWT AND API TOKEN
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

// Middleware: Verify JWT
function verifyJWT(req, res, next) {
    const token = req.headers['authorization']?.replace('Bearer ', '') || req.session.token;
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// Middleware: Verify API Token
async function verifyAPIToken(req, res, next) {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ error: 'No API token provided' });
    }

    try {
        const [rows] = await pool.query(
            'SELECT * FROM api_tokens WHERE token = ? AND (expires_at IS NULL OR expires_at > NOW())',
            [token]
        );

        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }

        req.userId = rows[0].user_id;
        req.tokenId = rows[0].id;
        
        // Update last used and request count
        await pool.query(
            'UPDATE api_tokens SET last_used = NOW(), request_count = request_count + 1 WHERE id = ?',
            [rows[0].id]
        );

        next();
    } catch (error) {
        res.status(500).json({ error: 'Token verification failed' });
    }
}

// Initialize WhatsApp Client for User
async function initializeClientForUser(userId) {
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
        await pool.query(
            `UPDATE whatsapp_sessions 
             SET phone_number = ?, pushname = ?, is_active = TRUE, last_connected = NOW()
             WHERE user_id = ?`,
            [info.wid.user, info.pushname, userId]
        );
        console.log(`Client ready for user ${userId}:`, info.pushname);
    });

    // Enhanced message listener to save received messages
    client.on('message', async (message) => {
        try {
            // Update stats
            await pool.query(
                'UPDATE message_stats SET received = received + 1 WHERE user_id = ?',
                [userId]
            );

            // Get contact info
            const contact = await message.getContact();
            const myInfo = client.info;

            // Determine if message has media
            const hasMedia = message.hasMedia;
            let mediaType = null;
            let mediaUrl = null;

            if (hasMedia) {
                try {
                    const media = await message.downloadMedia();
                    if (media) {
                        mediaType = media.mimetype.split('/')[0];
                        // Save media file
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

            // Save to database
            await pool.query(
                `INSERT INTO messages 
                (user_id, message_id, type, from_number, from_name, to_number, to_name, 
                 message_body, has_media, media_type, media_url, status, timestamp) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    userId,
                    message.id.id,
                    'received',
                    contact.number,
                    contact.name || contact.pushname || contact.number,
                    myInfo.wid.user,
                    myInfo.pushname,
                    message.body || null,
                    hasMedia,
                    mediaType,
                    mediaUrl,
                    'received',
                    message.timestamp
                ]
            );

            console.log(`Message saved for user ${userId}`);
        } catch (error) {
            console.error('Error saving received message:', error);
        }
    });

    // UPDATED: Enhanced disconnected event listener with cleanup
  client.on('disconnected', async (reason) => {
    console.log(`Client disconnected for user ${userId}. Reason:`, reason);
    
    try {
        // Update database - clear all session data
        await pool.query(
            `UPDATE whatsapp_sessions 
             SET is_active = FALSE, 
                 phone_number = NULL, 
                 pushname = NULL, 
                 session_data = NULL,
                 last_connected = NULL
             WHERE user_id = ?`,
            [userId]
        );

        // Clear QR code from memory
        qrCodes.delete(userId);
        
        // Remove client from active clients map
        clients.delete(userId);

        console.log(`Session data cleared for user ${userId} after disconnect`);

        // Schedule auth folder deletion after delay
        // This prevents file lock issues
        setTimeout(async () => {
            const authPath = path.join('./auth_data', `session-user-${userId}`);
            await safeDeleteAuthFolder(authPath);
        }, 3000); // Wait 3 seconds before attempting delete
        
    } catch (error) {
        console.error(`Error cleaning up after disconnect for user ${userId}:`, error.message);
        // Don't crash - just log the error
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
                // Wait before attempting delete to ensure files are released
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
            return true; // Path doesn't exist, consider it success
        } catch (error) {
            if (i === maxRetries - 1) {
                // Last attempt failed
                console.error(`Failed to delete auth folder after ${maxRetries} attempts:`, error.message);
                console.log('Auth folder will be cleaned on next server restart');
                return false;
            }
            // Wait longer before next retry
            console.log(`Retry ${i + 1}/${maxRetries} to delete auth folder...`);
            await new Promise(resolve => setTimeout(resolve, delay * (i + 1)));
        }
    }
    return false;
}


// Add this simple health check endpoint anywhere in your code
// I recommend placing it right after the app initialization (around line 20)
// or at the end before app.listen()

// ============================================
// HEALTH CHECK ENDPOINT
// ============================================

// Simple health check - no authentication required
app.get('/api/health', (req, res) => {
    res.status(200).json({ 
        status: 'ok',
        message: 'Server is running',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Detailed health check - includes database connection status
app.get('/api/health/detailed', async (req, res) => {
    let dbStatus = 'disconnected';
    let dbError = null;

    try {
        const connection = await pool.getConnection();
        await connection.ping();
        connection.release();
        dbStatus = 'connected';
    } catch (error) {
        dbError = error.message;
    }

    res.status(200).json({
        status: dbStatus === 'connected' ? 'healthy' : 'degraded',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        services: {
            server: 'running',
            database: dbStatus,
            activeClients: clients.size,
            qrCodesGenerated: qrCodes.size
        },
        error: dbError
    });
});


// ============================================
// AUTH ROUTES
// ============================================

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;

        if (!email || !password || !name) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        const [result] = await pool.query(
            'INSERT INTO users (email, password, name) VALUES (?, ?, ?)',
            [email, hashedPassword, name]
        );

        const userId = result.insertId;

        // Initialize message stats
        await pool.query(
            'INSERT INTO message_stats (user_id) VALUES (?)',
            [userId]
        );

        // Create WhatsApp session entry
        await pool.query(
            'INSERT INTO whatsapp_sessions (user_id) VALUES (?)',
            [userId]
        );

        res.json({ 
            success: true, 
            message: 'User registered successfully',
            userId 
        });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            res.status(400).json({ error: 'Email already exists' });
        } else {
            res.status(500).json({ error: error.message });
        }
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const [users] = await pool.query(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
        req.session.token = token;
        req.session.userId = user.id;

        // Check if WhatsApp is already connected
        const [sessions] = await pool.query(
            'SELECT * FROM whatsapp_sessions WHERE user_id = ?',
            [user.id]
        );

        const whatsappConnected = sessions[0]?.is_active || false;

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name
            },
            whatsappConnected
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Logout
app.post('/api/auth/logout', verifyJWT, async (req, res) => {
    try {
        req.session.destroy();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get Current User
app.get('/api/auth/me', verifyJWT, async (req, res) => {
    try {
        const [users] = await pool.query(
            'SELECT id, email, name, created_at FROM users WHERE id = ?',
            [req.userId]
        );

        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const [sessions] = await pool.query(
            'SELECT * FROM whatsapp_sessions WHERE user_id = ?',
            [req.userId]
        );

        res.json({
            user: users[0],
            whatsappSession: sessions[0] || null
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// WHATSAPP ROUTES
// ============================================

// Initialize WhatsApp
app.post('/api/whatsapp/initialize', verifyJWT, async (req, res) => {
    try {
        const [sessions] = await pool.query(
            'SELECT * FROM whatsapp_sessions WHERE user_id = ?',
            [req.userId]
        );

        if (sessions[0]?.is_active) {
            return res.json({ 
                success: true, 
                message: 'WhatsApp already connected',
                connected: true
            });
        }

        await initializeClientForUser(req.userId);
        res.json({ success: true, message: 'WhatsApp client initializing' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get QR Code
app.get('/api/whatsapp/qr', verifyJWT, async (req, res) => {
    try {
        const [sessions] = await pool.query(
            'SELECT * FROM whatsapp_sessions WHERE user_id = ?',
            [req.userId]
        );

        if (sessions[0]?.is_active) {
            return res.json({ 
                qr: null, 
                ready: true, 
                session: sessions[0] 
            });
        }

        const qr = qrCodes.get(req.userId);
        res.json({ 
            qr: qr || null, 
            ready: false,
            session: sessions[0] || null
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Disconnect WhatsApp
// Updated Disconnect WhatsApp route with database cleanup
app.post('/api/whatsapp/disconnect', verifyJWT, async (req, res) => {
    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        
        const client = clients.get(req.userId);
        
        if (client) {
            try {
                // Destroy the client first (closes browser)
                await client.destroy();
                console.log(`Client destroyed for user ${req.userId}`);
            } catch (destroyError) {
                console.error('Error destroying client:', destroyError.message);
                // Continue anyway
            }
            
            clients.delete(req.userId);
        }

        // Clear QR code if exists
        qrCodes.delete(req.userId);

        // Update WhatsApp session to inactive and clear session data
        await connection.query(
            `UPDATE whatsapp_sessions 
             SET is_active = FALSE, 
                 phone_number = NULL, 
                 pushname = NULL, 
                 session_data = NULL,
                 last_connected = NULL
             WHERE user_id = ?`,
            [req.userId]
        );

        await connection.commit();
        console.log(`WhatsApp disconnected and data cleared for user ${req.userId}`);
        
        // Respond immediately to user
        res.json({ 
            success: true, 
            message: 'WhatsApp disconnected successfully. Session data will be cleared shortly.' 
        });

        // Schedule auth folder deletion after response is sent
        // This prevents blocking the response
        setTimeout(async () => {
            const authPath = path.join('./auth_data', `session-user-${req.userId}`);
            await safeDeleteAuthFolder(authPath, 5, 2000);
        }, 3000); // Wait 3 seconds
        
    } catch (error) {
        await connection.rollback();
        console.error('Error disconnecting WhatsApp:', error);
        res.status(500).json({ error: error.message });
    } finally {
        connection.release();
    }
});



async function cleanupOrphanedAuthFolders() {
    try {
        const [sessions] = await pool.query(
            'SELECT user_id FROM whatsapp_sessions WHERE is_active = FALSE'
        );

        for (const session of sessions) {
            const authPath = path.join('./auth_data', `session-user-${session.user_id}`);
            if (fs.existsSync(authPath)) {
                console.log(`Cleaning up orphaned auth folder for user ${session.user_id}`);
                await safeDeleteAuthFolder(authPath, 3, 1000);
            }
        }
        
        console.log('Orphaned auth folders cleanup completed');
    } catch (error) {
        console.error('Error cleaning up orphaned folders:', error.message);
    }
}



// ADD this new endpoint for status checking
// Place this after your existing /api/whatsapp/qr route (around line 570)

app.get('/api/whatsapp/status', verifyJWT, async (req, res) => {
    try {
        const [sessions] = await pool.query(
            'SELECT is_active, phone_number, pushname, last_connected FROM whatsapp_sessions WHERE user_id = ?',
            [req.userId]
        );

        const isClientActive = clients.has(req.userId);
        
        res.json({
            connected: sessions[0]?.is_active && isClientActive,
            session: sessions[0] || null,
            clientActive: isClientActive
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// API TOKEN MANAGEMENT
// ============================================

// Generate API Token
app.post('/api/tokens/generate', verifyJWT, async (req, res) => {
    try {
        const { name, expiresInDays } = req.body;
        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = expiresInDays ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000) : null;

        await pool.query(
            'INSERT INTO api_tokens (user_id, token, name, expires_at) VALUES (?, ?, ?, ?)',
            [req.userId, token, name || 'API Token', expiresAt]
        );

        const [tokens] = await pool.query(
            'SELECT * FROM api_tokens WHERE token = ?',
            [token]
        );

        res.json({ token, tokenData: tokens[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get All Tokens
app.get('/api/tokens', verifyJWT, async (req, res) => {
    try {
        const [tokens] = await pool.query(
            'SELECT * FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC',
            [req.userId]
        );

        const tokenList = tokens.map(t => ({
            ...t,
            tokenPreview: t.token.substring(0, 8) + '...' + t.token.substring(t.token.length - 8)
        }));

        res.json(tokenList);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete Token
app.delete('/api/tokens/:id', verifyJWT, async (req, res) => {
    try {
        await pool.query(
            'DELETE FROM api_tokens WHERE id = ? AND user_id = ?',
            [req.params.id, req.userId]
        );
        res.json({ success: true });
    } catch (error) { 
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// MESSAGING ROUTES (API TOKEN PROTECTED)
// ============================================

// Get Messages with Filters (JWT Protected - for frontend dashboard)
app.get('/api/messages', verifyJWT, async (req, res) => {
    try {
        const { type, search, limit = 50, offset = 0 } = req.query;
        
        let query = 'SELECT * FROM messages WHERE user_id = ?';
        const params = [req.userId];
        
        // Filter by type
        if (type && type !== 'all') {
            query += ' AND type = ?';
            params.push(type);
        }
        
        // Search filter
        if (search && search.trim()) {
            query += ` AND (
                message_body LIKE ? OR 
                from_name LIKE ? OR 
                to_name LIKE ? OR 
                from_number LIKE ? OR 
                to_number LIKE ?
            )`;
            const searchPattern = `%${search.trim()}%`;
            params.push(searchPattern, searchPattern, searchPattern, searchPattern, searchPattern);
        }
        
        // Order by most recent first
        query += ' ORDER BY created_at DESC';
        
        // Pagination
        query += ' LIMIT ? OFFSET ?';
        params.push(parseInt(limit), parseInt(offset));
        
        const [messages] = await pool.query(query, params);
        
        res.json(messages);
    } catch (error) {
        console.error('Failed to fetch messages:', error);
        res.status(500).json({ error: error.message });
    }
});

// Send Message
// app.post('/api/send-message', verifyAPIToken, async (req, res) => {
//     try {
//         const { number, message } = req.body;
//         const client = clients.get(req.userId);

//         if (!client) {
//             return res.status(400).json({ error: 'WhatsApp not connected' });
//         }

//         const chatId = number.includes('@c.us') ? number : `${number}@c.us`;
//         const sentMessage = await client.sendMessage(chatId, message);

//         // Get contact info
//         let contactName = number;
//         try {
//             const contact = await client.getContactById(chatId);
//             contactName = contact.name || contact.pushname || number;
//         } catch (err) {
//             console.log('Could not get contact name:', err.message);
//         }

//         const myInfo = client.info;

//         // Save to database
//         await pool.query(
//             `INSERT INTO messages 
//             (user_id, message_id, type, from_number, from_name, to_number, to_name, 
//              message_body, has_media, status, timestamp) 
//             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
//             [
//                 req.userId,
//                 sentMessage.id.id,
//                 'sent',
//                 myInfo.wid.user,
//                 myInfo.pushname,
//                 number,
//                 contactName,
//                 message,
//                 false,
//                 'sent',
//                 sentMessage.timestamp
//             ]
//         );

//         await pool.query(
//             'UPDATE message_stats SET sent = sent + 1 WHERE user_id = ?',
//             [req.userId]
//         );

//         res.json({ 
//             success: true, 
//             message: 'Message sent successfully',
//             messageId: sentMessage.id.id
//         });
//     } catch (error) {
//         await pool.query(
//             'UPDATE message_stats SET failed = failed + 1 WHERE user_id = ?',
//             [req.userId]
//         );
//         res.status(500).json({ success: false, error: error.message });
//     }
// });

// Send Media
app.post('/api/send-media', verifyAPIToken, upload.single('file'), async (req, res) => {
    try {
        const { number, caption } = req.body;
        const client = clients.get(req.userId);

        if (!client) {
            return res.status(400).json({ error: 'WhatsApp not connected' });
        }

        const chatId = number.includes('@c.us') ? number : `${number}@c.us`;
        const media = MessageMedia.fromFilePath(req.file.path);
        
        const sentMessage = await client.sendMessage(chatId, media, { caption });

        // Get contact info
        let contactName = number;
        try {
            const contact = await client.getContactById(chatId);
            contactName = contact.name || contact.pushname || number;
        } catch (err) {
            console.log('Could not get contact name:', err.message);
        }

        const myInfo = client.info;

        // Determine media type
        const mediaType = req.file.mimetype.split('/')[0];

        // Save to database
        await pool.query(
            `INSERT INTO messages 
            (user_id, message_id, type, from_number, from_name, to_number, to_name, 
             message_body, has_media, media_type, media_url, status, timestamp) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                req.userId,
                sentMessage.id.id,
                'sent',
                myInfo.wid.user,
                myInfo.pushname,
                number,
                contactName,
                caption || null,
                true,
                mediaType,
                `/uploads/${req.file.filename}`,
                'sent',
                sentMessage.timestamp
            ]
        );

        await pool.query(
            'UPDATE message_stats SET sent = sent + 1 WHERE user_id = ?',
            [req.userId]
        );

        res.json({ 
            success: true, 
            message: 'Media sent successfully',
            messageId: sentMessage.id.id
        });
    } catch (error) {
        // Clean up file on error
        if (req.file && fs.existsSync(req.file.path)) {
            fs.unlinkSync(req.file.path);
        }
        
        await pool.query(
            'UPDATE message_stats SET failed = failed + 1 WHERE user_id = ?',
            [req.userId]
        );
        res.status(500).json({ success: false, error: error.message });
    }
});

// Get Stats
// app.get('/api/stats', verifyAPIToken, async (req, res) => {
//     try {
//         const [stats] = await pool.query(
//             'SELECT * FROM message_stats WHERE user_id = ?',
//             [req.userId]
//         );
//         res.json(stats[0] || { sent: 0, received: 0, failed: 0 });
//     } catch (error) {
//         res.status(500).json({ error: error.message });
//     }
// });

// Get Chats
// app.get('/api/chats', verifyAPIToken, async (req, res) => {
//     try {
//         const client = clients.get(req.userId);
//         if (!client) {
//             return res.status(400).json({ error: 'WhatsApp not connected' });
//         }

//         const chats = await client.getChats();
//         const chatList = chats.map(chat => ({
//             id: chat.id._serialized,
//             name: chat.name,
//             isGroup: chat.isGroup,
//             unreadCount: chat.unreadCount
//         }));
//         res.json(chatList);
//     } catch (error) {
//         res.status(500).json({ error: error.message });
//     }
// });

// Get Contacts
// app.get('/api/contacts', verifyAPIToken, async (req, res) => {
//     try {
//         const client = clients.get(req.userId);
//         if (!client) {
//             return res.status(400).json({ error: 'WhatsApp not connected' });
//         }

//         const contacts = await client.getContacts();
//         const contactList = contacts
//             .filter(c => c.isMyContact && !c.isGroup)
//             .map(c => ({
//                 id: c.id._serialized,
//                 name: c.name || c.pushname,
//                 number: c.number
//             }));
//         res.json(contactList);
//     } catch (error) {
//         res.status(500).json({ error: error.message });
//     }
// });

// Status
app.get('/api/status', verifyJWT, async (req, res) => {
    try {
        const [sessions] = await pool.query(
            'SELECT * FROM whatsapp_sessions WHERE user_id = ?',
            [req.userId]
        );

        const [stats] = await pool.query(
            'SELECT * FROM message_stats WHERE user_id = ?',
            [req.userId]
        );

        res.json({
            ready: sessions[0]?.is_active || false,
            session: sessions[0] || null,
            stats: stats[0] || { sent: 0, received: 0, failed: 0 }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete a specific message
app.delete('/api/messages/:id', verifyJWT, async (req, res) => {
    try {
        await pool.query(
            'DELETE FROM messages WHERE id = ? AND user_id = ?',
            [req.params.id, req.userId]
        );
        res.json({ success: true, message: 'Message deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Clear all messages
app.delete('/api/messages', verifyJWT, async (req, res) => {
    try {
        await pool.query(
            'DELETE FROM messages WHERE user_id = ?',
            [req.userId]
        );
        res.json({ success: true, message: 'All messages cleared successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Restore existing sessions on startup
async function restoreExistingSessions() {
    try {
        const [sessions] = await pool.query(
            'SELECT user_id FROM whatsapp_sessions WHERE is_active = TRUE'
        );

        for (const session of sessions) {
            console.log(`Restoring session for user ${session.user_id}`);
            await initializeClientForUser(session.user_id);
        }
    } catch (error) {
        console.error('Error restoring sessions:', error);
    }
}

app.listen(PORT, async () => {
    console.log(`Server running on http://localhost:${PORT}`);
    
    // Clean up any orphaned auth folders first
    await cleanupOrphanedAuthFolders();
    
    // Then restore active sessions
    await restoreExistingSessions();
});