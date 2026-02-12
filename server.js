const express = require("express");
const cors = require("cors");
const { Client, LocalAuth, MessageMedia } = require("whatsapp-web.js");
const qrcode = require("qrcode");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const axios = require("axios");

const app = express();
const PORT = process.env.PORT || 5000;

// Environment variables
const PHP_API_URL =
  process.env.PHP_API_URL || "https://rightmsg.in/whatsapp-api/api.php";
const FRONTEND_URL = process.env.FRONTEND_URL || "https://rightmsg.in";
const NODE_ENV = process.env.NODE_ENV || "development";

// Debug configuration
const DEBUG_MODE = process.env.DEBUG_MODE === "true" || true;
const DEBUG_TAG = "🕵️‍♂️ [DEBUG]";

// ⭐ NEW: Global error handlers to prevent crashes
process.on('uncaughtException', (error) => {
  console.error('❌ UNCAUGHT EXCEPTION:', error);
  console.error('Stack:', error.stack);
  // Don't exit - try to continue
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ UNHANDLED REJECTION at:', promise);
  console.error('Reason:', reason);
  // Don't exit - try to continue
});

// Debug logging function
function debugLog(...args) {
  if (DEBUG_MODE) {
    const timestamp = new Date().toISOString();
    console.log(`${DEBUG_TAG} ${timestamp}:`, ...args);
  }
}

// CORS Configuration
app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  }),
);

app.use(express.json());
app.use("/uploads", express.static("uploads"));

// Configure multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// Create directories
["uploads", "auth_data"].forEach((dir) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// WhatsApp Client Management
const clients = new Map();
const qrCodes = new Map();
const clientInitializing = new Map();
const initializationPromises = new Map();
const eventListenersAttached = new Map();
const deviceTokens = new Map();
const userDevices = new Map();

// Token caching
const tokenCache = new Map();
const TOKEN_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Helper to cache tokens
function cacheToken(token, userData) {
  tokenCache.set(token, {
    data: userData,
    timestamp: Date.now(),
  });

  setTimeout(() => {
    tokenCache.delete(token);
  }, TOKEN_CACHE_TTL);
}

function getCachedToken(token) {
  const cached = tokenCache.get(token);
  if (!cached) return null;

  if (Date.now() - cached.timestamp > TOKEN_CACHE_TTL) {
    tokenCache.delete(token);
    return null;
  }

  return cached.data;
}

// ⭐ IMPROVED: Safer Puppeteer configuration
function getPuppeteerConfig() {
  return {
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
      '--disable-web-security',
      '--disable-features=IsolateOrigins,site-per-process',
      '--disable-blink-features=AutomationControlled',
      '--disable-background-networking',
      '--disable-background-timer-throttling',
      '--disable-backgrounding-occluded-windows',
      '--disable-breakpad',
      '--disable-client-side-phishing-detection',
      '--disable-component-update',
      '--disable-default-apps',
      '--disable-extensions',
      '--disable-features=TranslateUI',
      '--disable-hang-monitor',
      '--disable-ipc-flooding-protection',
      '--disable-popup-blocking',
      '--disable-prompt-on-repost',
      '--disable-renderer-backgrounding',
      '--disable-sync',
      '--force-color-profile=srgb',
      '--metrics-recording-only',
      '--no-default-browser-check',
      '--safebrowsing-disable-auto-update',
      '--enable-automation',
      '--password-store=basic',
      '--use-mock-keychain'
    ],
    ignoreDefaultArgs: ['--disable-extensions'],
    // ⭐ CRITICAL: Set timeout for browser launch
    timeout: 60000, // 60 seconds
  };
}

// Monkey patch for deprecated method
Client.prototype.getContactModel = async function (contactId) {
  try {
    const contact = await this.pupPage.evaluate(async (contactId) => {
      try {
        const contact = window.Store.Contact.get(contactId);
        if (contact) {
          return {
            id: contact.id,
            name: contact.name || contact.pushname || contact.id.user,
            number: contact.id.user,
            pushname: contact.pushname || "",
            isMyContact: contact.isMyContact || false,
            isUser: contact.isUser || false,
            isGroup: contact.isGroup || false,
            isWAContact: contact.isWAContact || false,
          };
        }

        const oldContact = await window.WWebJS.getContact(contactId);
        return oldContact;
      } catch (error) {
        console.error("Error getting contact:", error);
        return {
          id: { _serialized: contactId },
          name: contactId.split("@")[0],
          number: contactId.split("@")[0],
          isMyContact: false,
        };
      }
    }, contactId);

    return contact;
  } catch (error) {
    debugLog(`Error in getContactModel: ${error.message}`);
    return {
      id: { _serialized: contactId },
      name: contactId.split("@")[0],
      number: contactId.split("@")[0],
      isMyContact: false,
    };
  }
};

// Helper function to call PHP API with debug logging
async function callPHPAPI(
  endpoint,
  method = "GET",
  data = null,
  token = null,
  retries = 2,
) {
  const callId = Math.random().toString(36).substring(7);
  debugLog(`[${callId}] PHP API Call: ${method} ${endpoint}`);

  if (DEBUG_MODE) {
    console.log(
      `${DEBUG_TAG} [${callId}] Token:`,
      token ? `${token.substring(0, 10)}...` : "None",
    );
    if (data && Object.keys(data).length > 0) {
      console.log(
        `${DEBUG_TAG} [${callId}] Request Data:`,
        JSON.stringify(data, null, 2),
      );
    }
    console.log(`${DEBUG_TAG} [${callId}] Full URL: ${PHP_API_URL}${endpoint}`);
  }

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const config = {
        method,
        url: `${PHP_API_URL}${endpoint}`,
        headers: {
          "Content-Type": "application/json",
        },
        timeout: 15000,
      };

      if (token) {
        config.headers["Authorization"] = `Bearer ${token}`;
      }

      if (data) {
        config.data = data;
      }

      debugLog(
        `[${callId}] Attempt ${attempt + 1}/${retries + 1} - Making request...`,
      );
      const response = await axios(config);

      debugLog(`[${callId}] Response Status: ${response.status}`);
      if (DEBUG_MODE) {
        console.log(
          `${DEBUG_TAG} [${callId}] Response Headers:`,
          response.headers,
        );
        console.log(
          `${DEBUG_TAG} [${callId}] Response Data:`,
          JSON.stringify(response.data, null, 2),
        );
      }

      return response.data;
    } catch (error) {
      debugLog(`[${callId}] Attempt ${attempt + 1} failed: ${error.message}`);

      if (DEBUG_MODE) {
        if (error.response) {
          console.log(
            `${DEBUG_TAG} [${callId}] Error Response Status: ${error.response.status}`,
          );
          console.log(
            `${DEBUG_TAG} [${callId}] Error Response Headers:`,
            error.response.headers,
          );
          console.log(
            `${DEBUG_TAG} [${callId}] Error Response Data:`,
            JSON.stringify(error.response.data, null, 2),
          );
        } else if (error.request) {
          console.log(
            `${DEBUG_TAG} [${callId}] No response received:`,
            error.request,
          );
        } else {
          console.log(
            `${DEBUG_TAG} [${callId}] Error setting up request:`,
            error.message,
          );
        }
      }

      if (error.response?.status === 401 || error.response?.status === 403) {
        debugLog(`[${callId}] Auth error detected, not retrying`);
        throw error;
      }

      if (
        attempt < retries &&
        (!error.response || error.response.status >= 500)
      ) {
        const delay = 1000 * (attempt + 1);
        debugLog(`[${callId}] Retrying in ${delay}ms...`);
        await new Promise((resolve) => setTimeout(resolve, delay));
        continue;
      }

      if (error.response) {
        const phpError = new Error(
          error.response.data.error ||
            `PHP API error: ${error.response.status}`,
        );
        phpError.status = error.response.status;
        phpError.responseData = error.response.data;
        throw phpError;
      }
      throw error;
    }
  }
}

function extractToken(req) {
  const authHeader = req.headers["authorization"];
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return authHeader.substring(7);
  }
  return null;
}

// Middleware to verify JWT tokens
async function verifyAuth(req, res, next) {
  const token = extractToken(req);

  debugLog(`Auth verification started for path: ${req.path}`);

  if (!token) {
    console.error("❌ No token provided in request");
    return res.status(401).json({
      error: "No token provided",
      code: "NO_TOKEN",
    });
  }

  try {
    const cachedData = getCachedToken(token);
    if (cachedData) {
      debugLog(`Using cached token data for user ${cachedData.user.id}`);
      req.userId = cachedData.user.id;
      req.token = token;
      req.user = cachedData.user;
      req.authType = "jwt";
      return next();
    }

    debugLog(`Verifying JWT token for request: ${req.method} ${req.path}`);

    const userData = await callPHPAPI("/auth/me", "GET", null, token);

    if (!userData || !userData.user) {
      debugLog("Invalid user data received from PHP API:", userData);
      return res.status(401).json({
        error: "Invalid user data",
        code: "INVALID_USER_DATA",
      });
    }

    cacheToken(token, userData);

    debugLog(
      `JWT Token verified for user ${userData.user.id} (${userData.user.email})`,
    );
    req.userId = userData.user.id;
    req.token = token;
    req.user = userData.user;
    req.authType = "jwt";
    next();
  } catch (error) {
    debugLog(`JWT Auth verification failed:`, error.message);

    tokenCache.delete(token);

    if (
      error.message.includes("signature") ||
      error.message.includes("Invalid token")
    ) {
      return res.status(401).json({
        error: "Invalid token signature",
        code: "INVALID_SIGNATURE",
        details: "Please log out and log in again",
      });
    }

    if (
      error.message.includes("expired") ||
      error.message.includes("jwt expired")
    ) {
      return res.status(401).json({
        error: "Token expired",
        code: "TOKEN_EXPIRED",
        details: "Your session has expired. Please login again.",
      });
    }

    return res.status(401).json({
      error: "Authentication failed",
      code: "AUTH_FAILED",
    });
  }
}

// Middleware to verify API tokens
async function verifyApiToken(req, res, next) {
  const token = extractToken(req);

  debugLog(`API Token verification started for path: ${req.path}`);

  if (!token) {
    console.error("❌ No API token provided");
    return res.status(401).json({
      error: "API token required",
      code: "NO_TOKEN",
    });
  }

  try {
    const cachedData = getCachedToken(`api_${token}`);
    if (cachedData) {
      debugLog(`Using cached API token data for user ${cachedData.user_id}`);
      req.userId = cachedData.user_id;
      req.token = token;
      req.apiTokenData = cachedData;
      req.authType = "api_token";
      return next();
    }

    debugLog(`Verifying API token for request: ${req.method} ${req.path}`);

    const result = await callPHPAPI("/tokens/verify", "POST", {}, token);

    if (!result || !result.valid) {
      debugLog("Invalid API token received:", result);
      return res.status(401).json({
        error: "Invalid or expired API token",
        code: "INVALID_API_TOKEN",
      });
    }

    cacheToken(`api_${token}`, result);

    debugLog(`API Token verified for user ${result.user_id}`);
    req.userId = result.user_id;
    req.token = token;
    req.apiTokenData = result;
    req.authType = "api_token";

    callPHPAPI("/tokens/update-usage", "POST", { token }).catch((err) => {
      debugLog("Warning: Failed to update token usage:", err.message);
    });

    next();
  } catch (error) {
    debugLog(`API Token verification failed:`, error.message);

    tokenCache.delete(`api_${token}`);

    if (error.response?.status === 401 || error.response?.status === 403) {
      return res.status(401).json({
        error: "Invalid API token",
        code: "INVALID_API_TOKEN",
        details: "Token is invalid or expired",
      });
    }

    return res.status(401).json({
      error: "Token verification failed",
      code: "INVALID_API_TOKEN",
      details: error.response?.data?.error || "Could not verify token",
    });
  }
}

// Combined middleware
async function verifyAnyToken(req, res, next) {
  debugLog(`verifyAnyToken middleware called for path: ${req.path}`);
  const token = extractToken(req);

  if (!token) {
    debugLog("No token provided");
    return res.status(401).json({ error: "Authentication token required" });
  }

  const isJWT = token.includes(".") && token.split(".").length === 3;

  if (isJWT) {
    debugLog("Detected JWT token, using JWT auth");
    return verifyAuth(req, res, next);
  } else {
    debugLog("Detected API token, using API token auth");
    return verifyApiToken(req, res, next);
  }
}

// ⭐ IMPROVED: Initialize WhatsApp Client with better error handling
async function initializeClientForUser(userId, token, forceNew = false) {
  const clientKey = userId;

  if (initializationPromises.has(clientKey)) {
    debugLog(
      `Client initialization already in progress for user ${userId}, reusing promise...`,
    );
    return await initializationPromises.get(clientKey);
  }

  const initPromise = (async () => {
    let client = null;
    
    try {
      clientInitializing.set(clientKey, true);
      debugLog(`Starting client initialization for user ${userId}`);

      // Clean existing client if exists
      if (clients.has(clientKey)) {
        const oldClient = clients.get(clientKey);
        debugLog(`Destroying existing client for user ${userId}`);
        try {
          await safeDestroyClient(oldClient, userId);
        } catch (error) {
          debugLog(`Error destroying old client: ${error.message}`);
        }
        clients.delete(clientKey);
        eventListenersAttached.delete(clientKey);
      }

      // Clean QR code and state
      qrCodes.delete(clientKey);

      // Clean auth data if forceNew
      if (forceNew) {
        debugLog(`Force cleaning auth data for user ${userId}`);
        await cleanStaleAuthData(userId);
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }

      debugLog(`Creating new WhatsApp client for user ${userId}`);

      // ⭐ IMPROVED: Create client with better error handling
      client = new Client({
        authStrategy: new LocalAuth({
          clientId: `user-${userId}`,
        }),
        puppeteer: getPuppeteerConfig(),
        // ⭐ NEW: Add these options
        webVersionCache: {
          type: 'remote',
          remotePath: 'https://raw.githubusercontent.com/wppconnect-team/wa-version/main/html/2.2412.54.html',
        },
      });

      // ⭐ IMPROVED: Set up error handlers BEFORE initialization
      client.on('error', (error) => {
        debugLog(`❌ Client error for user ${userId}:`, error.message);
        // Don't crash - just log
      });

      client.on('disconnected', (reason) => {
        debugLog(`⚠️ Client disconnected for user ${userId}:`, reason);
        // Clean up
        clients.delete(clientKey);
        qrCodes.delete(clientKey);
        eventListenersAttached.delete(clientKey);
      });

      // ⭐ IMPROVED: QR Code handler with error handling
      client.once("qr", async (qr) => {
        debugLog(`QR Code received for user ${userId}`);
        try {
          const qrData = await qrcode.toDataURL(qr);
          qrCodes.set(clientKey, qrData);
          debugLog(`QR Code generated and stored for user ${userId}`);
        } catch (qrError) {
          debugLog(`Error generating QR code: ${qrError.message}`);
          // Don't throw - just log
        }
      });

      // Authentication handler
      client.once("authenticated", async () => {
        debugLog(`User ${userId} authenticated successfully`);
        qrCodes.delete(clientKey);
      });

      // ⭐ IMPROVED: Ready handler with better error handling
      client.once("ready", async () => {
        debugLog(`WhatsApp client ready for user ${userId}`);
        try {
          const info = client.info;
          debugLog(`Client info: ${info.pushname} (${info.wid.user})`);

          // Update session with retry logic
          let updateSuccess = false;
          for (let attempt = 0; attempt < 3; attempt++) {
            try {
              debugLog(
                `Attempt ${attempt + 1}/3 to update database session...`,
              );

              const updateResult = await callPHPAPI(
                "/whatsapp/session/update",
                "POST",
                {
                  phone_number: info.wid.user,
                  pushname: info.pushname,
                  is_active: 1,
                },
                token,
              );

              debugLog(`Database update result:`, updateResult);
              updateSuccess = true;
              break;
            } catch (error) {
              debugLog(`Attempt ${attempt + 1} failed: ${error.message}`);
              if (attempt < 2) {
                await new Promise((resolve) => setTimeout(resolve, 1000));
              }
            }
          }

          if (updateSuccess) {
            debugLog(
              `✅ Database session updated successfully for user ${userId}`,
            );
          } else {
            debugLog(`❌ Failed to update database session for user ${userId}`);
          }
        } catch (error) {
          debugLog(`Error in ready handler: ${error.message}`);
          // Don't throw - just log
        }
      });

      // ⭐ IMPROVED: Initialize with timeout
      debugLog(`Initializing WhatsApp client...`);
      
      const initTimeout = new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Initialization timeout after 60 seconds')), 60000)
      );
      
      await Promise.race([
        client.initialize(),
        initTimeout
      ]);
      
      debugLog(`Client initialization started for user ${userId}`);

      clients.set(clientKey, client);
      clientInitializing.delete(clientKey);

      // Wait a moment to see if we get a QR code or immediate connection
      await new Promise((resolve) => setTimeout(resolve, 2000));

      // Check initial state
      try {
        const state = await client.getState();
        debugLog(`Initial client state for user ${userId}: ${state}`);
      } catch (stateError) {
        debugLog(`Could not check initial state: ${stateError.message}`);
      }

      debugLog(`Client successfully initialized for user ${userId}`);

      return client;
    } catch (error) {
      debugLog(`❌ Error initializing client for user ${userId}:`, error.message);
      debugLog(`Error stack:`, error.stack);

      // ⭐ IMPROVED: Clean up everything on error
      clientInitializing.delete(clientKey);
      initializationPromises.delete(clientKey);
      eventListenersAttached.delete(clientKey);
      clients.delete(clientKey);
      qrCodes.delete(clientKey);

      // Destroy client if it was created
      if (client) {
        try {
          await safeDestroyClient(client, userId);
        } catch (destroyError) {
          debugLog(`Error destroying failed client: ${destroyError.message}`);
        }
      }

      // Force clean auth data on error
      try {
        await cleanStaleAuthData(userId);
      } catch (cleanError) {
        debugLog(`Error cleaning auth data: ${cleanError.message}`);
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

// ⭐ IMPROVED: Initialize client for device with better error handling
async function initializeClientForDevice(
  userId,
  deviceId,
  phoneNumber,
  token,
  forceNew = false,
) {
  const clientKey = `${userId}-${deviceId}`;

  if (initializationPromises.has(clientKey)) {
    debugLog(
      `Device initialization already in progress for ${clientKey}, reusing promise...`,
    );
    return await initializationPromises.get(clientKey);
  }

  const initPromise = (async () => {
    let client = null;
    
    try {
      clientInitializing.set(clientKey, true);
      debugLog(
        `Starting client initialization for device ${deviceId} (user ${userId})`,
      );

      // Clean existing client if exists
      if (clients.has(clientKey)) {
        const oldClient = clients.get(clientKey);
        debugLog(`Destroying existing client for device ${deviceId}`);
        try {
          await safeDestroyClient(oldClient, clientKey);
        } catch (error) {
          debugLog(`Error destroying old client: ${error.message}`);
        }
        clients.delete(clientKey);
        eventListenersAttached.delete(clientKey);
      }

      // Clean QR code and state
      qrCodes.delete(clientKey);

      // Clean auth data if forceNew
      if (forceNew) {
        debugLog(`Force cleaning auth data for device ${deviceId}`);
        await cleanStaleAuthData(clientKey);
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }

      debugLog(`Creating new WhatsApp client for device ${deviceId}`);

      client = new Client({
        authStrategy: new LocalAuth({
          clientId: `device-${deviceId}`,
        }),
        puppeteer: getPuppeteerConfig(),
        webVersionCache: {
          type: 'remote',
          remotePath: 'https://raw.githubusercontent.com/wppconnect-team/wa-version/main/html/2.2412.54.html',
        },
      });

      // Set up error handlers
      client.on('error', (error) => {
        debugLog(`❌ Device ${deviceId} error:`, error.message);
      });

      client.on('disconnected', (reason) => {
        debugLog(`⚠️ Device ${deviceId} disconnected:`, reason);
        clients.delete(clientKey);
        qrCodes.delete(clientKey);
        eventListenersAttached.delete(clientKey);
      });

      // QR Code handler
      client.once("qr", async (qr) => {
        debugLog(`QR Code received for device ${deviceId}`);
        try {
          const qrData = await qrcode.toDataURL(qr);
          qrCodes.set(clientKey, qrData);
          debugLog(`QR Code generated and stored for device ${deviceId}`);
        } catch (qrError) {
          debugLog(`Error generating QR code: ${qrError.message}`);
        }
      });

      // Authentication handler
      client.once("authenticated", async () => {
        debugLog(`Device ${deviceId} authenticated successfully`);
        qrCodes.delete(clientKey);
      });

      // Ready handler
      client.once("ready", async () => {
        debugLog(`WhatsApp client ready for device ${deviceId}`);
        try {
          const info = client.info;
          debugLog(`Device client info: ${info.pushname} (${info.wid.user})`);

          // Update device in database
          await callPHPAPI(
            `/devices/${deviceId}/update`,
            "POST",
            {
              phone_number: info.wid.user,
              pushname: info.pushname,
              is_active: 1,
              last_active: new Date().toISOString(),
            },
            token,
          );

          debugLog(`✅ Database updated for device ${deviceId}`);
        } catch (error) {
          debugLog(
            `Error in ready handler for device ${deviceId}: ${error.message}`,
          );
        }
      });

      // Message handler for device
      client.on("message", async (message) => {
        try {
          const contact = await message.getContact();
          const myInfo = client.info;

          await callPHPAPI(
            "/stats/update",
            "POST",
            {
              field: "received",
              increment: 1,
            },
            token,
          );

          const hasMedia = message.hasMedia;
          let mediaType = null;
          let mediaUrl = null;

          if (hasMedia) {
            try {
              const media = await message.downloadMedia();
              if (media) {
                mediaType = media.mimetype.split("/")[0];
                const extension = media.mimetype.split("/")[1] || "bin";
                const filename = `${Date.now()}_${message.id.id}.${extension}`;
                const filepath = path.join("uploads", filename);
                fs.writeFileSync(filepath, media.data, "base64");
                mediaUrl = `/uploads/${filename}`;
              }
            } catch (mediaError) {
              debugLog("Error downloading media:", mediaError);
            }
          }

          await callPHPAPI(
            "/messages/save",
            "POST",
            {
              message_id: message.id.id,
              type: "received",
              from_number: contact.number,
              from_name: contact.name || contact.pushname || contact.number,
              to_number: myInfo.wid.user,
              to_name: myInfo.pushname,
              message_body: message.body || null,
              has_media: hasMedia,
              media_type: mediaType,
              media_url: mediaUrl,
              status: "received",
              timestamp: message.timestamp,
              device_id: deviceId,
            },
            token,
          );

          debugLog(`✓ Message saved for device ${deviceId}`);
        } catch (error) {
          debugLog(
            `✗ Error saving received message for device ${deviceId}:`,
            error,
          );
        }
      });

      debugLog(`🚀 Initializing WhatsApp client for device ${deviceId}...`);
      
      const initTimeout = new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Device initialization timeout after 60 seconds')), 60000)
      );
      
      await Promise.race([
        client.initialize(),
        initTimeout
      ]);

      clients.set(clientKey, client);
      clientInitializing.delete(clientKey);

      debugLog(`✅ Client successfully initialized for device ${deviceId}`);

      return client;
    } catch (error) {
      debugLog(
        `✗ Error initializing client for device ${deviceId}:`,
        error.message,
      );
      debugLog(`Error stack:`, error.stack);

      // Clean up on error
      clientInitializing.delete(clientKey);
      initializationPromises.delete(clientKey);
      eventListenersAttached.delete(clientKey);
      clients.delete(clientKey);
      qrCodes.delete(clientKey);

      if (client) {
        try {
          await safeDestroyClient(client, clientKey);
        } catch (destroyError) {
          debugLog(`Error destroying failed client: ${destroyError.message}`);
        }
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

// Helper to safely delete auth folder
async function safeDeleteAuthFolder(
  authPath,
  maxRetries = 8,
  baseDelay = 1000,
) {
  if (!fs.existsSync(authPath)) {
    return true;
  }

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      if (process.platform === "win32") {
        try {
          const { execSync } = require("child_process");
          execSync(
            "taskkill /f /im chrome.exe /t 2>nul || taskkill /f /im chromedriver.exe /t 2>nul",
            { stdio: "ignore" },
          );
        } catch (e) {
          // Ignore errors
        }
      }

      const delay = baseDelay * Math.pow(2, attempt);
      if (attempt > 0) {
        debugLog(
          `Retry ${attempt}/${maxRetries} to delete auth folder (waiting ${delay}ms)...`,
        );
        await new Promise((resolve) => setTimeout(resolve, delay));
      }

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
          debugLog(`Could not delete ${filePath}: ${fileError.message}`);
        }
      }

      fs.rmSync(authPath, {
        recursive: true,
        force: true,
        maxRetries: 3,
        retryDelay: 1000,
      });

      debugLog(`Successfully deleted auth data: ${authPath}`);
      return true;
    } catch (error) {
      if (attempt === maxRetries - 1) {
        debugLog(
          `Failed to delete auth folder after ${maxRetries} attempts: ${error.message}`,
        );

        try {
          const cleanupMarker = path.join(
            "./auth_data",
            `cleanup-needed-${Date.now()}`,
          );
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
  if (process.platform !== "win32") return;

  try {
    const { execSync } = require("child_process");

    const processes = ["chrome.exe", "chromedriver.exe", "node.exe"];

    for (const proc of processes) {
      try {
        execSync(
          `tasklist /fi "imagename eq ${proc}" | find /i "${proc}" >nul && (
                    taskkill /f /im ${proc} /t
                    echo Killed ${proc}
                ) || echo ${proc} not running`,
          { stdio: "ignore", shell: true },
        );
      } catch (e) {
        // Process might not exist
      }
    }

    try {
      execSync("wmic process where \"name='chrome.exe'\" delete 2>nul", {
        stdio: "ignore",
      });
    } catch (e) {}
  } catch (error) {
    debugLog("Chrome process cleanup warning:", error.message);
  }
}

// Helper to check if auth folder exists and has valid session
function hasValidAuthSession(userId) {
  const authPath = path.join("./auth_data", `session-user-${userId}`);
  return fs.existsSync(authPath);
}

// Helper to clean stale auth data
async function cleanStaleAuthData(userId) {
  const authPath = path.join("./auth_data", `session-user-${userId}`);

  if (!fs.existsSync(authPath)) {
    return true;
  }

  debugLog(`Enhanced cleaning for user ${userId} auth data...`);

  await killChromeProcesses();

  await new Promise((resolve) => setTimeout(resolve, 2000));

  const result = await safeDeleteAuthFolder(authPath);

  if (!result) {
    debugLog(
      `Could not immediately delete auth data for user ${userId}, will retry later`,
    );
    setTimeout(() => safeDeleteAuthFolder(authPath), 30000);
  }

  return result;
}

// ⭐ IMPROVED: Safer client destruction
async function safeDestroyClient(client, userId) {
  if (!client) return;

  try {
    debugLog(`Starting safe destruction for ${userId}...`);

    // Stop any heartbeats first
    if (eventListenersAttached.has(userId)) {
      eventListenersAttached.delete(userId);
    }

    // Remove from tracking maps
    clients.delete(userId);
    qrCodes.delete(userId);
    clientInitializing.delete(userId);
    initializationPromises.delete(userId);

    // ⭐ IMPROVED: Try to destroy client with timeout
    if (typeof client.destroy === "function") {
      const destroyTimeout = new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Destroy timeout')), 10000)
      );
      
      await Promise.race([
        client.destroy(),
        destroyTimeout
      ]).catch((err) => {
        debugLog(`Graceful destroy failed: ${err.message}`);
      });
    }

    // Kill Chrome processes
    await killChromeProcesses();

    debugLog(`Client safely destroyed for ${userId}`);
  } catch (error) {
    debugLog(`Error in safeDestroyClient for ${userId}:`, error.message);
  }
}

function getRandomConnectedDevice(userId, devices) {
  const connectedDevices = devices.filter((device) => {
    const clientKey = `${userId}-${device.device_id}`;
    const client = clients.get(clientKey);
    if (!client) return false;

    try {
      return client.pupBrowser?.isConnected?.() !== false;
    } catch {
      return false;
    }
  });

  if (connectedDevices.length === 0) return null;

  const randomIndex = Math.floor(Math.random() * connectedDevices.length);
  return connectedDevices[randomIndex];
}

function isNumeric(value) {
  if (typeof value === "number") return true;
  if (typeof value === "string") {
    return !isNaN(value) && !isNaN(parseFloat(value));
  }
  return false;
}

// Export for use in main server file
module.exports = {
  verifyAuth,
  verifyApiToken,
  verifyAnyToken,
  callPHPAPI,
  cacheToken,
  getCachedToken,
  tokenCache,
};

// Request logging middleware
app.use((req, res, next) => {
  debugLog(`${req.method} ${req.url} - Headers:`, req.headers);
  next();
});

// Health check
app.get("/api/health", (req, res) => {
  debugLog("Health check called");
  const token = extractToken(req);
  const isAuthenticated = token && getCachedToken(token) !== null;

  res.status(200).json({
    status: "ok",
    message: "WhatsApp Server is running",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    activeClients: clients.size,
    cachedTokens: tokenCache.size,
    environment: NODE_ENV,
    authenticated: isAuthenticated,
  });
});

// ... REST OF YOUR ENDPOINTS (keeping them unchanged to save space) ...
// I'll include the critical /api/whatsapp/initialize endpoint with improvements

// ⭐ IMPROVED: WhatsApp initialization endpoint
app.post("/api/whatsapp/initialize", verifyAuth, async (req, res) => {
  debugLog(`POST /api/whatsapp/initialize called by user ${req.userId}`);

  try {
    const clientKey = req.userId;

    // Check if already connected
    const existingClient = clients.get(clientKey);
    if (existingClient) {
      try {
        const statePromise = existingClient.getState();
        const timeoutPromise = new Promise((_, reject) =>
          setTimeout(() => reject(new Error("timeout")), 3000)
        );

        const state = await Promise.race([statePromise, timeoutPromise]);
        
        if (state === "CONNECTED") {
          debugLog(`Client already connected for user ${req.userId}`);
          return res.json({
            success: true,
            alreadyConnected: true,
            message: "WhatsApp is already connected",
          });
        }
      } catch (error) {
        debugLog(`Existing client check failed: ${error.message}`);
        // Clean up the stuck client
        await safeDestroyClient(existingClient, req.userId);
      }
    }

    // Check if already initializing
    if (initializationPromises.has(clientKey)) {
      debugLog(`Initialization already in progress for user ${req.userId}`);
      return res.status(429).json({
        error: "Initialization already in progress",
        message: "Please wait for the current initialization to complete",
      });
    }

    debugLog(`Starting WhatsApp initialization for user ${req.userId}`);

    // Start initialization (don't await fully)
    initializeClientForUser(req.userId, req.token, true).catch((err) => {
      debugLog(`Background initialization error: ${err.message}`);
    });

    // Wait up to 10 seconds for QR code to appear
    const maxWaitTime = 10000;
    const checkInterval = 500;
    let waited = 0;

    while (waited < maxWaitTime) {
      if (qrCodes.has(clientKey)) {
        debugLog(`QR code generated after ${waited}ms`);
        return res.json({
          success: true,
          message: "QR code ready",
          qrReady: true,
        });
      }

      await new Promise((resolve) => setTimeout(resolve, checkInterval));
      waited += checkInterval;
    }

    // If no QR after 10 seconds, still return success
    debugLog(`No QR after ${waited}ms, client still initializing`);
    res.json({
      success: true,
      message: "WhatsApp client initializing, please wait for QR code",
      qrReady: false,
    });
  } catch (error) {
    debugLog("Initialize error:", error.message);
    debugLog("Error stack:", error.stack);
    res.status(500).json({
      error: error.message,
      message: "Failed to initialize WhatsApp. Please try again.",
    });
  }
});

// ... (Include all other endpoints from your original file)

// Cleanup on server shutdown
process.on("SIGTERM", gracefulShutdown);
process.on("SIGINT", gracefulShutdown);

async function gracefulShutdown(signal) {
  debugLog(`${signal} received, starting graceful shutdown...`);

  // Clear token cache
  tokenCache.clear();

  // Destroy all WhatsApp clients
  const destroyPromises = [];
  for (const [userId, client] of clients.entries()) {
    destroyPromises.push(
      safeDestroyClient(client, userId).catch((error) => {
        debugLog(`Error destroying client for user ${userId}:`, error.message);
      })
    );
  }

  // Wait for all clients to be destroyed (with timeout)
  await Promise.race([
    Promise.all(destroyPromises),
    new Promise(resolve => setTimeout(resolve, 15000)) // 15 second timeout
  ]);

  debugLog("Graceful shutdown complete");
  process.exit(0);
}

// ⭐ NEW: Periodic cleanup of stuck clients
setInterval(() => {
  debugLog('Running periodic client health check...');
  
  for (const [userId, client] of clients.entries()) {
    if (!client || !client.pupBrowser) {
      debugLog(`Removing dead client for ${userId}`);
      clients.delete(userId);
      qrCodes.delete(userId);
      eventListenersAttached.delete(userId);
      continue;
    }
    
    // Check if browser is connected
    try {
      if (!client.pupBrowser.isConnected()) {
        debugLog(`Browser disconnected for ${userId}, cleaning up`);
        safeDestroyClient(client, userId);
      }
    } catch (error) {
      debugLog(`Health check error for ${userId}: ${error.message}`);
    }
  }
}, 5 * 60 * 1000); // Every 5 minutes

app.listen(PORT, () => {
  debugLog(`WhatsApp Server running on port ${PORT}`);
  debugLog(`Environment: ${NODE_ENV}`);
  debugLog(`PHP API URL: ${PHP_API_URL}`);
  debugLog(`Frontend URL: ${FRONTEND_URL}`);
  debugLog(`Server ready to accept connections`);
});