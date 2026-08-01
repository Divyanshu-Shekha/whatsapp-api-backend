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
  process.env.PHP_API_URL || "https://rightmsg.info/whatsapp-api/api.php";
const FRONTEND_URL = process.env.FRONTEND_URL || "https://rightmsg.info";
const NODE_ENV = process.env.NODE_ENV || "development";

// Debug configuration
const DEBUG_MODE = process.env.DEBUG_MODE === "true" || true;
const DEBUG_TAG = "🕵️‍♂️ [DEBUG]";

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
    timestamp: Date.now(),
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

// Fix for ContactMethods.getIsMyContact deprecation
// Add this before creating your Client instances

// const { Client } = require('whatsapp-web.js');

// Monkey patch the problematic method
Client.prototype.getContactModel = async function (contactId) {
  const contact = await this.pupPage.evaluate(async (contactId) => {
    try {
      // Try new method structure first
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

      // Fallback to old method
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

      // Don't retry on auth errors
      if (error.response?.status === 401 || error.response?.status === 403) {
        debugLog(`[${callId}] Auth error detected, not retrying`);
        throw error;
      }

      // Retry on network errors or 500s
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

// Middleware to verify JWT tokens (for dashboard/UI)
async function verifyAuth(req, res, next) {
  const token = extractToken(req);

  debugLog(`Auth verification started for path: ${req.path}`);
  debugLog(`Request headers:`, req.headers);

  if (!token) {
    console.error("❌ No token provided in request");
    debugLog("No Authorization header found");
    return res.status(401).json({
      error: "No token provided",
      code: "NO_TOKEN",
    });
  }

  try {
    // Check cache first
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

    // Verify token by calling PHP API
    const userData = await callPHPAPI("/auth/me", "GET", null, token);

    if (!userData || !userData.user) {
      debugLog("Invalid user data received from PHP API:", userData);
      return res.status(401).json({
        error: "Invalid user data",
        code: "INVALID_USER_DATA",
      });
    }

    // Cache the token
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
    debugLog(`Error details:`, error);

    // Clear token from cache on error
    tokenCache.delete(token);

    // Provide specific error codes
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

// function findChrome() {
//   const possiblePaths = [
//     "/usr/bin/google-chrome",
//     "/usr/bin/google-chrome-stable",
//     "/usr/bin/chromium",
//     "/usr/bin/chromium-browser",
//     process.env.PUPPETEER_EXECUTABLE_PATH,
//   ];

//   for (const path of possiblePaths) {
//     if (path && fs.existsSync(path)) {
//       console.log(`✅ Found Chrome at: ${path}`);
//       return path;
//     }
//   }

//   console.error("❌ Chrome not found in any standard location");
//   return null;
// }

// const chromePath = findChrome();

// if (!chromePath) {
//   throw new Error(
//     "Chrome executable not found. Please check Docker installation.",
//   );
// }

// NEW: Middleware to verify API tokens (for external API calls)
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
    // Check cache first
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

    // Verify API token by calling PHP API
    // FIX: Don't send token in body, just use it as the auth header
    const result = await callPHPAPI("/tokens/verify", "POST", {}, token); // Only token in headers

    if (!result || !result.valid) {
      debugLog("Invalid API token received:", result);
      return res.status(401).json({
        error: "Invalid or expired API token",
        code: "INVALID_API_TOKEN",
      });
    }

    // Cache the API token
    cacheToken(`api_${token}`, result);

    debugLog(`API Token verified for user ${result.user_id}`);
    req.userId = result.user_id;
    req.token = token;
    req.apiTokenData = result;
    req.authType = "api_token";

    // Update token usage stats (async, don't wait)
    callPHPAPI("/tokens/update-usage", "POST", { token }).catch((err) => {
      debugLog("Warning: Failed to update token usage:", err.message);
    });

    next();
  } catch (error) {
    debugLog(`API Token verification failed:`, error.message);

    // Clear from cache
    tokenCache.delete(`api_${token}`);

    // Provide more detailed error information
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

// NEW: Combined middleware - accepts both JWT and API tokens
async function verifyAnyToken(req, res, next) {
  debugLog(`verifyAnyToken middleware called for path: ${req.path}`);
  const token = extractToken(req);

  if (!token) {
    debugLog("No token provided");
    return res.status(401).json({ error: "Authentication token required" });
  }

  // Check token length to determine type
  // JWT tokens are much longer (3 parts separated by dots)
  // API tokens are typically 64 characters (sha256 hash)

  const isJWT = token.includes(".") && token.split(".").length === 3;

  if (isJWT) {
    debugLog("Detected JWT token, using JWT auth");
    return verifyAuth(req, res, next);
  } else {
    debugLog("Detected API token, using API token auth");
    return verifyApiToken(req, res, next);
  }
}

function getPuppeteerConfig() {
  return {
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-ipv6",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-accelerated-2d-canvas",
      "--no-first-run",
      "--disable-gpu",
      "--disable-web-security",
      "--disable-features=IsolateOrigins,site-per-process",
      "--disable-blink-features=AutomationControlled",
      "--disable-background-networking",
      "--disable-background-timer-throttling",
      "--disable-backgrounding-occluded-windows",
      "--disable-breakpad",
      "--disable-client-side-phishing-detection",
      "--disable-component-update",
      "--disable-default-apps",
      "--disable-extensions",
      "--disable-features=TranslateUI",
      "--disable-hang-monitor",
      "--disable-ipc-flooding-protection",
      "--disable-popup-blocking",
      "--disable-prompt-on-repost",
      "--disable-renderer-backgrounding",
      "--disable-sync",
      "--force-color-profile=srgb",
      "--metrics-recording-only",
      "--no-default-browser-check",
      "--safebrowsing-disable-auto-update",
      "--enable-automation",
      "--password-store=basic",
      "--use-mock-keychain",
      // REMOVED UNSTABLE FLAGS:
      // '--single-process',
      // '--no-zygote',
    ],
    ignoreDefaultArgs: ["--disable-extensions"],
    timeout: 120000,
    // ADD THESE:
    dumpio: false, // Don't dump browser console
  };
}

// Initialize WhatsApp Client for Device
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
        // webVersion: '2.3000.1035211615',
        // webVersionCache: {
        //   type: 'remote',
        //   remotePath: 'https://raw.githubusercontent.com/wppconnect-team/wa-version/main/html/2.3000.1035211615-alpha.html',
        // },
         webVersionCache: {
          type: 'local',
        },
      });

      // ⭐ IMPROVED: Set up error handlers BEFORE initialization
      client.on("error", (error) => {
        debugLog(`❌ Client error for user ${userId}:`, error.message);
        // Don't crash - just log
      });

      client.on("disconnected", (reason) => {
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
        setTimeout(
          () => reject(new Error("Initialization timeout after 60 seconds")),
          120000,
        ),
      );

      await Promise.race([client.initialize(), initTimeout]);

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
      debugLog(
        `❌ Error initializing client for user ${userId}:`,
        error.message,
      );
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

// Add this function (NEW)
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
        // webVersion: '2.3000.1035211615',
        // webVersionCache: {
        //   type: 'remote',
        //   remotePath: 'https://raw.githubusercontent.com/wppconnect-team/wa-version/main/html/2.3000.1035211615-alpha.html',
        // },
         webVersionCache: {
          type: 'local',
        },
      });

      // Set up error handlers
      client.on("error", (error) => {
        debugLog(`❌ Device ${deviceId} error:`, error.message);
      });

      client.on("disconnected", (reason) => {
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
              user_id: userId,
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
        setTimeout(
          () =>
            reject(
              new Error("Device initialization timeout after 120 seconds"),
            ),
          120000,
        ),
      );

      await Promise.race([client.initialize(), initTimeout]);

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
// Track pending retries to avoid stacking
// const pendingCleanups = new Map();

// async function cleanStaleAuthData(userId) {
//   // Handle BOTH user and device auth path formats
//   const possiblePaths = [
//     path.join("./auth_data", `session-user-${userId}`),    // user: "42"
//     path.join("./auth_data", `session-device-${userId}`),  // device: "device-123"
//     path.join("./auth_data", `session-${userId}`),         // fallback
//   ];

//   // Filter to only paths that actually exist
//   const existingPaths = possiblePaths.filter(p => fs.existsSync(p));

//   if (existingPaths.length === 0) {
//     debugLog(`No auth data found for ${userId}, skipping cleanup`);
//     return true;
//   }

//   debugLog(`Cleaning ${existingPaths.length} auth path(s) for ${userId}...`);

//   // Cancel any pending retry for this userId
//   if (pendingCleanups.has(userId)) {
//     clearTimeout(pendingCleanups.get(userId));
//     pendingCleanups.delete(userId);
//     debugLog(`Cancelled pending cleanup retry for ${userId}`);
//   }

//   // Only kill Chrome on Windows, and only if no other clients are active
//   if (process.platform === "win32" && clients.size === 0) {
//     await killChromeProcesses();
//     await new Promise((resolve) => setTimeout(resolve, 1000)); // shorter wait
//   }

//   let allSuccess = true;

//   for (const authPath of existingPaths) {
//     debugLog(`Deleting: ${authPath}`);
//     const result = await safeDeleteAuthFolder(authPath);

//     if (!result) {
//       allSuccess = false;
//       debugLog(`Could not delete ${authPath}, scheduling retry...`);

//       // Only schedule ONE retry per userId, not per path
//       if (!pendingCleanups.has(userId)) {
//         const retryTimer = setTimeout(async () => {
//           pendingCleanups.delete(userId);
//           debugLog(`Retrying cleanup for ${userId}...`);
//           const retryResult = await safeDeleteAuthFolder(authPath);
//           debugLog(`Retry result for ${userId}: ${retryResult}`);
//         }, 30000);

//         pendingCleanups.set(userId, retryTimer);
//       }
//     }
//   }

//   return allSuccess;
// }

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

// Helper function to configure client heartbeat with fixes
function configureClientHeartbeat(client, userId, token) {
  // Check if already attached
  if (eventListenersAttached.get(userId)) {
    debugLog(
      `Event listeners already attached for user ${userId}, skipping...`,
    );
    return;
  }

  eventListenersAttached.set(userId, true);

  let heartbeatInterval = null;
  let reconnectAttempts = 0;
  const MAX_RECONNECT_ATTEMPTS = 10;
  let isDestroyed = false;
  let lastHeartbeatTime = Date.now();

  const startHeartbeat = () => {
    if (heartbeatInterval) {
      clearInterval(heartbeatInterval);
    }

    debugLog(`Starting heartbeat for user ${userId}`);
    // CHANGED: Increase interval from 30s to 60s to reduce load
    heartbeatInterval = setInterval(async () => {
      if (isDestroyed) {
        debugLog(`Heartbeat stopped - client destroyed for user ${userId}`);
        stopHeartbeat();
        return;
      }

      try {
        // More robust browser check
        if (
          !client?.pupBrowser?.isConnected?.() ||
          client.pupBrowser.process?.killed
        ) {
          debugLog(`Browser not available for user ${userId}`);
          return; // Don't destroy, just skip this cycle
        }

        const statePromise = client.getState();
        const timeoutPromise = new Promise((_, reject) =>
          setTimeout(() => reject(new Error("State check timeout")), 10000),
        );

        const state = await Promise.race([statePromise, timeoutPromise]);
        lastHeartbeatTime = Date.now();

        if (state === "CONNECTED") {
          debugLog(`Heartbeat OK - Client alive for user ${userId}`);
          reconnectAttempts = 0;
        }
      } catch (error) {
        // Only log significant errors
        if (
          !error.message.includes("Execution context was destroyed") &&
          !error.message.includes("navigation") &&
          !error.message.includes("Session closed") &&
          !error.message.includes("timeout")
        ) {
          debugLog(`Heartbeat error for user ${userId}:`, error.message);
        }
      }
    }, 60000); // Changed from 30000 to 60000 (1 minute)

    return heartbeatInterval;
  };

  const stopHeartbeat = () => {
    if (heartbeatInterval) {
      clearInterval(heartbeatInterval);
      heartbeatInterval = null;
      debugLog(`Heartbeat stopped for user ${userId}`);
    }
  };

  // Rest of the heartbeat configuration remains the same...
  // (keep your existing event handlers)

  return { startHeartbeat, stopHeartbeat };
}

// Improved client destruction with better cleanup
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
        setTimeout(() => reject(new Error("Destroy timeout")), 10000),
      );

      await Promise.race([client.destroy(), destroyTimeout]).catch((err) => {
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



// function findChrome() {
//   const possiblePaths = [
//     "/usr/bin/google-chrome",
//     "/usr/bin/google-chrome-stable",
//     "/usr/bin/chromium",
//     "/usr/bin/chromium-browser",
//     process.env.PUPPETEER_EXECUTABLE_PATH,
//   ];

//   for (const path of possiblePaths) {
//     if (path && fs.existsSync(path)) {
//       console.log(`✅ Found Chrome at: ${path}`);
//       return path;
//     }
//   }

//   console.error("❌ Chrome not found in any standard location");
//   return null;
// }

function getRandomConnectedDevice(userId, devices) {
  // Get all connected devices for this user
  const connectedDevices = devices.filter((device) => {
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

// Helper function to check if value is numeric
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

// Token validation routes
app.post("/api/auth/validate-token", async (req, res) => {
  debugLog(`POST /api/auth/validate-token called`);
  debugLog("Request body:", req.body);

  try {
    const { token } = req.body;

    if (!token) {
      debugLog("Token is required but not provided");
      return res.status(400).json({ error: "Token is required" });
    }

    debugLog("Validating token with PHP API...");
    const result = await callPHPAPI("/auth/token/validate", "POST", { token });
    res.json(result);
  } catch (error) {
    debugLog("Token validation error:", error);
    res.status(401).json({ error: error.message });
  }
});

app.post("/api/auth/store-token", verifyAuth, async (req, res) => {
  debugLog(`POST /api/auth/store-token called by user ${req.userId}`);
  debugLog("Request body:", req.body);

  try {
    const { deviceInfo } = req.body;

    const result = await callPHPAPI(
      "/auth/token/store",
      "POST",
      {
        device_info: deviceInfo || "Web Browser",
      },
      req.token,
    );

    res.json(result);
  } catch (error) {
    debugLog("Error storing token:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/auth/remove-token", verifyAuth, async (req, res) => {
  debugLog(`POST /api/auth/remove-token called by user ${req.userId}`);
  debugLog("Request body:", req.body);

  try {
    const { token } = req.body;

    if (!token) {
      debugLog("Token is required but not provided");
      return res.status(400).json({ error: "Token is required" });
    }

    const result = await callPHPAPI(
      "/auth/token/remove",
      "POST",
      { token },
      req.token,
    );
    res.json(result);
  } catch (error) {
    debugLog("Error removing token:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/auth/check-token", async (req, res) => {
  debugLog(`GET /api/auth/check-token called`);

  try {
    const token = extractToken(req);

    if (!token) {
      debugLog("No token provided");
      return res.json({ valid: false, reason: "NO_TOKEN" });
    }

    // Check cache first
    const cachedData = getCachedToken(token);
    if (cachedData) {
      debugLog("Using cached token data");
      return res.json({
        valid: true,
        user: cachedData.user,
        cached: true,
      });
    }

    // Verify with PHP API
    debugLog("Verifying token with PHP API...");
    const result = await callPHPAPI("/auth/token/validate", "POST", { token });

    if (result.valid) {
      debugLog("Token is valid, caching it");
      cacheToken(token, result);
    }

    debugLog("Token validation result:", result.valid);
    res.json(result);
  } catch (error) {
    debugLog("Token check error:", error.message);
    res.json({
      valid: false,
      reason: "VERIFICATION_FAILED",
      error: error.message,
    });
  }
});

// WhatsApp Routes
app.post("/api/whatsapp/initialize", verifyAuth, async (req, res) => {
  debugLog(`POST /api/whatsapp/initialize called by user ${req.userId}`);

  try {
    const clientKey = req.userId;

    // Check if already connected
    const existingClient = clients.get(clientKey);
    if (existingClient) {
      try {
        const state = await existingClient.getState();
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

    // ✅ FIX: Start initialization (don't await fully)
    initializeClientForUser(req.userId, req.token, true).catch((err) => {
      debugLog(`Background initialization error: ${err.message}`);
    });

    // ✅ FIX: Wait up to 10 seconds for QR code to appear
    const maxWaitTime = 10000; // 10 seconds
    const checkInterval = 500; // Check every 500ms
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
    // (frontend will poll for QR)
    debugLog(`No QR after ${waited}ms, client still initializing`);
    res.json({
      success: true,
      message: "WhatsApp client initializing, please wait for QR code",
      qrReady: false,
    });
  } catch (error) {
    debugLog("Initialize error:", error.message);
    res.status(500).json({
      error: error.message,
      message: "Failed to initialize WhatsApp. Please try again.",
    });
  }
});
app.get("/api/whatsapp/qr", verifyAuth, async (req, res) => {
  debugLog(`GET /api/whatsapp/qr called by user ${req.userId}`);

  try {
    const client = clients.get(req.userId);

    // Check actual client state
    if (client) {
      try {
        // Add timeout to prevent hanging
        const statePromise = client.getState();
        const timeoutPromise = new Promise((_, reject) =>
          setTimeout(() => reject(new Error("timeout")), 3000),
        );

        const state = await Promise.race([statePromise, timeoutPromise]);
        debugLog(`QR request - Client state for user ${req.userId}: ${state}`);

        if (state === "CONNECTED") {
          const session = await callPHPAPI(
            "/whatsapp/session/get",
            "GET",
            null,
            req.token,
          );
          return res.json({
            qr: null,
            ready: true,
            session,
          });
        }
      } catch (error) {
        if (!error.message.includes("timeout")) {
          debugLog(`Error checking client state: ${error.message}`);
        }
      }
    }

    const qr = qrCodes.get(req.userId);

    debugLog(`Returning QR status:`, { hasQR: !!qr });
    res.json({
      qr: qr || null,
      ready: false,
      session: null,
    });
  } catch (error) {
    debugLog("QR fetch error:", error);
    res.status(500).json({ error: error.message });
  }
});

// app.get("/api/whatsapp/status", verifyAuth, async (req, res) => {
//   debugLog(`GET /api/whatsapp/status called by user ${req.userId}`);

//   try {
//     const client = clients.get(req.userId);
//     let isConnected = false;
//     let clientState = "NONE";

//     // ⭐ FIX: Better connection checking
//     if (client) {
//       try {
//         // Check if browser is alive and client is initialized
//         const browserConnected = client.pupBrowser?.isConnected?.();
//         const pageConnected = client.pupPage?.isClosed?.() === false;

//         if (browserConnected && pageConnected) {
//           // Try to get state with timeout
//           try {
//             const statePromise = client.getState();
//             const timeoutPromise = new Promise((_, reject) =>
//               setTimeout(() => reject(new Error("State check timeout")), 5000),
//             );

//             clientState = await Promise.race([statePromise, timeoutPromise]);
//             isConnected = clientState === "CONNECTED";

//             // ⭐ ADDITIONAL CHECK: If state is null but browser/page are connected,
//             // assume we're connected (this fixes the main issue)
//             if (!clientState && browserConnected && pageConnected) {
//               debugLog(
//                 `⚠️ State is null but browser/page are connected. Assuming connected.`,
//               );
//               isConnected = true;
//               clientState = "CONNECTED (assumed)";
//             }
//           } catch (error) {
//             debugLog(`State check failed: ${error.message}`);
//             // If browser/page are connected but state check failed, still assume connected
//             if (browserConnected && pageConnected) {
//               isConnected = true;
//               clientState = "CONNECTED (browser alive)";
//             }
//           }
//         } else {
//           debugLog(
//             `Browser or page not connected: browser=${browserConnected}, page=${pageConnected}`,
//           );
//           clientState = "DISCONNECTED";
//         }
//       } catch (error) {
//         debugLog(`Error checking client: ${error.message}`);
//       }
//     }

//     let session = null;
//     try {
//       debugLog("Fetching session from database...");
//       session = await callPHPAPI(
//         "/whatsapp/session/get",
//         "GET",
//         null,
//         req.token,
//       );
//     } catch (error) {
//       debugLog(`No session in DB for user ${req.userId}: ${error.message}`);
//     }

//     // ⭐ FIX: Use session data as fallback for connection status
//     // If database says active, trust it more than client.getState()
//     const sessionActive = session?.is_active === 1;

//     // ⭐ CRITICAL FIX: If database says we're active, return connected=true
//     if (sessionActive && !isConnected) {
//       debugLog(
//         `⚠️ Database says active but client.getState() says disconnected. Trusting database.`,
//       );
//       isConnected = true;
//       clientState = "CONNECTED (from DB)";
//     }

//     let stats = null;
//     try {
//       stats = await callPHPAPI("/stats/get", "GET", null, req.token);
//     } catch (error) {
//       debugLog(`Error fetching stats: ${error.message}`);
//     }

//     debugLog(`Status response:`, {
//       connected: isConnected,
//       clientActive: isConnected,
//       clientState,
//       sessionActive: session?.is_active,
//     });

//     res.json({
//       connected: isConnected,
//       session: session || null,
//       clientActive: isConnected, // ⭐ Ensure this is true when connected
//       clientState,
//       stats: stats || null,
//       timestamp: Date.now(),
//       debug: {
//         clientConnected: isConnected,
//         dbActive: session?.is_active || 0,
//         stateMismatch: isConnected !== sessionActive,
//       },
//     });
//   } catch (error) {
//     debugLog("Status check error:", error.message);
//     res.status(500).json({
//       error: error.message,
//       code: "STATUS_CHECK_FAILED",
//     });
//   }
// });

app.get("/api/whatsapp/status", verifyAuth, async (req, res) => {
  debugLog(`GET /api/whatsapp/status called by user ${req.userId}`);

  try {
    const client = clients.get(req.userId);

    // ⭐ SIMPLE CHECK: If QR code exists, NOT connected
    if (qrCodes.has(req.userId)) {
      debugLog(`QR code exists for user ${req.userId} - NOT connected`);
      return res.json({
        connected: false, // ⭐ Definitely false
        ready: false,
        needsQR: true,
        message: "Scan QR code to connect",
      });
    }

    // ⭐ SIMPLE CHECK: No client, NOT connected
    if (!client) {
      debugLog(`No client for user ${req.userId} - NOT connected`);
      return res.json({
        connected: false, // ⭐ Definitely false
        ready: false,
        message: "WhatsApp not initialized",
      });
    }

    // ⭐ SIMPLE CHECK: Get actual WhatsApp state
    let isConnected = false;
    let state = "UNKNOWN";

    try {
      state = await client.getState();
      isConnected = state === "CONNECTED"; // ⭐ Only true if state is "CONNECTED"
      debugLog(
        `Actual WhatsApp state for user ${req.userId}: ${state}, connected: ${isConnected}`,
      );
    } catch (error) {
      debugLog(`Error getting state: ${error.message}`);
      isConnected = false; // ⭐ Error means not connected
    }

    // Get session info (optional)
    let session = null;
    try {
      session = await callPHPAPI(
        "/whatsapp/session/get",
        "GET",
        null,
        req.token,
      );
    } catch (error) {
      debugLog(`No session in DB: ${error.message}`);
    }

    // ⭐ SIMPLE RESPONSE: Return actual connection status
    res.json({
      connected: isConnected, // ⭐ Only true if WhatsApp says "CONNECTED"
      ready: isConnected && session?.is_active === 1,
      state: state,
      session: session,
      message: isConnected ? "WhatsApp is connected" : `WhatsApp is ${state}`,
    });
  } catch (error) {
    debugLog("Status check error:", error.message);
    res.status(500).json({
      error: error.message,
      connected: false, // ⭐ Always false on error
    });
  }
});

app.post("/api/whatsapp/disconnect", verifyAuth, async (req, res) => {
  debugLog(`POST /api/whatsapp/disconnect called by user ${req.userId}`);

  try {
    debugLog(`Enhanced disconnect request for user ${req.userId}`);

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
      debugLog("Updating database session...");
      await callPHPAPI("/whatsapp/session/disconnect", "POST", {}, req.token);
    } catch (error) {
      debugLog("Error updating DB session:", error);
    }

    // Enhanced auth data cleanup
    await cleanStaleAuthData(req.userId);

    debugLog(`WhatsApp fully disconnected for user ${req.userId}`);

    res.json({
      success: true,
      message: "WhatsApp disconnected successfully",
    });
  } catch (error) {
    debugLog("Error disconnecting WhatsApp:", error);
    res.status(500).json({ error: error.message });
  }
});

// Manual cleanup endpoint - IMPORTANT for debugging
app.post("/api/whatsapp/force-cleanup", verifyAuth, async (req, res) => {
  debugLog(`POST /api/whatsapp/force-cleanup called by user ${req.userId}`);

  try {
    debugLog(`Force cleanup requested for user ${req.userId}`);

    // Destroy client if exists
    if (clients.has(req.userId)) {
      const client = clients.get(req.userId);
      try {
        await client.destroy();
      } catch (error) {
        debugLog(`Error destroying client: ${error.message}`);
      }
      clients.delete(req.userId);
    }

    // Clear all state
    qrCodes.delete(req.userId);
    clientInitializing.delete(req.userId);

    // Update database
    try {
      await callPHPAPI("/whatsapp/session/disconnect", "POST", {}, req.token);
    } catch (error) {
      debugLog(`Error updating DB: ${error.message}`);
    }

    // Force clean auth data
    await cleanStaleAuthData(req.userId);

    // Double check and force delete
    await new Promise((resolve) => setTimeout(resolve, 1000));
    const authPath = path.join("./auth_data", `session-user-${req.userId}`);
    if (fs.existsSync(authPath)) {
      debugLog(`Auth data still exists, force removing...`);
      fs.rmSync(authPath, { recursive: true, force: true, maxRetries: 5 });
    }

    // Check all session directories for this user
    const parentDir = path.join("./auth_data");
    if (fs.existsSync(parentDir)) {
      const allDirs = fs.readdirSync(parentDir);
      const userDirs = allDirs.filter((d) => d.includes(`user-${req.userId}`));
      debugLog(`Found ${userDirs.length} directories for user ${req.userId}`);

      userDirs.forEach((dir) => {
        const fullPath = path.join(parentDir, dir);
        debugLog(`Removing: ${fullPath}`);
        try {
          fs.rmSync(fullPath, { recursive: true, force: true, maxRetries: 5 });
        } catch (error) {
          debugLog(`Failed to remove ${fullPath}:`, error.message);
        }
      });
    }

    debugLog("Complete cleanup performed");
    res.json({
      success: true,
      message: "Complete cleanup performed",
      cleaned: {
        client: true,
        qrCode: true,
        initializing: true,
        database: true,
        authData: true,
      },
    });
  } catch (error) {
    debugLog("Force cleanup error:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/whatsapp/check-and-recover", verifyAuth, async (req, res) => {
  debugLog(`POST /api/whatsapp/check-and-recover called by user ${req.userId}`);

  try {
    const client = clients.get(req.userId);

    if (!client) {
      debugLog("No client instance found");
      return res.json({
        status: "no_client",
        message: "No client instance found",
      });
    }

    try {
      const state = await client.getState();

      if (state === "CONNECTED") {
        debugLog(`Client is connected, state: ${state}`);
        return res.json({
          status: "connected",
          state: state,
        });
      } else {
        debugLog(`Client exists but not connected, state: ${state}`);
        return res.json({
          status: "not_connected",
          state: state,
          message: "Client exists but not connected",
        });
      }
    } catch (error) {
      // Client is stuck, clean it up
      debugLog(
        `Cleaning stuck client for user ${req.userId}: ${error.message}`,
      );
      await safeDestroyClient(client, req.userId);

      return res.json({
        status: "cleaned",
        message: "Cleaned stuck client, please reconnect",
      });
    }
  } catch (error) {
    debugLog("Error in check-and-recover:", error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// PLANS ENDPOINTS
// ============================================

app.get("/api/plans", verifyAnyToken, async (req, res) => {
  debugLog(`GET /api/plans called`);
  debugLog("Auth type:", req.authType);
  debugLog("User ID:", req.userId);
  try {
    debugLog(`Calling PHP API: /plans`);
    const plans = await callPHPAPI("/plans", "GET", null, req.token);
    debugLog("Plans response:", plans);
    res.json(plans);
  } catch (error) {
    debugLog("Error fetching plans:", error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// SUBSCRIPTIONS ENDPOINTS
// ============================================

// Get all subscriptions
app.get("/api/subscriptions", verifyAnyToken, async (req, res) => {
  debugLog(`GET /api/subscriptions called`);
  debugLog("Query parameters:", req.query);
  debugLog("Auth type:", req.authType);
  debugLog("User ID:", req.userId);

  try {
    // Get query parameters
    const planType = req.query.plan_type || null;
    const planStatus = req.query.plan_status || null;
    const sortBy = req.query.sort_by || "createdAt";
    const sortOrder = req.query.sort_order || "DESC";
    const limit = parseInt(req.query.limit) || 100;
    const page = parseInt(req.query.page) || 1;
    const offset = (page - 1) * limit;

    // Build query string for PHP API
    let queryString = `?sort_by=${sortBy}&sort_order=${sortOrder}&limit=${limit}&page=${page}`;

    if (planType) queryString += `&plan_type=${planType}`;
    if (planStatus) queryString += `&plan_status=${planStatus}`;

    debugLog(`Calling PHP API: /subscriptions${queryString}`);
    const subscriptions = await callPHPAPI(
      `/subscriptions${queryString}`,
      "GET",
      null,
      req.token,
    );

    debugLog(`Received subscriptions response:`, subscriptions);
    res.json(subscriptions);
  } catch (error) {
    debugLog("Error fetching subscriptions:", error.message);
    debugLog("Error details:", error);

    res.status(500).json({
      error: error.message || "Failed to fetch subscriptions",
      code: "SUBSCRIPTIONS_FETCH_ERROR",
      details: error.responseData || null,
    });
  }
});

// Get active subscription
app.get("/api/subscriptions/active", verifyAnyToken, async (req, res) => {
  debugLog(`GET /api/subscriptions/active called`);
  debugLog("Auth type:", req.authType);
  debugLog("User ID:", req.userId);

  try {
    debugLog("Calling PHP API: /subscriptions/active");
    const subscription = await callPHPAPI(
      "/subscriptions/active",
      "GET",
      null,
      req.token,
    );

    debugLog("Active subscription response:", subscription);
    res.json(subscription);
  } catch (error) {
    debugLog("Error fetching active subscription:", error.message);
    debugLog("Error details:", error);

    res.status(500).json({
      error: error.message || "Failed to fetch active subscription",
      code: "ACTIVE_SUBSCRIPTION_ERROR",
      details: error.responseData || null,
    });
  }
});

// Get specific subscription by ID
app.get("/api/subscriptions/:id", verifyAnyToken, async (req, res) => {
  const subscriptionId = req.params.id;
  debugLog(`GET /api/subscriptions/${subscriptionId} called`);
  debugLog("Auth type:", req.authType);
  debugLog("User ID:", req.userId);

  try {
    debugLog(`Calling PHP API: /subscriptions/${subscriptionId}`);
    const subscription = await callPHPAPI(
      `/subscriptions/${subscriptionId}`,
      "GET",
      null,
      req.token,
    );

    debugLog(`Subscription ${subscriptionId} response:`, subscription);
    res.json(subscription);
  } catch (error) {
    debugLog(`Error fetching subscription ${subscriptionId}:`, error.message);

    if (error.status === 404) {
      return res.status(404).json({
        error: "Subscription not found",
        code: "SUBSCRIPTION_NOT_FOUND",
        requestedId: subscriptionId,
        details: error.responseData || null,
      });
    }
    debugLog("Error details:", error);

    res.status(500).json({
      error: error.message || "Failed to fetch subscription",
      code: "SUBSCRIPTION_FETCH_ERROR",
      details: error.responseData || null,
    });
  }
});

// Create new subscription
app.post("/api/subscriptions/create", verifyAnyToken, async (req, res) => {
  debugLog(`POST /api/subscriptions/create called`);
  debugLog("Request body:", req.body);
  debugLog("Auth type:", req.authType);
  debugLog("User ID:", req.userId);

  try {
    const subscriptionData = req.body;

    // Validate required fields
    const requiredFields = ["plan_type", "Plan_charge", "plan_duration"];
    const missingFields = requiredFields.filter(
      (field) => !subscriptionData[field],
    );

    if (missingFields.length > 0) {
      debugLog(`Missing required fields: ${missingFields.join(", ")}`);
      return res.status(400).json({
        error: `Missing required fields: ${missingFields.join(", ")}`,
        code: "MISSING_REQUIRED_FIELDS",
      });
    }

    // Validate plan_type
    const allowedPlanTypes = ["basic", "standard", "premium", "enterprise"];
    if (!allowedPlanTypes.includes(subscriptionData.plan_type.toLowerCase())) {
      debugLog(`Invalid plan_type: ${subscriptionData.plan_type}`);
      return res.status(400).json({
        error: `Invalid plan_type. Allowed values: ${allowedPlanTypes.join(", ")}`,
        code: "INVALID_PLAN_TYPE",
      });
    }

    // Validate Plan_charge
    if (
      !isNumeric(subscriptionData.Plan_charge) ||
      parseFloat(subscriptionData.Plan_charge) <= 0
    ) {
      debugLog(`Invalid Plan_charge: ${subscriptionData.Plan_charge}`);
      return res.status(400).json({
        error: "Plan_charge must be a positive number",
        code: "INVALID_PLAN_CHARGE",
      });
    }

    // Validate plan_duration
    if (
      !isNumeric(subscriptionData.plan_duration) ||
      parseInt(subscriptionData.plan_duration) <= 0
    ) {
      debugLog(`Invalid plan_duration: ${subscriptionData.plan_duration}`);
      return res.status(400).json({
        error: "plan_duration must be a positive integer",
        code: "INVALID_PLAN_DURATION",
      });
    }

    debugLog("Calling PHP API: /subscriptions/create");
    const subscription = await callPHPAPI(
      "/subscriptions/create",
      "POST",
      subscriptionData,
      req.token,
    );

    debugLog("Subscription created:", subscription);
    res.json(subscription);
  } catch (error) {
    debugLog("Error creating subscription:", error.message);
    debugLog("Error details:", error);

    res.status(500).json({
      error: error.message || "Failed to create subscription",
      code: "SUBSCRIPTION_CREATE_ERROR",
      details: error.responseData || null,
    });
  }
});

// Update subscription
app.put("/api/subscriptions/:id", verifyAnyToken, async (req, res) => {
  const subscriptionId = req.params.id;
  debugLog(`PUT /api/subscriptions/${subscriptionId} called`);
  debugLog("Request body:", req.body);
  debugLog("Auth type:", req.authType);
  debugLog("User ID:", req.userId);

  try {
    const { id } = req.params;
    const updateData = req.body;

    // Validate update data
    if (Object.keys(updateData).length === 0) {
      debugLog("No fields to update");
      return res.status(400).json({
        error: "No fields to update",
        code: "NO_UPDATE_FIELDS",
      });
    }

    // If plan_type is being updated, validate it
    if (updateData.plan_type) {
      const allowedPlanTypes = ["basic", "standard", "premium", "enterprise"];
      if (!allowedPlanTypes.includes(updateData.plan_type.toLowerCase())) {
        debugLog(`Invalid plan_type in update: ${updateData.plan_type}`);
        return res.status(400).json({
          error: `Invalid plan_type. Allowed values: ${allowedPlanTypes.join(", ")}`,
          code: "INVALID_PLAN_TYPE",
        });
      }
    }

    // Validate Plan_charge if provided
    if (
      updateData.Plan_charge &&
      (!isNumeric(updateData.Plan_charge) ||
        parseFloat(updateData.Plan_charge) <= 0)
    ) {
      debugLog(`Invalid Plan_charge in update: ${updateData.Plan_charge}`);
      return res.status(400).json({
        error: "Plan_charge must be a positive number",
        code: "INVALID_PLAN_CHARGE",
      });
    }

    // Validate plan_duration if provided
    if (
      updateData.plan_duration &&
      (!isNumeric(updateData.plan_duration) ||
        parseInt(updateData.plan_duration) <= 0)
    ) {
      debugLog(`Invalid plan_duration in update: ${updateData.plan_duration}`);
      return res.status(400).json({
        error: "plan_duration must be a positive integer",
        code: "INVALID_PLAN_DURATION",
      });
    }

    debugLog(`Calling PHP API: /subscriptions/${id}`);
    const subscription = await callPHPAPI(
      `/subscriptions/${id}`,
      "PUT",
      updateData,
      req.token,
    );

    debugLog(`Subscription ${id} updated:`, subscription);
    res.json(subscription);
  } catch (error) {
    debugLog(`Error updating subscription ${subscriptionId}:`, error.message);

    if (error.status === 404) {
      return res.status(404).json({
        error: "Subscription not found",
        code: "SUBSCRIPTION_NOT_FOUND",
        requestedId: subscriptionId,
        details: error.responseData || null,
      });
    }
    debugLog("Error details:", error);

    res.status(500).json({
      error: error.message || "Failed to update subscription",
      code: "SUBSCRIPTION_UPDATE_ERROR",
      details: error.responseData || null,
    });
  }
});

// Cancel subscription (soft delete)
app.delete("/api/subscriptions/:id", verifyAnyToken, async (req, res) => {
  const subscriptionId = req.params.id;
  debugLog(`DELETE /api/subscriptions/${subscriptionId} called`);
  debugLog("Auth type:", req.authType);
  debugLog("User ID:", req.userId);

  try {
    const { id } = req.params;

    debugLog(`Calling PHP API: /subscriptions/${id}`);
    const result = await callPHPAPI(
      `/subscriptions/${id}`,
      "DELETE",
      null,
      req.token,
    );

    debugLog(`Subscription ${id} cancelled:`, result);
    res.json(result);
  } catch (error) {
    debugLog(`Error canceling subscription ${subscriptionId}:`, error.message);

    if (error.status === 404) {
      return res.status(404).json({
        error: "Subscription not found",
        code: "SUBSCRIPTION_NOT_FOUND",
        requestedId: subscriptionId,
        details: error.responseData || null,
      });
    }
    debugLog("Error details:", error);

    res.status(500).json({
      error: error.message || "Failed to cancel subscription",
      code: "SUBSCRIPTION_CANCEL_ERROR",
      details: error.responseData || null,
    });
  }
});

// Get subscription summary/analytics
app.get("/api/subscriptions/summary", verifyAnyToken, async (req, res) => {
  debugLog(`GET /api/subscriptions/summary called`);
  debugLog("Auth type:", req.authType);
  debugLog("User ID:", req.userId);

  try {
    // First get all subscriptions
    debugLog("Fetching all subscriptions...");
    const subscriptions = await callPHPAPI(
      "/subscriptions",
      "GET",
      null,
      req.token,
    );

    if (
      !subscriptions ||
      !subscriptions.data ||
      !Array.isArray(subscriptions.data)
    ) {
      debugLog("Invalid subscription data received:", subscriptions);
      return res.status(500).json({
        error: "Invalid subscription data received",
        code: "INVALID_DATA",
        receivedData: subscriptions,
      });
    }

    const subscriptionData = subscriptions.data;
    debugLog(`Received ${subscriptionData.length} subscriptions`);

    // Calculate summary statistics
    const totalSubscriptions =
      subscriptions.pagination?.total || subscriptionData.length;
    const activeSubscriptions = subscriptionData.filter(
      (sub) => sub.plan_status === "active",
    ).length;
    const cancelledSubscriptions = subscriptionData.filter(
      (sub) => sub.plan_status === "cancelled",
    ).length;

    // Group by plan type
    const planTypeStats = {};
    subscriptionData.forEach((sub) => {
      const planType = sub.plan_type || "unknown";
      if (!planTypeStats[planType]) {
        planTypeStats[planType] = {
          count: 0,
          totalRevenue: 0,
          averageDuration: 0,
        };
      }
      planTypeStats[planType].count++;
      planTypeStats[planType].totalRevenue += parseFloat(sub.Plan_charge || 0);
    });

    // Calculate averages
    Object.keys(planTypeStats).forEach((planType) => {
      const planSubs = subscriptionData.filter(
        (sub) => sub.plan_type === planType,
      );
      const totalDuration = planSubs.reduce(
        (sum, sub) => sum + parseInt(sub.plan_duration || 0),
        0,
      );
      planTypeStats[planType].averageDuration = totalDuration / planSubs.length;
    });

    // Calculate total revenue
    const totalRevenue = subscriptionData.reduce((sum, sub) => {
      return sum + parseFloat(sub.Plan_charge || 0);
    }, 0);

    // Get most recent subscription
    const recentSubscription =
      subscriptionData.length > 0
        ? subscriptionData[0] // Assuming data is sorted by createdAt DESC
        : null;

    // Response
    const summary = {
      overview: {
        total: totalSubscriptions,
        active: activeSubscriptions,
        cancelled: cancelledSubscriptions,
        totalRevenue: totalRevenue.toFixed(2),
      },
      planTypeStats: planTypeStats,
      recentSubscription: recentSubscription,
      lastUpdated: new Date().toISOString(),
    };

    debugLog("Generated summary:", summary);
    res.json({
      success: true,
      data: summary,
    });
  } catch (error) {
    debugLog("Error generating subscription summary:", error.message);
    debugLog("Error details:", error);

    res.status(500).json({
      error: error.message || "Failed to generate subscription summary",
      code: "SUBSCRIPTION_SUMMARY_ERROR",
      details: error.responseData || null,
    });
  }
});

app.get("/api/subscriptions/has-active", verifyAnyToken, async (req, res) => {
  debugLog(`GET /api/subscriptions/has-active called`);
  debugLog("Auth type:", req.authType);
  debugLog("User ID:", req.userId);

  try {
    debugLog("Calling PHP API: /subscriptions/active");
    // ADD THIS DEBUG LINE:
    debugLog(
      "Full PHP API URL will be:",
      `${PHP_API_URL}/subscriptions/active`,
    );

    const activeSubscription = await callPHPAPI(
      "/subscriptions/active",
      "GET",
      null,
      req.token,
    );

    debugLog("PHP API Response:", activeSubscription);
    debugLog("Response type:", typeof activeSubscription);

    // Check response structure
    if (activeSubscription) {
      debugLog(
        "Response has success:",
        activeSubscription.success !== undefined,
      );
      debugLog(
        "Response has has_active_subscription:",
        activeSubscription.has_active_subscription !== undefined,
      );
      debugLog("Response has data:", activeSubscription.data !== undefined);
    }

    const hasActive =
      activeSubscription &&
      activeSubscription.success &&
      activeSubscription.has_active_subscription === true;

    debugLog(`User has active subscription: ${hasActive}`);

    res.json({
      success: true,
      hasActive: hasActive,
      subscription: hasActive ? activeSubscription.data : null,
      message: hasActive
        ? "Active subscription found"
        : "No active subscription",
      debug: DEBUG_MODE
        ? {
            rawResponse: activeSubscription,
            userId: req.userId,
          }
        : undefined,
    });
  } catch (error) {
    debugLog("Error checking active subscription:", error.message);
    debugLog("Error details:", error);

    res.status(500).json({
      success: false,
      error: error.message || "Failed to check active subscription",
      code: "CHECK_ACTIVE_ERROR",
      details: error.responseData || null,
    });
  }
});

// Get subscription usage stats
app.get("/api/subscriptions/:id/usage", verifyAnyToken, async (req, res) => {
  const subscriptionId = req.params.id;
  debugLog(`GET /api/subscriptions/${subscriptionId}/usage called`);
  debugLog("Auth type:", req.authType);
  debugLog("User ID:", req.userId);

  try {
    // Get the subscription
    debugLog(`Fetching subscription ${subscriptionId}...`);
    const subscription = await callPHPAPI(
      `/subscriptions/${subscriptionId}`,
      "GET",
      null,
      req.token,
    );

    if (!subscription || !subscription.data) {
      debugLog(`Subscription ${subscriptionId} not found`);
      return res.status(404).json({
        error: "Subscription not found",
        code: "SUBSCRIPTION_NOT_FOUND",
        requestedId: subscriptionId,
      });
    }

    // Get user's message stats (if needed)
    debugLog("Fetching user stats...");
    const stats = await callPHPAPI("/stats/get", "GET", null, req.token);

    // Calculate days left if subscription is active
    let daysLeft = null;
    let usagePercentage = null;

    if (
      subscription.data.plan_status === "active" &&
      subscription.data.createdAt &&
      subscription.data.plan_duration
    ) {
      try {
        const createdAt = new Date(subscription.data.createdAt);
        const planDuration = parseInt(subscription.data.plan_duration);
        const endDate = new Date(createdAt);
        endDate.setDate(createdAt.getDate() + planDuration);

        const now = new Date();
        const totalDays = planDuration;
        const daysPassed = Math.floor(
          (now - createdAt) / (1000 * 60 * 60 * 24),
        );
        daysLeft = Math.max(0, totalDays - daysPassed);
        usagePercentage = Math.min(
          100,
          Math.round((daysPassed / totalDays) * 100),
        );

        debugLog(
          `Days calculation: daysPassed=${daysPassed}, daysLeft=${daysLeft}, usagePercentage=${usagePercentage}%`,
        );
      } catch (dateError) {
        debugLog("Date calculation error:", dateError.message);
      }
    }

    const usageStats = {
      subscription: subscription.data,
      messageStats: stats || {},
      durationStats: {
        daysLeft: daysLeft,
        usagePercentage: usagePercentage,
        startDate: subscription.data.createdAt,
        duration: subscription.data.plan_duration,
      },
      calculatedAt: new Date().toISOString(),
    };

    debugLog("Generated usage stats:", usageStats);
    res.json({
      success: true,
      data: usageStats,
    });
  } catch (error) {
    debugLog(
      `Error getting subscription ${subscriptionId} usage:`,
      error.message,
    );

    if (error.status === 404) {
      return res.status(404).json({
        error: "Subscription not found",
        code: "SUBSCRIPTION_NOT_FOUND",
        requestedId: subscriptionId,
        details: error.responseData || null,
      });
    }
    debugLog("Error details:", error);

    res.status(500).json({
      error: error.message || "Failed to get subscription usage",
      code: "USAGE_STATS_ERROR",
      details: error.responseData || null,
    });
  }
});

// Add Device - Associate token with phone number
app.get("/api/devices", verifyAuth, async (req, res) => {
  debugLog(`GET /api/devices called by user ${req.userId}`);
  try {
    const devices = await callPHPAPI("/devices/list", "GET", null, req.token);

    // Enhance with real-time connection status
    const enhancedDevices = devices.map((device) => {
      const clientKey = `${req.userId}-${device.device_id}`;
      const isConnected = clients.has(clientKey);
      let clientState = "DISCONNECTED";

      if (isConnected) {
        try {
          const client = clients.get(clientKey);
          // Don't await here, just check if client exists
          clientState = "CONNECTED";
        } catch (error) {
          clientState = "ERROR";
        }
      }

      return {
        ...device,
        isConnected,
        clientState,
      };
    });

    debugLog(`Returning ${enhancedDevices.length} devices`);
    res.json(enhancedDevices);
  } catch (error) {
    debugLog("Get devices error:", error);
    res.status(500).json({ error: error.message });
  }
});
app.post("/api/devices/add", verifyAuth, async (req, res) => {
  debugLog(`POST /api/devices/add called by user ${req.userId}`);
  debugLog("Request body:", req.body);

  try {
    const { token, phoneNumber, deviceName } = req.body;

    if (!token || !phoneNumber) {
      debugLog("Missing required fields: token or phoneNumber");
      return res
        .status(400)
        .json({ error: "Token and phone number are required" });
    }

    // Clean phone number
    const cleanNumber = phoneNumber.replace(/[^\d]/g, "");

    // Verify token exists in database and belongs to user
    debugLog("Verifying token in database...");
    const tokenData = await callPHPAPI(
      "/tokens/verify",
      "POST",
      { token },
      req.token,
    );

    if (!tokenData || !tokenData.valid || tokenData.user_id !== req.userId) {
      debugLog("Invalid token or token does not belong to user:", tokenData);
      return res
        .status(400)
        .json({ error: "Invalid token or token does not belong to you" });
    }

    // Check if token is already assigned
    try {
      debugLog("Checking if token is already assigned...");
      const existingDevice = await callPHPAPI(
        "/devices/by-token",
        "POST",
        { token },
        req.token,
      );
      if (existingDevice && existingDevice.id) {
        debugLog("Token already assigned to device:", existingDevice);
        return res.status(400).json({
          error:
            "This token is already assigned to: " +
            (existingDevice.device_name || existingDevice.device_id),
        });
      }
    } catch (error) {
      debugLog("Token not assigned - this is good:", error.message);
    }

    const deviceId = `device-${Date.now()}`;

    // Store device-token mapping in memory
    deviceTokens.set(token, {
      userId: req.userId,
      phoneNumber: cleanNumber,
      deviceId: deviceId,
      deviceName: deviceName || `Device ${cleanNumber}`,
      createdAt: new Date(),
      isActive: false,
    });

    // Add to user's devices
    if (!userDevices.has(req.userId)) {
      userDevices.set(req.userId, []);
    }
    userDevices.get(req.userId).push(deviceId);

    // Save to database
    debugLog("Saving device to database...");
    await callPHPAPI(
      "/devices/add",
      "POST",
      {
        device_id: deviceId,
        device_name: deviceName || `Device ${cleanNumber}`,
        phone_number: cleanNumber,
        token: token,
      },
      req.token,
    );

    debugLog(`Device added successfully: ${deviceId}`);
    res.json({
      success: true,
      deviceId,
      message: "Device added successfully",
    });
  } catch (error) {
    debugLog("Add device error:", error);

    if (error.response?.data?.error) {
      return res.status(error.response.status || 500).json({
        error: error.response.data.error,
      });
    }

    res.status(500).json({ error: error.message });
  }
});

// Update device (for webhook URL, etc.)
app.post("/api/devices/:deviceId/update", verifyAuth, async (req, res) => {
  debugLog(
    `POST /api/devices/${req.params.deviceId}/update called by user ${req.userId}`,
  );
  debugLog("Request body:", req.body);

  try {
    const { deviceId } = req.params;
    const { webhook_url, phone_number, pushname, is_active } = req.body;

    await callPHPAPI(
      `/devices/${deviceId}/update`,
      "POST",
      {
        webhook_url,
        phone_number,
        pushname,
        is_active,
      },
      req.token,
    );

    debugLog(`Device ${deviceId} updated successfully`);
    res.json({
      success: true,
      message: "Device updated successfully",
    });
  } catch (error) {
    debugLog("Update device error:", error);
    res.status(500).json({ error: error.message });
  }
});

// Initialize WhatsApp for specific device
app.post("/api/devices/:deviceId/initialize", verifyAuth, async (req, res) => {
  debugLog(
    `POST /api/devices/${req.params.deviceId}/initialize called by user ${req.userId}`,
  );

  try {
    const { deviceId } = req.params;

    // Get device info from database
    debugLog(`Fetching device info for ${deviceId}...`);
    const device = await callPHPAPI(
      `/devices/${deviceId}`,
      "GET",
      null,
      req.token,
    );

    if (!device) {
      debugLog(`Device ${deviceId} not found`);
      return res.status(404).json({ error: "Device not found" });
    }

    const clientKey = `${req.userId}-${deviceId}`;

    // Check if already initializing
    if (initializationPromises.has(clientKey)) {
      debugLog(`Initialization already in progress for ${clientKey}`);
      return res.status(409).json({
        error: "Initialization already in progress",
        message: "Please wait for the current initialization to complete",
      });
    }

    // Clean existing client
    if (clients.has(clientKey)) {
      const client = clients.get(clientKey);
      try {
        await client.destroy();
      } catch (error) {
        debugLog(`Error destroying client: ${error.message}`);
      }
      clients.delete(clientKey);
      eventListenersAttached.delete(clientKey);
    }

    qrCodes.delete(clientKey);
    clientInitializing.delete(clientKey);

    // Clean auth data
    debugLog(`Cleaning auth data for ${clientKey}...`);
    await cleanStaleAuthData(`${req.userId}-${deviceId}`);
    // await new Promise(resolve => setTimeout(resolve, 1000));

    // Initialize client for this device
    await initializeClientForDevice(
      req.userId,
      deviceId,
      device.phone_number,
      req.token,
      true,
    );

    debugLog(`Device ${deviceId} initialization started`);
    res.json({
      success: true,
      message: "Device initializing, please scan QR code",
      deviceId,
    });
  } catch (error) {
    debugLog("Device initialize error:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get QR code for specific device
app.get("/api/devices/:deviceId/qr", verifyAuth, async (req, res) => {
  debugLog(
    `GET /api/devices/${req.params.deviceId}/qr called by user ${req.userId}`,
  );

  try {
    const { deviceId } = req.params;
    const clientKey = `${req.userId}-${deviceId}`;

    const client = clients.get(clientKey);

    if (client) {
      try {
        const state = await client.getState();

        if (state === "CONNECTED") {
          const device = await callPHPAPI(
            `/devices/${deviceId}`,
            "GET",
            null,
            req.token,
          );
          debugLog(`Device ${deviceId} is already connected`);
          return res.json({
            qr: null,
            ready: true,
            device,
          });
        }
      } catch (error) {
        debugLog(`Error checking client state: ${error.message}`);
      }
    }

    const qr = qrCodes.get(clientKey);

    debugLog(`Returning QR status for ${deviceId}:`, { hasQR: !!qr });
    res.json({
      qr: qr || null,
      ready: false,
      deviceId,
    });
  } catch (error) {
    debugLog("QR fetch error:", error);
    res.status(500).json({ error: error.message });
  }
});

// Disconnect specific device
app.post("/api/devices/:deviceId/disconnect", verifyAuth, async (req, res) => {
  debugLog(
    `POST /api/devices/${req.params.deviceId}/disconnect called by user ${req.userId}`,
  );

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
    debugLog(`Updating database for device ${deviceId}...`);
    await callPHPAPI(`/devices/${deviceId}/disconnect`, "POST", {}, req.token);

    // Clean auth data
    await cleanStaleAuthData(`${req.userId}-${deviceId}`);

    debugLog(`Device ${deviceId} disconnected successfully`);
    res.json({
      success: true,
      message: "Device disconnected successfully",
    });
  } catch (error) {
    debugLog("Device disconnect error:", error);
    res.status(500).json({ error: error.message });
  }
});

// Delete device
app.delete("/api/devices/:deviceId", verifyAuth, async (req, res) => {
  debugLog(
    `DELETE /api/devices/${req.params.deviceId} called by user ${req.userId}`,
  );

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
    debugLog(`Deleting device ${deviceId} from database...`);
    await callPHPAPI(`/devices/${deviceId}`, "DELETE", null, req.token);

    debugLog(`Device ${deviceId} deleted successfully`);
    res.json({
      success: true,
      message: "Device deleted successfully",
    });
  } catch (error) {
    debugLog("Delete device error:", error);
    res.status(500).json({ error: error.message });
  }
});

// Messaging Routes - Accept both JWT and API tokens
app.post("/api/send-message", verifyAnyToken, async (req, res) => {
  try {
    const { number, message, deviceId } = req.body;

    if (!number || !message) {
      return res.status(400).json({ error: "Number and message are required" });
    }

    let client;
    let clientKey;
    let actualDeviceId;

    // FIX: Handle API tokens differently
    if (req.authType === "api_token") {
      // ⭐ SIMPLE FIX: Just use user ID without device
      actualDeviceId = "default";
      clientKey = req.userId; // No device suffix
      client = clients.get(clientKey);

      if (!client) {
        debugLog(`No WhatsApp client for user ${req.userId}`);
        return res.status(400).json({
          error: "WhatsApp not connected",
          details: "Please connect WhatsApp first using the dashboard",
        });
      }
    } else {
      // JWT token - use specified device or default
      actualDeviceId = deviceId || "default";
      clientKey = `${req.userId}-${actualDeviceId}`;
      client = clients.get(clientKey);
    }

    if (!client) {
      debugLog(`No client found for ${clientKey}`);
      return res.status(400).json({
        error: "WhatsApp not connected",
        details: "Please connect to WhatsApp first",
        code: "NOT_CONNECTED",
      });
    }

    // Check client state
    let state;
    try {
      state = await client.getState();
      debugLog(`Client state before sending: ${state}`);
    } catch (stateError) {
      debugLog(`Error checking state: ${stateError.message}`);
      return res.status(400).json({
        error: "WhatsApp client error",
        details: "Client is not responding",
        code: "CLIENT_ERROR",
      });
    }

    if (state !== "CONNECTED") {
      debugLog(`Client not ready, state: ${state}`);
      return res.status(400).json({
        error: "WhatsApp not ready",
        state: state,
        code: "NOT_READY",
        details: "Please wait for WhatsApp to connect",
      });
    }

    const chatId = number.includes("@c.us") ? number : `${number}@c.us`;

    debugLog(`📤 Sending message to ${chatId} (User: ${req.userId})`);
    const sentMessage = await client.sendMessage(chatId, message);
    const sentMessageId = sentMessage?.id?._serialized || sentMessage?.id?.id || sentMessage?._data?.id?._serialized || `local_${Date.now()}_${Math.random().toString(36).slice(2,10)}`;
    const sentTimestamp = sentMessage?.timestamp || Math.floor(Date.now() / 1000);
    debugLog(`✓ Message sent successfully: ${sentMessageId || "(id unavailable)"}`);
    if (!sentMessageId) { debugLog("⚠️ sentMessage.id missing - WhatsApp Web response shape may have changed:", JSON.stringify(sentMessage)); }

    let contactName = number;
    try {
      const contact = await client.getContactById(chatId);
      contactName = contact.name || contact.pushname || number;
    } catch (err) {
      debugLog("Could not get contact name:", err.message);
    }

    const myInfo = client.info;

    // Save to database
    try {
      await callPHPAPI(
        "/messages/save",
        "POST",
        {
          message_id: sentMessageId,
          type: "sent",
          from_number: myInfo.wid.user,
          from_name: myInfo.pushname,
          to_number: number,
          to_name: contactName,
          message_body: message,
          has_media: false,
          status: "sent",
          timestamp: sentTimestamp,
        },
        req.token,
      );

      debugLog("Message saved to database");
    } catch (dbError) {
      debugLog("❌ Database save failed:", dbError.message);
    }

    // Update stats
    try {
      await callPHPAPI(
        "/stats/update",
        "POST",
        {
          field: "sent",
          increment: 1,
        },
        req.token,
      );
    } catch (statsError) {
      debugLog("❌ Stats update failed:", statsError.message);
    }

    res.json({
      success: true,
      message: "Message sent successfully",
      messageId: sentMessageId,
      deviceId: actualDeviceId,
    });
  } catch (error) {
    debugLog("✗ Error sending message:", error.message);
    debugLog("Full error:", error);

    try {
      await callPHPAPI(
        "/stats/update",
        "POST",
        {
          field: "failed",
          increment: 1,
        },
        req.token,
      );
    } catch (e) {
      debugLog("Failed to update stats:", e.message);
    }

    res.status(500).json({
      success: false,
      error: error.message || "Failed to send message",
      code: "SEND_MESSAGE_ERROR",
    });
  }
});

app.post(
  "/api/send-media",
  verifyAnyToken,
  upload.single("file"),
  async (req, res) => {
    debugLog(`POST /api/send-media called`);
    debugLog("Auth type:", req.authType);
    debugLog("User ID:", req.userId);
    debugLog("Request body:", req.body);
    debugLog("File info:", req.file);

    try {
      const { number, caption, deviceId } = req.body;

      if (!number) {
        debugLog("Number is required but not provided");
        return res.status(400).json({ error: "Number is required" });
      }

      if (!req.file) {
        debugLog("No file uploaded");
        return res.status(400).json({ error: "No file uploaded" });
      }

      let clientKey;
      let client;
      let actualDeviceId = deviceId;
      let selectedDevice;

      // Get all user's devices
      const authToken = req.token;
      debugLog("Fetching user devices...");
      const userDevices = await callPHPAPI(
        "/devices/list",
        "GET",
        null,
        authToken,
      );

      if (req.authType === "api_token") {
        debugLog("API token auth detected");
        const deviceData = await callPHPAPI(
          "/devices/by-token",
          "POST",
          { token: req.token },
          authToken,
        );

        if (deviceData && deviceData.device_id) {
          actualDeviceId = deviceData.device_id;
          clientKey = `${req.userId}-${deviceData.device_id}`;
          client = clients.get(clientKey);
          selectedDevice = deviceData;
          debugLog(`Found device from token: ${actualDeviceId}`);
        } else {
          debugLog(
            "No device found for token, finding random connected device",
          );
          selectedDevice = getRandomConnectedDevice(req.userId, userDevices);
          if (!selectedDevice) {
            debugLog("No connected devices found");
            return res
              .status(400)
              .json({ error: "No connected devices found" });
          }
          actualDeviceId = selectedDevice.device_id;
          clientKey = `${req.userId}-${selectedDevice.device_id}`;
          client = clients.get(clientKey);
        }
      } else {
        if (deviceId) {
          clientKey = `${req.userId}-${deviceId}`;
          client = clients.get(clientKey);
          selectedDevice = userDevices.find((d) => d.device_id === deviceId);
        } else {
          debugLog("Finding random connected device...");
          selectedDevice = getRandomConnectedDevice(req.userId, userDevices);
          if (!selectedDevice) {
            debugLog("No connected devices found");
            return res
              .status(400)
              .json({ error: "No connected devices found" });
          }
          actualDeviceId = selectedDevice.device_id;
          clientKey = `${req.userId}-${selectedDevice.device_id}`;
          client = clients.get(clientKey);
        }
      }

      if (!client) {
        debugLog(`Device ${actualDeviceId} not connected`);
        return res.status(400).json({ error: "Device not connected" });
      }

      const chatId = number.includes("@c.us") ? number : `${number}@c.us`;
      const media = MessageMedia.fromFilePath(req.file.path);

      debugLog(
        `Sending media to ${chatId} from device ${selectedDevice?.device_name || actualDeviceId}`,
      );
      const sentMessage = await client.sendMessage(chatId, media, { caption });
      const sentMessageId = sentMessage?.id?._serialized || sentMessage?.id?.id || sentMessage?._data?.id?._serialized || `local_${Date.now()}_${Math.random().toString(36).slice(2,10)}`;
      const sentTimestamp = sentMessage?.timestamp || Math.floor(Date.now() / 1000);
      debugLog(`Media sent successfully: ${sentMessageId || "(id unavailable)"}`);
      if (!sentMessageId) { debugLog("⚠️ sentMessage.id missing on media send:", JSON.stringify(sentMessage)); }

      let contactName = number;
      try {
        const contact = await client.getContactById(chatId);
        contactName = contact.name || contact.pushname || number;
      } catch (err) {
        debugLog("Could not get contact name:", err.message);
      }

      const myInfo = client.info;
      const mediaType = req.file.mimetype.split("/")[0];

      const savedMessage = await callPHPAPI(
        "/messages/save",
        "POST",
        {
          message_id: sentMessageId,
          type: "sent",
          from_number: myInfo.wid.user,
          from_name: myInfo.pushname,
          to_number: number,
          to_name: contactName,
          message_body: caption || null,
          has_media: true,
          media_type: mediaType,
          media_url: `/uploads/${req.file.filename}`,
          status: "sent",
          timestamp: sentTimestamp,
          device_id: actualDeviceId,
        },
        authToken,
      );

      await callPHPAPI(
        "/stats/update",
        "POST",
        {
          field: "sent",
          increment: 1,
        },
        authToken,
      );

      await callPHPAPI(
        `/devices/${actualDeviceId}/update-stats`,
        "POST",
        {
          field: "sent",
          increment: 1,
        },
        authToken,
      );

      // Send webhook notification
      if (selectedDevice?.webhook_url) {
        try {
          debugLog(`Sending webhook to ${selectedDevice.webhook_url}`);
          await axios.post(
            selectedDevice.webhook_url,
            {
              event: "media_sent",
              message_id: sentMessageId,
              from: myInfo.wid.user,
              to: number,
              caption: caption,
              media_type: mediaType,
              timestamp: sentTimestamp,
              device_id: actualDeviceId,
              device_name: selectedDevice.device_name,
            },
            { timeout: 5000 },
          );
        } catch (webhookError) {
          debugLog(`Webhook failed: ${webhookError.message}`);
        }
      }

      debugLog("Media sent and saved successfully");
      res.json({
        success: true,
        message: "Media sent successfully",
        messageId: sentMessageId,
        dbId: savedMessage.id,
        deviceId: actualDeviceId,
        deviceName: selectedDevice?.device_name || "Unknown",
      });
    } catch (error) {
      debugLog("Error sending media:", error);
      debugLog("Error details:", error.message);

      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }

      try {
        await callPHPAPI(
          "/stats/update",
          "POST",
          {
            field: "failed",
            increment: 1,
          },
          req.token,
        );
      } catch (e) {
        debugLog("Failed to update stats:", e.message);
      }

      res.status(500).json({ success: false, error: error.message });
    }
  },
);

// Public endpoints - only accept API tokens
app.get("/api/chats", verifyApiToken, async (req, res) => {
  debugLog(`GET /api/chats called`);
  debugLog("Auth type:", req.authType);
  debugLog("User ID:", req.userId);

  try {
    const client = clients.get(req.userId);
    if (!client) {
      debugLog("WhatsApp not connected");
      return res.status(400).json({ error: "WhatsApp not connected" });
    }

    const chats = await client.getChats();
    const chatList = chats.map((chat) => ({
      id: chat.id._serialized,
      name: chat.name,
      isGroup: chat.isGroup,
      unreadCount: chat.unreadCount,
    }));

    debugLog(`Returning ${chatList.length} chats`);
    res.json(chatList);
  } catch (error) {
    debugLog("Error getting chats:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/contacts", verifyApiToken, async (req, res) => {
  debugLog(`GET /api/contacts called`);
  debugLog("Auth type:", req.authType);
  debugLog("User ID:", req.userId);

  try {
    const client = clients.get(req.userId);
    if (!client) {
      debugLog("WhatsApp not connected");
      return res.status(400).json({ error: "WhatsApp not connected" });
    }

    // Get chats instead of contacts (more reliable)
    const chats = await client.getChats();

    const contactList = chats
      .filter((chat) => !chat.isGroup) // Only individual chats
      .map((chat) => ({
        id: chat.id._serialized,
        name: chat.name,
        number: chat.id.user,
        pushname: chat.contact?.pushname || chat.name,
      }));

    debugLog(`Returning ${contactList.length} contacts`);
    res.json(contactList);
  } catch (error) {
    debugLog("Error getting contacts:", error.message);
    res.status(500).json({
      error: "Could not retrieve contacts",
      details: error.message,
    });
  }
});

// Proxy routes to PHP API
app.post("/api/auth/register", async (req, res) => {
  debugLog(`POST /api/auth/register called`);
  debugLog("Request body:", req.body);

  try {
    const result = await callPHPAPI("/auth/register", "POST", req.body);
    debugLog("Registration result:", result);
    res.json(result);
  } catch (error) {
    debugLog("Registration error:", error.message);
    res.status(400).json({ error: error.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  debugLog(`POST /api/auth/login called`);
  debugLog("Request body:", req.body);

  try {
    const result = await callPHPAPI("/auth/login", "POST", req.body);
    debugLog("Login result:", result);
    res.json(result);
  } catch (error) {
    debugLog("Login error:", error.message);
    res.status(401).json({ error: error.message });
  }
});

app.get("/api/auth/me", verifyAuth, async (req, res) => {
  debugLog(`GET /api/auth/me called by user ${req.userId}`);

  try {
    const result = await callPHPAPI("/auth/me", "GET", null, req.token);
    debugLog("User data result:", result);
    res.json(result);
  } catch (error) {
    debugLog("Error getting user data:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/messages", verifyAuth, async (req, res) => {
  debugLog(`GET /api/messages called by user ${req.userId}`);
  debugLog("Query parameters:", req.query);

  try {
    const result = await callPHPAPI(
      `/messages/list?type=${req.query.type || "all"}&search=${req.query.search || ""}&limit=${req.query.limit || 50}&offset=${req.query.offset || 0}`,
      "GET",
      null,
      req.token,
    );
    debugLog(`Returning ${result.length || 0} messages`);
    res.json(result);
  } catch (error) {
    debugLog("Error getting messages:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/messages/:id", verifyAuth, async (req, res) => {
  debugLog(
    `DELETE /api/messages/${req.params.id} called by user ${req.userId}`,
  );

  try {
    const result = await callPHPAPI(
      `/messages/${req.params.id}`,
      "DELETE",
      null,
      req.token,
    );
    debugLog("Delete result:", result);
    res.json(result);
  } catch (error) {
    debugLog("Error deleting message:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/messages", verifyAuth, async (req, res) => {
  debugLog(`DELETE /api/messages called by user ${req.userId}`);

  try {
    const result = await callPHPAPI(
      "/messages/clear",
      "DELETE",
      null,
      req.token,
    );
    debugLog("Clear messages result:", result);
    res.json(result);
  } catch (error) {
    debugLog("Error clearing messages:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/stats", verifyAuth, async (req, res) => {
  debugLog(`GET /api/stats called by user ${req.userId}`);

  try {
    const result = await callPHPAPI("/stats/get", "GET", null, req.token);
    debugLog("Stats result:", result);
    res.json(result);
  } catch (error) {
    debugLog("Error getting stats:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/tokens/generate", verifyAuth, async (req, res) => {
  debugLog(`POST /api/tokens/generate called by user ${req.userId}`);
  debugLog("Request body:", req.body);

  try {
    const result = await callPHPAPI(
      "/tokens/generate",
      "POST",
      req.body,
      req.token,
    );
    debugLog("Token generation result:", result);
    res.json(result);
  } catch (error) {
    debugLog("Error generating token:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/tokens", verifyAuth, async (req, res) => {
  debugLog(`GET /api/tokens called by user ${req.userId}`);

  try {
    const result = await callPHPAPI("/tokens/list", "GET", null, req.token);
    debugLog(`Returning ${result.length || 0} tokens`);
    res.json(result);
  } catch (error) {
    debugLog("Error getting tokens:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.delete("/api/tokens/:id", verifyAuth, async (req, res) => {
  debugLog(`DELETE /api/tokens/${req.params.id} called by user ${req.userId}`);

  try {
    const result = await callPHPAPI(
      `/tokens/${req.params.id}`,
      "DELETE",
      null,
      req.token,
    );
    debugLog("Delete token result:", result);
    res.json(result);
  } catch (error) {
    debugLog("Error deleting token:", error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/status", verifyAuth, async (req, res) => {
  debugLog(`GET /api/status called by user ${req.userId}`);

  try {
    const client = clients.get(req.userId);
    let isConnected = false;

    if (client) {
      // ⭐ FIX: Add proper state check with timeout
      try {
        const statePromise = client.getState();
        const timeoutPromise = new Promise((_, reject) =>
          setTimeout(() => reject(new Error("timeout")), 5000),
        );

        const state = await Promise.race([statePromise, timeoutPromise]);
        isConnected = state === "CONNECTED";
        debugLog(`Client state: ${state}, connected: ${isConnected}`);
      } catch (error) {
        debugLog(`Error checking client state: ${error.message}`);
        isConnected = false;
      }
    }

    const session = await callPHPAPI(
      "/whatsapp/session/get",
      "GET",
      null,
      req.token,
    );
    const stats = await callPHPAPI("/stats/get", "GET", null, req.token);

    // ⭐ CRITICAL FIX: Calculate ready correctly
    const ready = isConnected && session?.is_active === 1;

    debugLog("Status response:", {
      ready: ready,
      isConnected: isConnected,
      sessionActive: session?.is_active,
      session,
      stats,
    });

    res.json({
      ready: ready, // ⭐ Use the calculated ready value
      connected: isConnected,
      session: session || null,
      stats,
    });
  } catch (error) {
    debugLog("Error getting status:", error.message);
    res.status(500).json({ error: error.message });
  }
});
// ============================================
// OTP & PASSWORD RESET PROXY ROUTES
// ============================================

app.post("/api/auth/send-registration-otp", async (req, res) => {
  debugLog(`POST /api/auth/send-registration-otp called`);
  try {
    const result = await callPHPAPI(
      "/auth/send-registration-otp",
      "POST",
      req.body,
    );
    res.json(result);
  } catch (error) {
    debugLog("Send registration OTP error:", error.message);
    res.status(error.status || 500).json({ error: error.message });
  }
});

app.post("/api/auth/verify-registration-otp", async (req, res) => {
  debugLog(`POST /api/auth/verify-registration-otp called`);
  try {
    const result = await callPHPAPI(
      "/auth/verify-registration-otp",
      "POST",
      req.body,
    );
    res.json(result);
  } catch (error) {
    debugLog("Verify registration OTP error:", error.message);
    res.status(error.status || 400).json({ error: error.message });
  }
});

app.post("/api/auth/send-login-otp", async (req, res) => {
  debugLog(`POST /api/auth/send-login-otp called`);
  try {
    const result = await callPHPAPI("/auth/send-login-otp", "POST", req.body);
    res.json(result);
  } catch (error) {
    debugLog("Send login OTP error:", error.message);
    res.status(error.status || 401).json({ error: error.message });
  }
});

app.post("/api/auth/verify-login-otp", async (req, res) => {
  debugLog(`POST /api/auth/verify-login-otp called`);
  try {
    const result = await callPHPAPI("/auth/verify-login-otp", "POST", req.body);
    res.json(result);
  } catch (error) {
    debugLog("Verify login OTP error:", error.message);
    res.status(error.status || 400).json({ error: error.message });
  }
});

app.post("/api/auth/send-reset-otp", async (req, res) => {
  debugLog(`POST /api/auth/send-reset-otp called`);
  try {
    const result = await callPHPAPI("/auth/send-reset-otp", "POST", req.body);
    res.json(result);
  } catch (error) {
    debugLog("Send reset OTP error:", error.message);
    res.status(error.status || 500).json({ error: error.message });
  }
});

app.post("/api/auth/verify-reset-otp", async (req, res) => {
  debugLog(`POST /api/auth/verify-reset-otp called`);
  try {
    const result = await callPHPAPI("/auth/verify-reset-otp", "POST", req.body);
    res.json(result);
  } catch (error) {
    debugLog("Verify reset OTP error:", error.message);
    res.status(error.status || 400).json({ error: error.message });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  debugLog(`POST /api/auth/reset-password called`);
  try {
    const result = await callPHPAPI("/auth/reset-password", "POST", req.body);
    res.json(result);
  } catch (error) {
    debugLog("Reset password error:", error.message);
    res.status(error.status || 400).json({ error: error.message });
  }
});

// Cleanup on server shutdown
process.on("SIGTERM", gracefulShutdown);
process.on("SIGINT", gracefulShutdown);

async function gracefulShutdown(signal) {
  debugLog(`${signal} received, starting graceful shutdown...`);

  // Clear token cache
  tokenCache.clear();

  // Destroy all WhatsApp clients
  for (const [userId, client] of clients.entries()) {
    try {
      debugLog(`Destroying client for user ${userId}...`);
      await client.destroy();
    } catch (error) {
      debugLog(`Error destroying client for user ${userId}:`, error.message);
    }
  }

  debugLog("Graceful shutdown complete");
  process.exit(0);
}

app.listen(PORT, () => {
  debugLog(`WhatsApp Server running on port ${PORT}`);
  debugLog(`Environment: ${NODE_ENV}`);
  debugLog(`PHP API URL: ${PHP_API_URL}`);
  debugLog(`Frontend URL: ${FRONTEND_URL}`);
  debugLog(`Server ready to accept connections`);
});
